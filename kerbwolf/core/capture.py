"""Extract all roastable data from pcap/pcapng files.

Native pcap/pcapng parsing - no external dependencies.  Decodes Kerberos
ASN.1 using impacket and MS-SNTP packets by struct.

Extracts from network captures:
- **AS-REQ**: PA-ENC-TIMESTAMP pre-auth data → ``$krb5pa$`` hashes
- **AS-REP**: enc-part cipher (no-preauth accounts) → ``$krb5asrep$`` hashes
- **TGS-REP**: ticket enc-part cipher → ``$krb5tgs$`` hashes
- **SNTP MD5**: 68-byte Authenticator response → ``$sntp-ms$`` hashes
- **SNTP SHA512**: 120-byte ExtendedAuthenticator response → ``$sntp-ms-sha512$`` hashes
"""

from __future__ import annotations

import enum
import logging
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from impacket.krb5 import constants as krb_constants
from impacket.krb5.asn1 import (
    AS_REP,
    AS_REQ,
    TGS_REP,
    EncryptedData,
)
from pyasn1.codec.der import decoder

from kerbwolf.models import KerbWolfError

_log = logging.getLogger(__name__)

# Kerberos port.
_KRB_PORT = 88

# NTP port (MS-SNTP timeroasting).
_NTP_PORT = 123

# Pcap magic numbers.
_PCAP_MAGIC_LE = 0xA1B2C3D4
_PCAP_MAGIC_BE = 0xD4C3B2A1
_PCAP_MAGIC_NS_LE = 0xA1B23C4D
_PCAP_MAGIC_NS_BE = 0x4D3CB2A1

# Pcapng Section Header Block.
_PCAPNG_SHB_TYPE = 0x0A0D0D0A
_PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

# Link layer types.
_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = 101
_LINKTYPE_LINUX_SLL = 113
_LINKTYPE_LINUX_SLL2 = 276

# Ethernet / IP / TCP / UDP constants.
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_IP_PROTO_TCP = 6
_IP_PROTO_UDP = 17

# IPv6 extension header types that must be skipped to reach TCP/UDP.
# Each has a Next Header field at byte 0 and a Header Extension Length at byte 1.
_IPV6_EXTENSION_HEADERS = frozenset(
    {
        0,  # Hop-by-Hop Options
        43,  # Routing
        44,  # Fragment
        50,  # ESP (Encapsulating Security Payload)
        51,  # AH (Authentication Header)
        60,  # Destination Options
        135,  # Mobility
        139,  # HIP (Host Identity Protocol)
        140,  # Shim6
    }
)

# MS-SNTP packet lengths (format detection by length, not header fields).
_SNTP_AUTH_LEN = 68  # Authenticator (MS-SNTP 2.2.1/2.2.2)
_SNTP_EXT_AUTH_LEN = 120  # ExtendedAuthenticator (MS-SNTP 2.2.3/2.2.4)

# MS-SNTP 2.2.1: Key Identifier bit 31 selects current (0) or old (1) password.
_SNTP_KEY_SELECTOR_OLD = 1 << 31


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class AttackType(enum.StrEnum):
    """Which message the hash was extracted from."""

    AS_REQ = "AS-REQ"
    AS_REP = "AS-REP"
    TGS_REP = "TGS-REP"
    SNTP_MD5 = "SNTP-MD5"
    SNTP_SHA512 = "SNTP-SHA512"
    NTLMV1 = "NTLMv1"
    NTLMV2 = "NTLMv2"
    LDAP_SIMPLE = "LDAP-Simple"


@dataclass(frozen=True)
class CapturedHash:
    """One roastable hash extracted from a pcap packet.

    For Kerberos hashes, ``cipher_hex`` holds the raw cipher bytes (hex).
    For SNTP hashes, ``cipher_hex`` holds the checksum (hex), ``salt_hex``
    holds the 48-byte NTP header (hex), and ``rid`` holds the account RID.
    """

    attack: AttackType
    username: str
    realm: str
    spn: str
    etype: int
    cipher_hex: str
    # SNTP-specific fields (populated only for SNTP_MD5/SNTP_SHA512).
    salt_hex: str = ""
    rid: int = 0
    # NTLM-specific fields (populated only for NTLMV1/NTLMV2).
    challenge_hex: str = ""
    lm_hex: str = ""
    ntlm_blob_hex: str = ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_pcap(path: str) -> list[CapturedHash]:
    """Parse a pcap or pcapng file and extract all roastable hashes.

    Extracts Kerberos (port 88), MS-SNTP (port 123), and NTLM (ports
    445/139/80/389) hashes from the same capture.

    Pass ``"-"`` to read from stdin (e.g. ``tcpdump -w - | ...``).
    """
    if path == "-":
        return _parse_stream(sys.stdin.buffer)

    with Path(path).open("rb") as fh:
        return _parse_stream(fh)


# ---------------------------------------------------------------------------
# Native pcap/pcapng parser
# ---------------------------------------------------------------------------


def _parse_stream(fh: BinaryIO) -> list[CapturedHash]:
    """Detect format (pcap vs pcapng) and parse packets."""
    header = fh.read(4)
    if len(header) < 4:  # noqa: PLR2004
        return []

    magic = struct.unpack("<I", header)[0]
    ntlm_sessions: dict[tuple[str, int, str, int], bytes] = {}
    tcp_streams: TcpStreams = {}

    if magic in {_PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE}:
        _log.debug("Format: pcap (little-endian)")
        return _parse_pcap(fh, header, byte_order="<", ntlm_sessions=ntlm_sessions, tcp_streams=tcp_streams)
    if magic in {_PCAP_MAGIC_BE, _PCAP_MAGIC_NS_BE}:
        _log.debug("Format: pcap (big-endian)")
        return _parse_pcap(fh, header, byte_order=">", ntlm_sessions=ntlm_sessions, tcp_streams=tcp_streams)
    if magic == _PCAPNG_SHB_TYPE:
        _log.debug("Format: pcapng")
        return _parse_pcapng(fh, ntlm_sessions=ntlm_sessions, tcp_streams=tcp_streams)

    msg = f"Unknown file format (magic: 0x{magic:08X})"
    raise KerbWolfError(msg)


def _parse_pcap(
    fh: BinaryIO,
    first4: bytes,
    *,
    byte_order: str,
    ntlm_sessions: dict[tuple[str, int, str, int], bytes],
    tcp_streams: TcpStreams,
) -> list[CapturedHash]:
    """Parse a libpcap format file."""
    rest = fh.read(20)
    if len(rest) < 20:  # noqa: PLR2004
        return []

    full_header = first4 + rest
    _ver_maj, _ver_min, _tz, _sigfigs, _snaplen, link_type = struct.unpack(
        f"{byte_order}xxxx HH i I I I",
        full_header,
    )

    results: list[CapturedHash] = []
    pkt_count = 0
    while True:
        rec_hdr = fh.read(16)
        if len(rec_hdr) < 16:  # noqa: PLR2004
            break
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(f"{byte_order}IIII", rec_hdr)
        pkt_data = fh.read(incl_len)
        if len(pkt_data) < incl_len:
            break
        pkt_count += 1
        results.extend(_process_packet(pkt_data, link_type, tcp_streams, ntlm_sessions))

    _log.info("Pcap: %d packets, %d hashes extracted", pkt_count, len(results))
    return results


def _parse_pcapng(
    fh: BinaryIO,
    *,
    ntlm_sessions: dict[tuple[str, int, str, int], bytes],
    tcp_streams: TcpStreams,
) -> list[CapturedHash]:
    """Parse a pcapng format file."""
    shb_rest = fh.read(8)
    if len(shb_rest) < 8:  # noqa: PLR2004
        return []

    bo_magic = struct.unpack("<I", shb_rest[4:8])[0]
    byte_order = "<" if bo_magic == _PCAPNG_BYTE_ORDER_MAGIC else ">"

    block_len = struct.unpack(f"{byte_order}I", shb_rest[:4])[0]
    fh.read(block_len - 12)  # skip rest of SHB

    link_type = _LINKTYPE_ETHERNET
    results: list[CapturedHash] = []

    while True:
        block_header = fh.read(8)
        if len(block_header) < 8:  # noqa: PLR2004
            break

        block_type, block_total_len = struct.unpack(f"{byte_order}II", block_header)
        body_len = block_total_len - 12
        if body_len < 0:
            break
        body = fh.read(body_len)
        fh.read(4)  # trailing block_total_length

        if block_type == 1 and len(body) >= 8:  # noqa: PLR2004 - IDB
            link_type = struct.unpack(f"{byte_order}HH", body[:4])[0]

        elif block_type == 6 and len(body) >= 20:  # noqa: PLR2004 - EPB
            _iface_id, _ts_hi, _ts_lo, cap_len, _orig_len = struct.unpack(
                f"{byte_order}IIIII",
                body[:20],
            )
            pkt_data = body[20 : 20 + cap_len]
            results.extend(_process_packet(pkt_data, link_type, tcp_streams, ntlm_sessions))

    return results


# ---------------------------------------------------------------------------
# Packet dispatch: TCP → stream reassembly, UDP → direct extraction
# ---------------------------------------------------------------------------


def _process_packet(
    pkt_data: bytes,
    link_type: int,
    tcp_streams: TcpStreams,
    ntlm_sessions: dict[tuple[str, int, str, int], bytes],
) -> list[CapturedHash]:
    """Process a raw packet, routing TCP through stream reassembly.

    TCP packets are buffered per connection.  Complete application messages
    are extracted from the buffer after each segment.  UDP packets (SNTP)
    are passed directly to the existing extractor.
    """
    from kerbwolf.core.ntlmssp import _LDAP_PORT, _NTLM_PORTS, extract_ldap_simple_from_stream, extract_ntlm_from_stream  # noqa: PLC0415

    ip_data = _strip_link_layer(pkt_data, link_type)
    if ip_data is None:
        return []

    # Try TCP reassembly path.
    tcp_info = _parse_tcp_info(ip_data)
    if tcp_info is not None:
        payload, src_ip, src_port, dst_ip, dst_port, tcp_flags = tcp_info
        conn_key = (src_ip, src_port, dst_ip, dst_port)

        # Reset buffer on SYN (new connection).
        if tcp_flags & _TCP_FLAG_SYN:
            tcp_streams.pop(conn_key, None)

        # Append payload to stream buffer.
        if payload:
            if conn_key not in tcp_streams:
                tcp_streams[conn_key] = bytearray()
            tcp_streams[conn_key].extend(payload)

        results: list[CapturedHash] = []

        # Kerberos TCP (port 88): length-prefix extraction.
        if _KRB_PORT in {src_port, dst_port} and conn_key in tcp_streams:
            results.extend(_extract_kerberos_from_stream(tcp_streams[conn_key]))

        # NTLM (SMB, HTTP, LDAP, DCE-RPC, SMTP, POP3, IMAP, Telnet): stream extraction.
        ntlm_port = src_port if src_port in _NTLM_PORTS else dst_port
        if ntlm_port in _NTLM_PORTS and conn_key in tcp_streams:
            results.extend(extract_ntlm_from_stream(tcp_streams[conn_key], conn_key, ntlm_port, ntlm_sessions))

        # LDAP simple bind (port 389): plaintext credential extraction.
        # Runs after NTLM so the NTLM path sees the full buffer first.
        if _LDAP_PORT in {src_port, dst_port} and conn_key in tcp_streams:
            results.extend(extract_ldap_simple_from_stream(tcp_streams[conn_key]))

        # Clean up empty buffers.
        if conn_key in tcp_streams and not tcp_streams[conn_key]:
            del tcp_streams[conn_key]

        return results

    # UDP path: direct extraction (SNTP, Kerberos UDP).
    return _extract_from_packet(pkt_data, link_type)


# ---------------------------------------------------------------------------
# UDP extraction: link layer → IP → UDP → Kerberos ASN.1 / SNTP
# ---------------------------------------------------------------------------


def _extract_from_packet(pkt_data: bytes, link_type: int) -> list[CapturedHash]:
    """Extract all roastable data from a raw packet."""
    ip_data = _strip_link_layer(pkt_data, link_type)
    if ip_data is None:
        return []

    payload, src_port, dst_port, proto = _strip_ip_transport(ip_data)
    if payload is None:
        return []

    # MS-SNTP (UDP port 123) - timeroast hashes.
    if _NTP_PORT in {dst_port, src_port} and proto == _IP_PROTO_UDP:
        return _try_parse_sntp(payload)

    # Kerberos (port 88) - AS-REQ, AS-REP, TGS-REP hashes.
    if _KRB_PORT not in {dst_port, src_port}:
        return []

    # TCP Kerberos: 4-byte length prefix.
    krb_data = payload
    if proto == _IP_PROTO_TCP and len(payload) > 4:  # noqa: PLR2004
        msg_len = struct.unpack("!I", payload[:4])[0]
        if msg_len <= len(payload) - 4:
            krb_data = payload[4 : 4 + msg_len]

    results: list[CapturedHash] = []
    results.extend(_try_parse_asreq(krb_data))
    results.extend(_try_parse_asrep(krb_data))
    results.extend(_try_parse_tgsrep(krb_data))
    return results


def _strip_link_layer(pkt_data: bytes, link_type: int) -> bytes | None:
    """Remove link-layer header and return IP data."""
    if link_type == _LINKTYPE_ETHERNET and len(pkt_data) > 14:  # noqa: PLR2004
        ethertype = struct.unpack("!H", pkt_data[12:14])[0]
        if ethertype in {_ETHERTYPE_IPV4, _ETHERTYPE_IPV6}:
            return pkt_data[14:]
        if ethertype == 0x8100 and len(pkt_data) > 18:  # noqa: PLR2004 - 802.1Q VLAN
            inner = struct.unpack("!H", pkt_data[16:18])[0]
            if inner in {_ETHERTYPE_IPV4, _ETHERTYPE_IPV6}:
                return pkt_data[18:]
        return None
    if link_type == _LINKTYPE_RAW:
        return pkt_data
    if link_type == _LINKTYPE_LINUX_SLL and len(pkt_data) > 16:  # noqa: PLR2004
        return pkt_data[16:]
    if link_type == _LINKTYPE_LINUX_SLL2 and len(pkt_data) > 20:  # noqa: PLR2004
        return pkt_data[20:]
    return None


def _skip_ipv6_extensions(next_header: int, data: bytes) -> tuple[int, bytes]:
    """Walk IPv6 extension header chain to reach the transport layer.

    Returns ``(proto, transport_data)`` where *proto* is the final Next Header
    value (e.g. TCP=6 or UDP=17) and *transport_data* starts at the transport
    header.  Handles Hop-by-Hop, Routing, Fragment, Destination Options, AH,
    and other standard extension headers per RFC 8200 section 4.
    """
    offset = 0
    proto = next_header
    while proto in _IPV6_EXTENSION_HEADERS and offset < len(data):
        if proto == 44:  # noqa: PLR2004 - Fragment header is fixed 8 bytes
            if offset + 8 > len(data):
                break
            proto = data[offset]
            offset += 8
        else:
            # All other extension headers: Next Header at byte 0,
            # Header Extension Length at byte 1 (in 8-octet units, not counting first 8).
            if offset + 2 > len(data):
                break
            proto = data[offset]
            ext_len = (data[offset + 1] + 1) * 8
            offset += ext_len
    return proto, data[offset:]


def _strip_ip_transport(ip_data: bytes) -> tuple[bytes | None, int, int, int]:
    """Parse IP + TCP/UDP headers.  Returns ``(payload, src_port, dst_port, proto)``."""
    if len(ip_data) < 20:  # noqa: PLR2004
        return None, 0, 0, 0

    version = (ip_data[0] >> 4) & 0xF

    if version == 4:  # noqa: PLR2004
        ihl = (ip_data[0] & 0xF) * 4
        proto = ip_data[9]
        transport_data = ip_data[ihl:]
    elif version == 6:  # noqa: PLR2004
        if len(ip_data) < 40:  # noqa: PLR2004
            return None, 0, 0, 0
        proto, transport_data = _skip_ipv6_extensions(ip_data[6], ip_data[40:])
    else:
        return None, 0, 0, 0

    if proto == _IP_PROTO_TCP and len(transport_data) >= 20:  # noqa: PLR2004
        src_port, dst_port = struct.unpack("!HH", transport_data[:4])
        data_offset = ((transport_data[12] >> 4) & 0xF) * 4
        return transport_data[data_offset:], src_port, dst_port, proto

    if proto == _IP_PROTO_UDP and len(transport_data) >= 8:  # noqa: PLR2004
        src_port, dst_port = struct.unpack("!HH", transport_data[:4])
        return transport_data[8:], src_port, dst_port, proto

    return None, 0, 0, 0


# TCP stream type for reassembly.
TcpStreams = dict[tuple[str, int, str, int], bytearray]

# TCP SYN flag (byte 13 of TCP header).
_TCP_FLAG_SYN = 0x02


def _parse_tcp_info(ip_data: bytes) -> tuple[bytes, str, int, str, int, int] | None:
    """Parse IP + TCP headers, returning payload and connection info with flags.

    Returns ``(payload, src_ip, src_port, dst_ip, dst_port, tcp_flags)``
    or ``None`` for non-TCP or unparseable packets.
    """
    if len(ip_data) < 20:  # noqa: PLR2004
        return None

    version = (ip_data[0] >> 4) & 0xF

    if version == 4:  # noqa: PLR2004
        ihl = (ip_data[0] & 0xF) * 4
        proto = ip_data[9]
        src_ip = socket.inet_ntoa(ip_data[12:16])
        dst_ip = socket.inet_ntoa(ip_data[16:20])
        transport_data = ip_data[ihl:]
    elif version == 6:  # noqa: PLR2004
        if len(ip_data) < 40:  # noqa: PLR2004
            return None
        src_ip = socket.inet_ntop(socket.AF_INET6, ip_data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
        proto, transport_data = _skip_ipv6_extensions(ip_data[6], ip_data[40:])
    else:
        return None

    if proto != _IP_PROTO_TCP or len(transport_data) < 20:  # noqa: PLR2004
        return None

    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
    tcp_flags = transport_data[13]
    data_offset = ((transport_data[12] >> 4) & 0xF) * 4
    payload = transport_data[data_offset:]
    return payload, src_ip, src_port, dst_ip, dst_port, tcp_flags


# ---------------------------------------------------------------------------
# TCP stream extraction: Kerberos
# ---------------------------------------------------------------------------


def _extract_kerberos_from_stream(buffer: bytearray) -> list[CapturedHash]:
    """Extract complete Kerberos messages from a TCP stream buffer.

    Kerberos over TCP uses a 4-byte big-endian length prefix per RFC 4120
    section 7.2.2.  This function consumes complete messages from the buffer,
    leaving incomplete data for the next segment.
    """
    results: list[CapturedHash] = []
    while len(buffer) > 4:  # noqa: PLR2004
        msg_len = struct.unpack("!I", buffer[:4])[0]
        total = 4 + msg_len
        if total > len(buffer):
            break  # Incomplete message, wait for more data.
        krb_data = bytes(buffer[4:total])
        results.extend(_try_parse_asreq(krb_data))
        results.extend(_try_parse_asrep(krb_data))
        results.extend(_try_parse_tgsrep(krb_data))
        del buffer[:total]
    return results


# ---------------------------------------------------------------------------
# Kerberos ASN.1 extraction - one function per message type
# ---------------------------------------------------------------------------


def _try_parse_asreq(data: bytes) -> list[CapturedHash]:
    """Extract PA-ENC-TIMESTAMP from an AS-REQ (msg-type 10) → ``$krb5pa$``."""
    try:
        as_req, _ = decoder.decode(data, asn1Spec=AS_REQ())
    except Exception:  # noqa: BLE001
        return []

    if int(as_req["msg-type"]) != int(krb_constants.ApplicationTagNumbers.AS_REQ.value):
        return []

    req_body = as_req["req-body"]
    realm = str(req_body["realm"]).upper()
    username = _extract_cname(req_body)
    if not username or not realm:
        return []

    results: list[CapturedHash] = []
    if as_req["padata"]:
        for pa_data in as_req["padata"]:
            if int(pa_data["padata-type"]) == int(krb_constants.PreAuthenticationDataTypes.PA_ENC_TIMESTAMP.value):
                enc_data, _ = decoder.decode(pa_data["padata-value"], asn1Spec=EncryptedData())
                results.append(
                    CapturedHash(
                        attack=AttackType.AS_REQ,
                        username=username,
                        realm=realm,
                        spn=f"krbtgt/{realm}",
                        etype=int(enc_data["etype"]),
                        cipher_hex=enc_data["cipher"].asOctets().hex(),
                    )
                )

    return results


def _try_parse_asrep(data: bytes) -> list[CapturedHash]:
    """Extract enc-part from an AS-REP (msg-type 11) → ``$krb5asrep$``."""
    try:
        as_rep, _ = decoder.decode(data, asn1Spec=AS_REP())
    except Exception:  # noqa: BLE001
        return []

    if int(as_rep["msg-type"]) != int(krb_constants.ApplicationTagNumbers.AS_REP.value):
        return []

    realm = str(as_rep["crealm"]).upper()
    username = ""
    if as_rep["cname"]:
        name_string = as_rep["cname"]["name-string"]
        if len(name_string) > 0:
            username = str(name_string[0])

    if not username or not realm:
        return []

    enc_part = as_rep["enc-part"]
    return [
        CapturedHash(
            attack=AttackType.AS_REP,
            username=username,
            realm=realm,
            spn=f"krbtgt/{realm}",
            etype=int(enc_part["etype"]),
            cipher_hex=enc_part["cipher"].asOctets().hex(),
        )
    ]


def _try_parse_tgsrep(data: bytes) -> list[CapturedHash]:
    """Extract ticket enc-part from a TGS-REP (msg-type 13) → ``$krb5tgs$``."""
    try:
        tgs_rep, _ = decoder.decode(data, asn1Spec=TGS_REP())
    except Exception:  # noqa: BLE001
        return []

    if int(tgs_rep["msg-type"]) != int(krb_constants.ApplicationTagNumbers.TGS_REP.value):
        return []

    realm = str(tgs_rep["crealm"]).upper()
    username = ""
    if tgs_rep["cname"]:
        name_string = tgs_rep["cname"]["name-string"]
        if len(name_string) > 0:
            username = str(name_string[0])

    # Extract SPN from the ticket's sname.
    ticket = tgs_rep["ticket"]
    spn_parts = [str(c) for c in ticket["sname"]["name-string"]] if ticket["sname"] else []
    spn = "/".join(spn_parts) if spn_parts else "unknown"

    ticket_enc = ticket["enc-part"]
    return [
        CapturedHash(
            attack=AttackType.TGS_REP,
            username=username,
            realm=realm,
            spn=spn,
            etype=int(ticket_enc["etype"]),
            cipher_hex=ticket_enc["cipher"].asOctets().hex(),
        )
    ]


# ---------------------------------------------------------------------------
# MS-SNTP response extraction (port 123)
# ---------------------------------------------------------------------------


def _try_parse_sntp(payload: bytes) -> list[CapturedHash]:
    """Try to parse a UDP payload as an MS-SNTP authentication response.

    Responses are identified by packet length (68 or 120 bytes) and a
    non-zero Crypto-Checksum field (requests have all-zero checksums).

    68-byte Authenticator (MS-SNTP 2.2.2):
        Bytes 0-47:  NTP header (salt).
        Bytes 48-51: Key Identifier (LE uint32, bit 31 = old-password flag).
        Bytes 52-67: MD5 Crypto-Checksum (16 bytes).

    120-byte ExtendedAuthenticator (MS-SNTP 2.2.4):
        Bytes 0-47:  NTP header (salt).
        Bytes 48-51: Key Identifier (LE uint32, full RID).
        Bytes 52-55: Reserved/Flags/Hints/SigHashID.
        Bytes 56-119: HMAC-SHA512 Crypto-Checksum (64 bytes).
    """
    if len(payload) == _SNTP_AUTH_LEN:
        checksum = payload[52:68]
        if checksum == b"\x00" * 16:
            return []  # Request packet (checksum is zero).
        key_id = struct.unpack("<I", payload[48:52])[0]
        rid = key_id & ~_SNTP_KEY_SELECTOR_OLD  # Mask out bit 31.
        salt = payload[:48]
        return [
            CapturedHash(
                attack=AttackType.SNTP_MD5,
                username=str(rid),
                realm="",
                spn="",
                etype=0,
                cipher_hex=checksum.hex(),
                salt_hex=salt.hex(),
                rid=rid,
            )
        ]

    if len(payload) == _SNTP_EXT_AUTH_LEN:
        checksum = payload[56:120]
        if checksum == b"\x00" * 64:
            return []  # Request packet.
        rid = struct.unpack("<I", payload[48:52])[0]
        salt = payload[:48]
        return [
            CapturedHash(
                attack=AttackType.SNTP_SHA512,
                username=str(rid),
                realm="",
                spn="",
                etype=0,
                cipher_hex=checksum.hex(),
                salt_hex=salt.hex(),
                rid=rid,
            )
        ]

    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_cname(req_body: Any) -> str:  # noqa: ANN401
    """Extract the client username from a KDC-REQ-BODY cname field."""
    if req_body["cname"]:
        name_string = req_body["cname"]["name-string"]
        if len(name_string) > 0:
            return str(name_string[0])
    return ""
