# SPDX-License-Identifier: Apache-2.0
"""Extract all roastable data from pcap/pcapng files.

Native pcap/pcapng parsing - no external dependencies.  Decodes Kerberos
ASN.1 using impacket and MS-SNTP packets by struct.

Extracts from network captures:
- **AS-REQ**: PA-ENC-TIMESTAMP pre-auth data → ``$krb5pa$`` hashes
- **AS-REP**: enc-part cipher (no-preauth accounts) → ``$krb5asrep$`` hashes
- **TGS-REP**: ticket enc-part cipher → ``$krb5tgs$`` hashes
- **AP-REQ**: ticket enc-part cipher, from SMB, HTTP, LDAP and DCE-RPC → ``$krb5tgs$`` hashes
- **SNTP MD5**: 68-byte Authenticator response → ``$sntp-ms$`` hashes
- **SNTP SHA512**: 120-byte ExtendedAuthenticator response → ``$sntp-ms-sha512$`` hashes
"""

from __future__ import annotations

import base64
import logging
import re
import signal
import socket
import struct
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO

from impacket.krb5 import constants as krb_constants
from impacket.krb5.asn1 import (
    AP_REQ,
    AS_REP,
    AS_REQ,
    ETYPE_INFO2,
    KRB_ERROR,
    METHOD_DATA,
    TGS_REP,
    EncryptedData,
    Ticket,
)
from pyasn1.codec.der import decoder

from kerbwolf.core.asreq import salt_from_padata
from kerbwolf.core.ipv6 import skip_ipv6_extensions
from kerbwolf.core.ntlmssp import _AP_REQ_PORTS, _HTTP_PORTS, _LDAP_PORT, _NTLM_PORTS, extract_ldap_simple_from_stream, extract_ntlm_from_stream
from kerbwolf.models import AttackType, CapturedHash, KerbWolfError

if TYPE_CHECKING:
    from types import FrameType

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
_PCAPNG_IDB_TYPE = 1  # Interface Description Block
_PCAPNG_SPB_TYPE = 3  # Simple Packet Block
_PCAPNG_EPB_TYPE = 6  # Enhanced Packet Block

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
_IP_VERSION_4 = 4
_IP_VERSION_6 = 6
_IPV4_MIN_HEADER = 20
_IPV6_HEADER = 40
_AS_REQ_TAG = 0x6A  # [APPLICATION 10]

# MS-SNTP packet lengths (format detection by length, not header fields).
_SNTP_AUTH_LEN = 68  # Authenticator (MS-SNTP 2.2.1/2.2.2)
_SNTP_EXT_AUTH_LEN = 120  # ExtendedAuthenticator (MS-SNTP 2.2.3/2.2.4)

# MS-SNTP 2.2.1: Key Identifier bit 31 selects current (0) or old (1) password.
_SNTP_KEY_SELECTOR_OLD = 1 << 31


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


SaltHints = dict[str, str]

# The cname of the last AS-REQ each client endpoint sent, keyed by
# ``(client_ip, client_port, kdc_ip, kdc_port)``.  A PREAUTH_REQUIRED error
# does not name the account it is about; the request it answers does.
KrbRequests = dict[tuple[str, int, str, int], str]


def parse_pcap(path: str) -> list[CapturedHash]:
    """Parse a pcap or pcapng file and extract all roastable hashes.

    Extracts Kerberos (port 88), MS-SNTP (port 123), and NTLM (ports
    445/139/80/389) hashes from the same capture.

    Pass ``"-"`` to read from stdin (e.g. ``tcpdump -w - | ...``).
    """
    if path == "-":
        return _parse_stdin()

    with Path(path).open("rb") as fh:
        return _parse_stream(fh)


def parse_pcap_with_salts(path: str) -> tuple[list[CapturedHash], SaltHints]:
    """Parse a pcap and return hashes + ETYPE-INFO2 salt hints.

    Salt hints come from two sources in the pcap:
    1. **KRB-ERROR(PREAUTH_REQUIRED)**: salt probes from KerbWolf
    2. **AS-REP padata**: ETYPE-INFO2 included in AS-REP responses

    The *salt_hints* dict maps ``lowercase(cname)`` to the raw
    ETYPE-INFO2 salt string.  Used to correct TGS-REP hash ``$user$``
    fields via case-insensitive sname matching.
    """
    all_results = parse_pcap(path)

    salt_hints: SaltHints = {}
    hashes: list[CapturedHash] = []

    for h in all_results:
        if h.attack == AttackType.SALT_HINT:
            salt_hints[h.username.lower()] = h.padata_salt
        else:
            hashes.append(h)
            if h.padata_salt and h.attack == AttackType.AS_REP:
                salt_hints[h.username.lower()] = h.padata_salt

    return hashes, salt_hints


# ---------------------------------------------------------------------------
# Native pcap/pcapng parser
# ---------------------------------------------------------------------------


def _parse_stdin() -> list[CapturedHash]:
    """Parse a capture piped in on stdin.

    In ``tcpdump -w - | kw-extract -`` a Ctrl-C reaches both processes.
    tcpdump flushes what it has buffered and exits, so the first interrupt
    is held back here and reading continues to the end of the pipe.  A
    second interrupt stops at once; the parsers keep what they had read.
    """
    interrupted = False

    def _on_sigint(_signum: int, _frame: FrameType | None) -> None:
        nonlocal interrupted
        if interrupted:
            raise KeyboardInterrupt
        interrupted = True
        _log.info("Interrupted: reading the rest of the capture (interrupt again to stop now)")

    previous = signal.signal(signal.SIGINT, _on_sigint)
    try:
        return _parse_stream(sys.stdin.buffer)
    finally:
        signal.signal(signal.SIGINT, previous)


def _parse_stream(fh: BinaryIO) -> list[CapturedHash]:
    """Detect format (pcap vs pcapng) and parse packets."""
    header = fh.read(4)
    if len(header) < 4:  # noqa: PLR2004
        return []

    magic = struct.unpack("<I", header)[0]
    ntlm_sessions: dict[tuple[str, int, str, int], bytes] = {}
    tcp_streams: TcpStreams = {}
    krb_requests: KrbRequests = {}

    if magic in {_PCAP_MAGIC_LE, _PCAP_MAGIC_NS_LE}:
        _log.debug("Format: pcap (little-endian)")
        results = _parse_pcap(fh, header, byte_order="<", ntlm_sessions=ntlm_sessions, tcp_streams=tcp_streams, krb_requests=krb_requests)
    elif magic in {_PCAP_MAGIC_BE, _PCAP_MAGIC_NS_BE}:
        _log.debug("Format: pcap (big-endian)")
        results = _parse_pcap(fh, header, byte_order=">", ntlm_sessions=ntlm_sessions, tcp_streams=tcp_streams, krb_requests=krb_requests)
    elif magic == _PCAPNG_SHB_TYPE:
        _log.debug("Format: pcapng")
        results = _parse_pcapng(fh, ntlm_sessions=ntlm_sessions, tcp_streams=tcp_streams, krb_requests=krb_requests)
    else:
        msg = f"Unknown file format (magic: 0x{magic:08X})"
        raise KerbWolfError(msg)

    return _drop_repeated_tickets(results)


def _drop_repeated_tickets(results: list[CapturedHash]) -> list[CapturedHash]:
    """Drop AP-REQ tickets that are already in *results*.

    A client presents the same service ticket on every connection to the
    service until it expires, and the TGS-REP that delivered it may be in the
    capture too.  The same ciphertext is the same hash, so each ticket is kept
    once: from its TGS-REP when the capture has one, otherwise from its first
    AP-REQ.
    """
    seen = {h.cipher_hex for h in results if h.attack == AttackType.TGS_REP}
    kept: list[CapturedHash] = []
    for h in results:
        if h.attack == AttackType.AP_REQ:
            if h.cipher_hex in seen:
                continue
            seen.add(h.cipher_hex)
        kept.append(h)
    return kept


def _collect_salt_hints_from_hashes(hashes: list[CapturedHash]) -> SaltHints:
    """Build a salt dictionary from AS-REQ cname → salt probe results.

    KerbWolf salt probes show up in the pcap as AS-REQ (msg-type 10)
    followed by KRB-ERROR (PREAUTH_REQUIRED).  We don't parse the
    KRB-ERROR directly, but we DO have the AS-REP padata salt for any
    AS-REP hashes.  For TGS-REP correlation, we build a case-insensitive
    map from AS-REP usernames (which went through ETYPE-INFO2 correction)
    to their corrected salt values.  Since KerbWolf sends sAMAccountNames
    as TGS-REQ snames, the TGS-REP sname matches the AS-REQ cname used
    for the salt probe.
    """
    hints: SaltHints = {}
    for h in hashes:
        if h.padata_salt and h.attack == AttackType.AS_REP:
            hints[h.username.lower()] = h.padata_salt
    return hints


def _parse_pcap(
    fh: BinaryIO,
    first4: bytes,
    *,
    byte_order: str,
    ntlm_sessions: dict[tuple[str, int, str, int], bytes],
    tcp_streams: TcpStreams,
    krb_requests: KrbRequests,
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
    try:
        while True:
            rec_hdr = fh.read(16)
            if len(rec_hdr) < 16:  # noqa: PLR2004
                break
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(f"{byte_order}IIII", rec_hdr)
            pkt_data = fh.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            pkt_count += 1
            results.extend(_process_packet(pkt_data, link_type, tcp_streams, ntlm_sessions, krb_requests))
    except KeyboardInterrupt:
        _log.info("Interrupted: keeping what was read so far")

    _log.info("Pcap: %d packets, %d hashes extracted", pkt_count, len(results))
    return results


def _parse_pcapng(
    fh: BinaryIO,
    *,
    ntlm_sessions: dict[tuple[str, int, str, int], bytes],
    tcp_streams: TcpStreams,
    krb_requests: KrbRequests,
) -> list[CapturedHash]:
    """Parse a pcapng format file."""
    shb_rest = fh.read(8)
    if len(shb_rest) < 8:  # noqa: PLR2004
        return []

    bo_magic = struct.unpack("<I", shb_rest[4:8])[0]
    byte_order = "<" if bo_magic == _PCAPNG_BYTE_ORDER_MAGIC else ">"

    block_len = struct.unpack(f"{byte_order}I", shb_rest[:4])[0]
    fh.read(block_len - 12)  # skip rest of SHB

    # One link type per Interface Description Block, in file order.  A packet
    # block names its interface by that index.
    link_types: list[int] = []
    results: list[CapturedHash] = []

    try:
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

            if block_type == _PCAPNG_IDB_TYPE and len(body) >= 8:  # noqa: PLR2004
                link_types.append(struct.unpack(f"{byte_order}HH", body[:4])[0])

            elif block_type == _PCAPNG_EPB_TYPE and len(body) >= 20:  # noqa: PLR2004
                iface_id, _ts_hi, _ts_lo, cap_len, _orig_len = struct.unpack(
                    f"{byte_order}IIIII",
                    body[:20],
                )
                link_type = link_types[iface_id] if iface_id < len(link_types) else _LINKTYPE_ETHERNET
                pkt_data = body[20 : 20 + cap_len]
                results.extend(_process_packet(pkt_data, link_type, tcp_streams, ntlm_sessions, krb_requests))

            elif block_type == _PCAPNG_SPB_TYPE and len(body) >= 4:  # noqa: PLR2004
                # A Simple Packet Block has no interface field: it belongs to interface 0.
                orig_len = struct.unpack(f"{byte_order}I", body[:4])[0]
                link_type = link_types[0] if link_types else _LINKTYPE_ETHERNET
                pkt_data = body[4 : 4 + orig_len]
                results.extend(_process_packet(pkt_data, link_type, tcp_streams, ntlm_sessions, krb_requests))
    except KeyboardInterrupt:
        _log.info("Interrupted: keeping what was read so far")

    return results


# ---------------------------------------------------------------------------
# Packet dispatch: TCP → stream reassembly, UDP → direct extraction
# ---------------------------------------------------------------------------


def _process_packet(
    pkt_data: bytes,
    link_type: int,
    tcp_streams: TcpStreams,
    ntlm_sessions: dict[tuple[str, int, str, int], bytes],
    krb_requests: KrbRequests | None = None,
) -> list[CapturedHash]:
    """Process a raw packet, routing TCP through stream reassembly.

    TCP payloads are put in sequence order per connection, so retransmitted
    and out-of-order segments do not corrupt a message.  Complete application
    messages are extracted from the stream after each segment.  UDP packets
    (SNTP) are passed directly to the existing extractor.
    """
    ip_data = _strip_link_layer(pkt_data, link_type)
    if ip_data is None:
        return []

    # Try TCP reassembly path.
    tcp_info = _parse_tcp_info(ip_data)
    if tcp_info is not None:
        payload, src_ip, src_port, dst_ip, dst_port, tcp_flags, seq = tcp_info
        conn_key = (src_ip, src_port, dst_ip, dst_port)

        # A SYN starts a new connection: forget the old stream.  The SYN
        # itself takes one sequence number, so data starts one past it.
        if tcp_flags & _TCP_FLAG_SYN:
            seq = (seq + 1) % _TCP_SEQ_MODULUS
            tcp_streams[conn_key] = TcpStream()
            tcp_streams[conn_key].next_seq = seq

        # Add the payload to the stream in sequence order.
        if payload:
            if conn_key not in tcp_streams:
                tcp_streams[conn_key] = TcpStream()
            _add_tcp_segment(tcp_streams[conn_key], seq, payload)

        results: list[CapturedHash] = []

        # Kerberos TCP (port 88): length-prefix extraction.
        if _KRB_PORT in {src_port, dst_port} and conn_key in tcp_streams:
            results.extend(_extract_kerberos_from_stream(tcp_streams[conn_key], conn_key, krb_requests))

        # Kerberos AP-REQ (SMB, HTTP, LDAP, DCE-RPC): service tickets.  This
        # only reads the stream, so it runs before NTLM consumes SMB messages.
        app_port = src_port if src_port in _AP_REQ_PORTS else dst_port
        if app_port in _AP_REQ_PORTS and conn_key in tcp_streams:
            results.extend(_extract_ap_req_from_stream(tcp_streams[conn_key], app_port))

        # NTLM (SMB, HTTP, LDAP, DCE-RPC, SMTP, POP3, IMAP, Telnet): stream extraction.
        ntlm_port = src_port if src_port in _NTLM_PORTS else dst_port
        if ntlm_port in _NTLM_PORTS and conn_key in tcp_streams:
            results.extend(extract_ntlm_from_stream(tcp_streams[conn_key], conn_key, ntlm_port, ntlm_sessions))

        # LDAP simple bind (port 389): plaintext credential extraction.
        # Runs after NTLM so the NTLM path sees the full buffer first.
        if _LDAP_PORT in {src_port, dst_port} and conn_key in tcp_streams:
            results.extend(extract_ldap_simple_from_stream(tcp_streams[conn_key]))

        # A stream is kept while the connection is open, because its position
        # is what orders the next segment.  Drop it once the sender is done.
        if tcp_flags & (_TCP_FLAG_FIN | _TCP_FLAG_RST) and conn_key in tcp_streams:
            stream = tcp_streams[conn_key]
            if not stream and not stream.pending:
                del tcp_streams[conn_key]

        return results

    # UDP path: direct extraction (SNTP, Kerberos UDP).
    return _extract_from_packet(pkt_data, link_type, krb_requests)


# ---------------------------------------------------------------------------
# UDP extraction: link layer → IP → UDP → Kerberos ASN.1 / SNTP
# ---------------------------------------------------------------------------


def _extract_from_packet(pkt_data: bytes, link_type: int, krb_requests: KrbRequests | None = None) -> list[CapturedHash]:
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

    addresses = _ip_addresses(ip_data)
    conn_key = (addresses[0], src_port, addresses[1], dst_port) if addresses is not None else None
    return _kerberos_hashes(krb_data, conn_key, krb_requests)


def _ip_addresses(ip_data: bytes) -> tuple[str, str] | None:
    """Return the source and destination address of an IPv4 or IPv6 packet."""
    version = (ip_data[0] >> 4) & 0xF if ip_data else 0
    if version == _IP_VERSION_4 and len(ip_data) >= _IPV4_MIN_HEADER:
        return socket.inet_ntoa(ip_data[12:16]), socket.inet_ntoa(ip_data[16:20])
    if version == _IP_VERSION_6 and len(ip_data) >= _IPV6_HEADER:
        return socket.inet_ntop(socket.AF_INET6, ip_data[8:24]), socket.inet_ntop(socket.AF_INET6, ip_data[24:40])
    return None


def _kerberos_hashes(
    krb_data: bytes,
    conn_key: tuple[str, int, str, int] | None = None,
    krb_requests: KrbRequests | None = None,
) -> list[CapturedHash]:
    """Run every Kerberos extractor over one message.

    The cname of an AS-REQ is remembered for the endpoint that sent it, so
    that a PREAUTH_REQUIRED error coming back the other way can be tied to the
    account it is about.
    """
    requested = ""
    if conn_key is not None and krb_requests is not None:
        cname = _as_req_cname(krb_data)
        if cname:
            krb_requests[conn_key] = cname
        src_ip, src_port, dst_ip, dst_port = conn_key
        requested = krb_requests.get((dst_ip, dst_port, src_ip, src_port), "")

    results: list[CapturedHash] = []
    results.extend(_try_parse_asreq(krb_data))
    results.extend(_try_parse_asrep(krb_data))
    results.extend(_try_parse_tgsrep(krb_data))
    results.extend(_try_parse_krberror_salt(krb_data, requested))
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
        proto, transport_data = skip_ipv6_extensions(ip_data[6], ip_data[40:])
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
class TcpStream(bytearray):
    """The in-order bytes of one direction of a TCP connection.

    The bytearray itself is what the protocol extractors read and consume.
    ``next_seq`` is the sequence number of the next byte it expects, and
    ``pending`` holds segments that arrived ahead of it, by sequence number.
    """

    def __init__(self) -> None:
        """Start an empty stream that takes its position from the first segment."""
        super().__init__()
        self.next_seq: int | None = None
        self.pending: dict[int, bytes] = {}
        self.kerberos_tokens: set[bytes] = set()


TcpStreams = dict[tuple[str, int, str, int], TcpStream]

# TCP flags (byte 13 of the TCP header).
_TCP_FLAG_FIN = 0x01
_TCP_FLAG_SYN = 0x02
_TCP_FLAG_RST = 0x04

_TCP_SEQ_MODULUS = 1 << 32
_TCP_SEQ_HALF = 1 << 31

# Segments held back while waiting for a gap to fill.  A gap that is still
# open after this many later segments is a packet the capture missed.
_TCP_MAX_PENDING_SEGMENTS = 256


def _seq_distance(seq: int, base: int) -> int:
    """Return how far *seq* is ahead of *base* (negative if behind), allowing for wraparound."""
    return ((seq - base + _TCP_SEQ_HALF) % _TCP_SEQ_MODULUS) - _TCP_SEQ_HALF


def _append_in_order(stream: TcpStream, seq: int, payload: bytes) -> bool:
    """Append *payload* if it continues the stream.  Return ``False`` if it is ahead of it.

    Bytes the stream already has (a retransmission, or the overlapping head
    of a segment) are dropped.
    """
    if stream.next_seq is None:
        stream.next_seq = seq

    ahead = _seq_distance(seq, stream.next_seq)
    if ahead > 0:
        return False

    fresh = payload[-ahead:]
    stream.extend(fresh)
    stream.next_seq = (stream.next_seq + len(fresh)) % _TCP_SEQ_MODULUS
    return True


def _add_tcp_segment(stream: TcpStream, seq: int, payload: bytes) -> None:
    """Add one TCP segment to *stream*, putting out-of-order segments back in order."""
    if not _append_in_order(stream, seq, payload):
        stream.pending.setdefault(seq, payload)
        if len(stream.pending) <= _TCP_MAX_PENDING_SEGMENTS or stream.next_seq is None:
            return
        # The gap is a packet the capture never saw.  What is buffered can no
        # longer be completed, so drop it and resume at the earliest held segment.
        base = stream.next_seq
        stream.clear()
        stream.next_seq = min(stream.pending, key=lambda held: _seq_distance(held, base))

    # Segments that were waiting may now fit.
    progressed = True
    while progressed and stream.pending:
        progressed = False
        for held_seq in list(stream.pending):
            if _append_in_order(stream, held_seq, stream.pending[held_seq]):
                del stream.pending[held_seq]
                progressed = True


def _parse_tcp_info(ip_data: bytes) -> tuple[bytes, str, int, str, int, int, int] | None:
    """Parse IP + TCP headers, returning payload and connection info with flags.

    Returns ``(payload, src_ip, src_port, dst_ip, dst_port, tcp_flags, seq)``
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
        proto, transport_data = skip_ipv6_extensions(ip_data[6], ip_data[40:])
    else:
        return None

    if proto != _IP_PROTO_TCP or len(transport_data) < 20:  # noqa: PLR2004
        return None

    src_port, dst_port, seq = struct.unpack("!HHI", transport_data[:8])
    tcp_flags = transport_data[13]
    data_offset = ((transport_data[12] >> 4) & 0xF) * 4
    payload = transport_data[data_offset:]
    return payload, src_ip, src_port, dst_ip, dst_port, tcp_flags, seq


# ---------------------------------------------------------------------------
# TCP stream extraction: Kerberos
# ---------------------------------------------------------------------------


def _extract_kerberos_from_stream(
    buffer: bytearray,
    conn_key: tuple[str, int, str, int] | None = None,
    krb_requests: KrbRequests | None = None,
) -> list[CapturedHash]:
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
        results.extend(_kerberos_hashes(krb_data, conn_key, krb_requests))
        del buffer[:total]
    return results


# ---------------------------------------------------------------------------
# Kerberos ASN.1 extraction - one function per message type
# ---------------------------------------------------------------------------


def _as_req_cname(data: bytes) -> str:
    """Return the cname of an AS-REQ, or ``""`` when *data* is not one."""
    if not data or data[0] != _AS_REQ_TAG:
        return ""
    try:
        as_req, _ = decoder.decode(data, asn1Spec=AS_REQ())
    except Exception:  # noqa: BLE001
        return ""
    if int(as_req["msg-type"]) != int(krb_constants.ApplicationTagNumbers.AS_REQ.value):
        return ""
    return _extract_cname(as_req["req-body"])


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
    # padata is OPTIONAL in a KDC-REQ (RFC 4120 section 5.4.1).
    padata = as_req["padata"]
    if padata.hasValue():
        for pa_data in padata:
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

    salt = _extract_etype_info2_salt(as_rep)

    enc_part = as_rep["enc-part"]
    return [
        CapturedHash(
            attack=AttackType.AS_REP,
            username=username,
            realm=realm,
            spn=f"krbtgt/{realm}",
            etype=int(enc_part["etype"]),
            cipher_hex=enc_part["cipher"].asOctets().hex(),
            padata_salt=salt,
        )
    ]


def _extract_etype_info2_salt(as_rep: Any) -> str:  # noqa: ANN401 - pyasn1 decoded object
    """Extract the salt from an AS-REP's padata (ETYPE-INFO2, or PA-PW-SALT for DES)."""
    try:
        return salt_from_padata(as_rep["padata"]) or ""
    except Exception:  # noqa: BLE001
        _log.debug("Failed to extract the salt from AS-REP padata", exc_info=True)
    return ""


def _try_parse_tgsrep(data: bytes) -> list[CapturedHash]:
    """Extract ticket enc-part from a TGS-REP (msg-type 13) → ``$krb5tgs$``.

    The ticket is encrypted with the **service account's** key, so the
    hash ``$user$`` field must be the service account's sAMAccountName
    (used as PBKDF2 salt for AES).  The TGS-REP packet does not carry
    the sAMAccountName — only the SPN in ``sname`` and the requesting
    client in ``cname``.  We use the SPN as the best available
    identifier; for AES etypes the user must correct it to the
    sAMAccountName before cracking.
    """
    try:
        tgs_rep, _ = decoder.decode(data, asn1Spec=TGS_REP())
    except Exception:  # noqa: BLE001
        return []

    if int(tgs_rep["msg-type"]) != int(krb_constants.ApplicationTagNumbers.TGS_REP.value):
        return []

    return [_ticket_hash(tgs_rep["ticket"], AttackType.TGS_REP)]


def _ticket_hash(ticket: Ticket, attack: AttackType) -> CapturedHash:
    """Return a ticket's enc-part cipher as a hash, named by the ticket's ``sname``.

    Shared by the TGS-REP and AP-REQ extractors, which carry the same ticket.
    The user field is the ``sname``, for the reason given in
    :func:`_try_parse_tgsrep`.
    """
    realm = str(ticket["realm"]).upper()

    spn_parts = [str(c) for c in ticket["sname"]["name-string"]] if ticket["sname"] else []
    spn = "/".join(spn_parts) if spn_parts else "unknown"

    ticket_enc = ticket["enc-part"]
    return CapturedHash(
        attack=attack,
        username=spn,
        realm=realm,
        spn=spn,
        etype=int(ticket_enc["etype"]),
        cipher_hex=ticket_enc["cipher"].asOctets().hex(),
    )


# An AP-REQ is found by its own first fields, pvno 5 and msg-type 14, which
# follow its application tag (0x6e) and SEQUENCE header.  A client that speaks
# GSS-API puts the mechanism OID and a TOK_ID in front of it ([RFC 4121]
# section 4.1); Impacket's LDAP bind puts it in the SPNEGO token bare.  Looking
# for the message itself finds both.
_AP_REQ_FIRST_FIELDS = bytes.fromhex("a003020105a10302010e")
_AP_REQ_TAG = 0x6E
_DER_SEQUENCE_TAG = 0x30
# A DER header is the tag and a length of one, two or three bytes.
_DER_HEADER_SIZES = (2, 3, 4)

# NTLM and Negotiate both appear in these headers; the Negotiate token is the
# one that may carry a Kerberos AP-REQ.
_HTTP_NEGOTIATE_RE = re.compile(
    rb"(?:Authorization|WWW-Authenticate|Proxy-Authenticate|Proxy-Authorization):\s*Negotiate\s+([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)


def _extract_ap_req_from_stream(buffer: TcpStream, app_port: int) -> list[CapturedHash]:
    """Extract Kerberos service tickets from AP-REQs in a TCP stream.

    A client wraps an AP-REQ in SPNEGO / GSS-API when it authenticates to a
    service over SMB, HTTP (WinRM/IIS), LDAP or DCE-RPC.  The ticket in it
    is encrypted with the service account's key, so it is Kerberoast material
    whether or not the TGS-REP that issued it was captured.

    The buffer is read, not consumed, because the NTLM path shares it.  Tickets
    already seen on this stream (``buffer.kerberos_tokens``) are skipped, so one
    that lingers in the buffer is reported once.
    """
    blobs: list[bytes] = []
    if app_port in _HTTP_PORTS:
        # HTTP carries the SPNEGO token as base64 in a Negotiate header.
        for match in _HTTP_NEGOTIATE_RE.finditer(bytes(buffer)):
            try:
                blobs.append(base64.b64decode(match.group(1)))
            except Exception:  # noqa: BLE001, S112
                continue
    else:
        # SMB, LDAP and DCE-RPC carry the token as binary in the stream.
        blobs.append(bytes(buffer))

    results: list[CapturedHash] = []
    for blob in blobs:
        for ticket_cipher, captured in _ap_reqs_in_blob(blob):
            if ticket_cipher in buffer.kerberos_tokens:
                continue
            buffer.kerberos_tokens.add(ticket_cipher)
            results.append(captured)
    return results


def _ap_reqs_in_blob(blob: bytes) -> list[tuple[bytes, CapturedHash]]:
    """Find AP-REQs in *blob*, returning ``(cipher, hash)`` pairs.

    Anchors on the pvno and msg-type fields every AP-REQ opens with, steps back
    over the two DER headers in front of them, DER-decodes the AP-REQ from
    there, and takes the service ticket from it.  A false anchor in binary data
    fails the header check, the decode or the message-type check and is
    dropped.
    """
    results: list[tuple[bytes, CapturedHash]] = []
    idx = 0
    while True:
        pos = blob.find(_AP_REQ_FIRST_FIELDS, idx)
        if pos < 0:
            break
        idx = pos + len(_AP_REQ_FIRST_FIELDS)
        found = _decode_ap_req_before(blob, pos)
        if found is not None:
            results.append(found)
    return results


def _decode_ap_req_before(blob: bytes, fields_pos: int) -> tuple[bytes, CapturedHash] | None:
    """Decode the AP-REQ whose first fields start at *fields_pos*, if there is one."""
    for sequence_header in _DER_HEADER_SIZES:
        for application_header in _DER_HEADER_SIZES:
            start = fields_pos - sequence_header - application_header
            if start < 0 or blob[start] != _AP_REQ_TAG or blob[start + application_header] != _DER_SEQUENCE_TAG:
                continue
            try:
                ap_req, _ = decoder.decode(blob[start:], asn1Spec=AP_REQ())
                if int(ap_req["msg-type"]) != int(krb_constants.ApplicationTagNumbers.AP_REQ.value):
                    continue
                ticket = ap_req["ticket"]
                cipher = ticket["enc-part"]["cipher"].asOctets()
            except Exception:  # noqa: BLE001, S112
                continue
            return bytes(cipher), _ticket_hash(ticket, AttackType.AP_REQ)
    return None


# ---------------------------------------------------------------------------
# MS-SNTP response extraction (port 123)
# ---------------------------------------------------------------------------


def _try_parse_krberror_salt(data: bytes, cname: str = "") -> list[CapturedHash]:
    """Extract ETYPE-INFO2 salt from a KRB-ERROR (PREAUTH_REQUIRED).

    Returns ``SALT_HINT`` pseudo-hashes that carry the ETYPE-INFO2 salt from
    the error.  They are filtered out by ``extract_from_pcap`` and used to
    build a salt dictionary for correcting hash usernames.

    The error does not name the account.  *cname* is the name from the AS-REQ
    it answers, and the hint is filed under it: that is the name later
    messages for the account carry, which the salt need not contain (a machine
    account is salted with ``host<fqdn>``, and a renamed account keeps its old
    salt).  The hint is also filed under the name read out of the salt, which
    is all there is when the request was not captured.
    """
    try:
        krb_error = decoder.decode(data, asn1Spec=KRB_ERROR())[0]
    except Exception:  # noqa: BLE001
        return []

    if int(krb_error["error-code"]) != krb_constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value:
        return []

    realm = str(krb_error["realm"]).upper() if krb_error["realm"] is not None else ""

    e_data = krb_error["e-data"]
    if e_data is None or not e_data.hasValue():
        return []

    salt = ""
    try:
        method_data = decoder.decode(e_data.asOctets(), asn1Spec=METHOD_DATA())[0]
        for pa_data in method_data:
            if int(pa_data["padata-type"]) == krb_constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value:
                etype_info2 = decoder.decode(pa_data["padata-value"], asn1Spec=ETYPE_INFO2())[0]
                for entry in etype_info2:
                    salt_val = entry["salt"]
                    if salt_val is not None and salt_val.hasValue():
                        salt = str(salt_val)
                        break
                if salt:
                    break
    except Exception:  # noqa: BLE001
        return []

    if not salt:
        return []

    salt_name = ""
    nul_idx = salt.find("\x00")
    clean_salt = salt[nul_idx + 1 :] if nul_idx >= 0 else salt
    if realm and clean_salt.startswith(realm):
        salt_name = clean_salt[len(realm) :]

    names = [name for name in dict.fromkeys((cname, salt_name)) if name]
    return [CapturedHash(attack=AttackType.SALT_HINT, username=name, realm=realm, spn="", etype=0, cipher_hex="", padata_salt=salt) for name in names]


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
