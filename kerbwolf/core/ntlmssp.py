"""NTLM hash extraction from pcap packets.

Extracts Net-NTLMv1, Net-NTLMv1-ESS, Net-NTLMv2, and Net-LMv2 hashes from
all common NTLM transports:

- SMB (ports 445/139) - [MS-SMB], [MS-SMB2]
- HTTP/WinRM (ports 80/5985/5986) - [MS-NTHT]
- LDAP (port 389) - SASL/SPNEGO
- SMTP (ports 25/587) - [MS-SMTPNTLM]
- POP3 (port 110) - [MS-POP3]
- IMAP (port 143) - [MS-OXIMAP]
- Telnet (port 23) - [MS-TNAP]

NTLM authentication spans two packets in the same TCP connection:
- **Type 2** (CHALLENGE_MESSAGE): server sends 8-byte ServerChallenge
- **Type 3** (AUTHENTICATE_MESSAGE): client sends user, domain, LM/NT responses

Connection tracking pairs Type 2 and Type 3 by TCP 4-tuple.

Hash classification (hashcat modes):
- Mode 5500: Net-NTLMv1, Net-NTLMv1-ESS (NT response == 24 bytes)
- Mode 5600: Net-NTLMv2, Net-LMv2 (NT response > 24 bytes)
"""

from __future__ import annotations

import base64
import logging
import re
import socket
import struct

from impacket import ntlm, spnego

from kerbwolf.core.capture import AttackType, CapturedHash
from kerbwolf.core.capture import _skip_ipv6_extensions as _skip_ipv6_ext

_log = logging.getLogger(__name__)

# Ports that carry NTLM authentication.
_SMB_PORTS = frozenset({445, 139})
_HTTP_PORTS = frozenset({80, 5985, 5986})  # HTTP + WinRM
_LDAP_PORT = 389
_SMTP_PORTS = frozenset({25, 587})
_POP3_PORT = 110
_IMAP_PORT = 143
_TELNET_PORT = 23
_NTLM_PORTS = _SMB_PORTS | _HTTP_PORTS | {_LDAP_PORT} | _SMTP_PORTS | {_POP3_PORT, _IMAP_PORT, _TELNET_PORT}

_IP_PROTO_TCP = 6

# NTLMSSP signature and message type offsets.
_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
_NTLMSSP_TYPE_OFFSET = 8  # byte offset of MessageType in NTLMSSP token

# NTLM response length thresholds.
_NTLMV1_RESPONSE_LEN = 24
_NTLM_NTPROOFSTR_LEN = 16
_NTLM_ESS_ZERO_PAD = b"\x00" * 16

# SMB signatures.
_SMB1_SIGNATURE = b"\xffSMB"
_SMB2_SIGNATURE = b"\xfeSMB"
_SMB1_SESSION_SETUP = 0x73
_SMB2_SESSION_SETUP = 0x0001

# NTLMSSP negotiate flag for Unicode strings.
_NTLMSSP_NEGOTIATE_UNICODE = 0x00000001

# Type alias for connection tracking state.
NtlmSessions = dict[tuple[str, int, str, int], bytes]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def try_extract_ntlm(
    ip_data: bytes,
    sessions: NtlmSessions,
) -> list[CapturedHash]:
    """Try to extract NTLM hashes from link-layer-stripped IP data.

    Handles SMB (445/139), HTTP (80), LDAP (389), SMTP (25/587),
    POP3 (110), and Telnet (23).

    Type 2 (CHALLENGE) messages store the server challenge in *sessions*.
    Type 3 (AUTHENTICATE) messages look up the challenge and produce hashes.

    Callers must strip the link layer before calling this function.
    """
    result = _strip_ip_transport_full(ip_data)
    if result is None:
        return []

    payload, src_ip, src_port, dst_ip, dst_port, proto = result

    if proto != _IP_PROTO_TCP or payload is None:
        return []

    # Check if either port is an NTLM-carrying port.
    if src_port not in _NTLM_PORTS and dst_port not in _NTLM_PORTS:
        return []

    # Determine the active NTLM port (the well-known port side).
    ntlm_port = src_port if src_port in _NTLM_PORTS else dst_port

    # Extract NTLMSSP token(s) from the transport layer.
    tokens = _extract_ntlmssp_tokens(payload, ntlm_port)
    if not tokens:
        return []

    results: list[CapturedHash] = []
    for token in tokens:
        if len(token) <= _NTLMSSP_TYPE_OFFSET:
            continue
        msg_type = token[_NTLMSSP_TYPE_OFFSET]

        if msg_type == 2:  # noqa: PLR2004 - CHALLENGE_MESSAGE
            # Store challenge keyed by (server_ip, server_port, client_ip, client_port).
            # Type 2 is sent FROM the server, so src is the server.
            conn_key = (src_ip, src_port, dst_ip, dst_port)
            _handle_type2(token, conn_key, sessions)

        elif msg_type == 3:  # noqa: PLR2004 - AUTHENTICATE_MESSAGE
            # Type 3 is sent FROM the client, so the server is at (dst_ip, dst_port).
            # Look up the challenge stored when the server sent Type 2.
            conn_key = (dst_ip, dst_port, src_ip, src_port)
            results.extend(_handle_type3(token, conn_key, sessions))

    # SMB1 raw auth (no NTLMSSP wrapper) - only on SMB ports.
    if ntlm_port in _SMB_PORTS:
        raw = _extract_smb1_raw_auth(payload, sessions, src_ip, src_port, dst_ip, dst_port)
        if raw:
            results.extend(raw)

    return results


def extract_ntlm_from_stream(
    buffer: bytearray,
    conn_key: tuple[str, int, str, int],
    ntlm_port: int,
    sessions: NtlmSessions,
) -> list[CapturedHash]:
    """Extract NTLM hashes from a buffered TCP stream.

    For SMB (ports 445/139), uses the 4-byte NetBIOS session header as
    message boundary.  For text protocols, tries extraction on the full
    buffer and clears consumed data on success.

    The *conn_key* is ``(src_ip, src_port, dst_ip, dst_port)`` of the
    packet that last appended to this buffer.
    """
    results: list[CapturedHash] = []

    if ntlm_port in _SMB_PORTS:
        # SMB: NetBIOS session header = type(1) + length(3).
        while len(buffer) > 4 and buffer[0] == 0x00:  # noqa: PLR2004
            nb_len = struct.unpack("!I", b"\x00" + bytes(buffer[1:4]))[0]
            total = 4 + nb_len
            if total > len(buffer):
                break  # Incomplete, wait for more data.
            smb_data = bytes(buffer[4:total])
            results.extend(_extract_ntlm_from_smb_message(smb_data, conn_key, sessions))
            del buffer[:total]
        return results

    # Text/telnet protocols: try extraction on the full buffer.
    payload = bytes(buffer)
    tokens = _extract_ntlmssp_tokens(payload, ntlm_port)
    if tokens:
        results.extend(_process_ntlm_tokens(tokens, conn_key, sessions))
        buffer.clear()

    # Also check for SMB1 raw auth on SMB ports (handled above).
    return results


def _extract_ntlm_from_smb_message(
    smb_data: bytes,
    conn_key: tuple[str, int, str, int],
    sessions: NtlmSessions,
) -> list[CapturedHash]:
    """Extract NTLM from a single complete SMB message (after NetBIOS header)."""
    results: list[CapturedHash] = []
    src_ip, src_port, dst_ip, dst_port = conn_key

    # Try NTLMSSP path.
    blob = _extract_smb_blob_from_data(smb_data)
    if blob is not None:
        token = _unwrap_spnego(blob)
        if token is not None and len(token) > _NTLMSSP_TYPE_OFFSET:
            results.extend(_process_ntlm_tokens([token], conn_key, sessions))

    # Try SMB1 raw auth (WordCount=13).
    if len(smb_data) >= 33 and smb_data[:4] == _SMB1_SIGNATURE and smb_data[4] == _SMB1_SESSION_SETUP and smb_data[32] == 13:  # noqa: PLR2004
        raw = _extract_smb1_raw_auth_from_data(smb_data, sessions, src_ip, src_port, dst_ip, dst_port)
        if raw:
            results.extend(raw)

    return results


def _extract_smb_blob_from_data(smb_data: bytes) -> bytes | None:
    """Extract security blob from SMB data (no NetBIOS header)."""
    if len(smb_data) < 5:  # noqa: PLR2004
        return None
    if smb_data[:4] == _SMB2_SIGNATURE:
        return _extract_smb2_session_setup_blob(smb_data)
    if smb_data[:4] == _SMB1_SIGNATURE:
        return _extract_smb1_session_setup_blob(smb_data)
    return None


def _extract_smb1_raw_auth_from_data(
    data: bytes,
    sessions: NtlmSessions,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> list[CapturedHash] | None:
    """Extract raw LM/NT from SMB1 basic security data (no NetBIOS header)."""
    if len(data) < 37 or data[:4] != _SMB1_SIGNATURE:  # noqa: PLR2004
        return None
    if data[4] != _SMB1_SESSION_SETUP:
        return None
    if data[32] != 13:  # noqa: PLR2004
        return None

    params_start = 33
    if len(data) < params_start + 26 + 2:
        return None

    oem_pw_len = struct.unpack("<H", data[params_start + 14 : params_start + 16])[0]
    uni_pw_len = struct.unpack("<H", data[params_start + 16 : params_start + 18])[0]

    data_start = params_start + 26 + 2
    if data_start + oem_pw_len + uni_pw_len > len(data):
        return None

    lm_response = data[data_start : data_start + oem_pw_len]
    nt_response = data[data_start + oem_pw_len : data_start + oem_pw_len + uni_pw_len]

    str_start = data_start + oem_pw_len + uni_pw_len
    remaining = data[str_start:]
    flags2 = struct.unpack("<H", data[10:12])[0] if len(data) >= 12 else 0  # noqa: PLR2004
    is_unicode = bool(flags2 & 0x8000)
    user, domain = _decode_smb1_identity_strings(remaining, is_unicode=is_unicode)

    if not user and not nt_response and (not lm_response or lm_response == b"\x00"):
        return None

    conn_key_server = (dst_ip, dst_port, src_ip, src_port)
    challenge = sessions.get(conn_key_server)
    if challenge is None:
        return None

    return _classify_ntlm_hash(user, domain, challenge, nt_response, lm_response)


def _process_ntlm_tokens(
    tokens: list[bytes],
    conn_key: tuple[str, int, str, int],
    sessions: NtlmSessions,
) -> list[CapturedHash]:
    """Process NTLMSSP tokens, storing Type 2 challenges and extracting Type 3 hashes."""
    src_ip, src_port, dst_ip, dst_port = conn_key
    results: list[CapturedHash] = []
    for token in tokens:
        if len(token) <= _NTLMSSP_TYPE_OFFSET:
            continue
        msg_type = token[_NTLMSSP_TYPE_OFFSET]
        if msg_type == 2:  # noqa: PLR2004
            _handle_type2(token, conn_key, sessions)
        elif msg_type == 3:  # noqa: PLR2004
            server_key = (dst_ip, dst_port, src_ip, src_port)
            results.extend(_handle_type3(token, server_key, sessions))
    return results


# ---------------------------------------------------------------------------
# IP + transport parsing with address extraction
# ---------------------------------------------------------------------------


def _strip_ip_transport_full(
    ip_data: bytes,
) -> tuple[bytes, str, int, str, int, int] | None:
    """Parse IP + TCP headers, returning payload and full connection info.

    Returns ``(payload, src_ip, src_port, dst_ip, dst_port, proto)`` or
    ``None`` if the packet cannot be parsed.
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
        proto, transport_data = _skip_ipv6_ext(ip_data[6], ip_data[40:])
    else:
        return None

    if proto != _IP_PROTO_TCP or len(transport_data) < 20:  # noqa: PLR2004
        return None

    src_port, dst_port = struct.unpack("!HH", transport_data[:4])
    data_offset = ((transport_data[12] >> 4) & 0xF) * 4
    payload = transport_data[data_offset:]
    return payload, src_ip, src_port, dst_ip, dst_port, proto


# ---------------------------------------------------------------------------
# Transport-specific NTLMSSP token extraction
# ---------------------------------------------------------------------------


def _extract_ntlmssp_tokens(payload: bytes, ntlm_port: int) -> list[bytes]:
    """Extract NTLMSSP tokens from the transport payload.

    Returns a list of raw NTLMSSP tokens (after SPNEGO unwrapping if needed).
    """
    if ntlm_port in _SMB_PORTS:
        blob = _extract_smb_security_blob(payload)
        if blob is None:
            return []
        token = _unwrap_spnego(blob)
        return [token] if token is not None else []

    if ntlm_port in _HTTP_PORTS:
        return _extract_http_ntlm_tokens(payload)

    if ntlm_port == _LDAP_PORT:
        token = _extract_ldap_ntlm_token(payload)
        return [token] if token is not None else []

    if ntlm_port in _SMTP_PORTS:
        return _extract_smtp_ntlm_tokens(payload)

    if ntlm_port == _POP3_PORT:
        return _extract_pop3_ntlm_tokens(payload)

    if ntlm_port == _IMAP_PORT:
        return _extract_imap_ntlm_tokens(payload)

    if ntlm_port == _TELNET_PORT:
        return _extract_telnet_ntlm_tokens(payload)

    return []


# ---------------------------------------------------------------------------
# SMB security blob extraction
# ---------------------------------------------------------------------------


def _extract_smb_security_blob(tcp_payload: bytes) -> bytes | None:
    """Extract the security blob from an SMB SESSION_SETUP packet.

    Handles SMB1 (extended security, WordCount=12) and SMB2.
    Strips the 4-byte NetBIOS session header if present.
    """
    data = tcp_payload

    # Strip NetBIOS session header (type=0x00, 3-byte length).
    if len(data) > 4 and data[0] == 0x00:  # noqa: PLR2004
        nb_len = struct.unpack("!I", b"\x00" + data[1:4])[0]
        if nb_len <= len(data) - 4:
            data = data[4 : 4 + nb_len]

    if len(data) < 5:  # noqa: PLR2004
        return None

    # SMB2: \xfeSMB
    if data[:4] == _SMB2_SIGNATURE:
        return _extract_smb2_session_setup_blob(data)

    # SMB1: \xffSMB
    if data[:4] == _SMB1_SIGNATURE:
        return _extract_smb1_session_setup_blob(data)

    return None


def _extract_smb2_session_setup_blob(data: bytes) -> bytes | None:
    """Extract security blob from an SMB2 SESSION_SETUP message."""
    if len(data) < 66:  # noqa: PLR2004 - 64-byte header + 2-byte StructureSize
        return None

    # SMB2 header: command at offset 12 (2 bytes LE).
    command = struct.unpack("<H", data[12:14])[0]
    if command != _SMB2_SESSION_SETUP:
        return None

    # Payload starts at offset 64 (after the 64-byte SMB2 header).
    cmd_data = data[64:]

    if len(cmd_data) < 8:  # noqa: PLR2004
        return None

    structure_size = struct.unpack("<H", cmd_data[:2])[0]

    # SESSION_SETUP Request: StructureSize=25 (0x19)
    # SecurityBufferOffset at cmd offset 12, SecurityBufferLength at cmd offset 14.
    if structure_size == 25 and len(cmd_data) >= 16:  # noqa: PLR2004
        buf_offset = struct.unpack("<H", cmd_data[12:14])[0]
        buf_len = struct.unpack("<H", cmd_data[14:16])[0]
        # Offset is from start of SMB2 header.
        start = buf_offset - 64
        if start >= 0 and start + buf_len <= len(cmd_data):
            return cmd_data[start : start + buf_len]

    # SESSION_SETUP Response: StructureSize=9 (0x09)
    # SecurityBufferOffset at cmd offset 4, SecurityBufferLength at cmd offset 6.
    if structure_size == 9 and len(cmd_data) >= 8:  # noqa: PLR2004
        buf_offset = struct.unpack("<H", cmd_data[4:6])[0]
        buf_len = struct.unpack("<H", cmd_data[6:8])[0]
        start = buf_offset - 64
        if start >= 0 and start + buf_len <= len(cmd_data):
            return cmd_data[start : start + buf_len]

    return None


def _extract_smb1_session_setup_blob(data: bytes) -> bytes | None:
    """Extract security blob from an SMB1 SESSION_SETUP_ANDX (WordCount=12)."""
    if len(data) < 37:  # noqa: PLR2004 - 32-byte header + 1 WC + min params
        return None

    # SMB1 command at offset 4.
    if data[4] != _SMB1_SESSION_SETUP:
        return None

    # WordCount at offset 32.
    word_count = data[32]
    if word_count != 12:  # noqa: PLR2004 - extended security
        return None

    # Parameters start at offset 33, 24 bytes (12 words).
    params_start = 33
    if len(data) < params_start + 24:
        return None

    # SecurityBlobLength is at parameter offset 14 (2 bytes LE).
    blob_len = struct.unpack("<H", data[params_start + 14 : params_start + 16])[0]

    # ByteCount at offset 33 + 24 = 57 (2 bytes LE).
    bc_offset = params_start + 24
    if len(data) < bc_offset + 2:
        return None

    # Security blob starts right after ByteCount.
    blob_start = bc_offset + 2
    if blob_start + blob_len > len(data):
        return None

    return data[blob_start : blob_start + blob_len]


# ---------------------------------------------------------------------------
# SMB1 raw auth (WordCount=13, no NTLMSSP wrapper)
# ---------------------------------------------------------------------------


def _extract_smb1_raw_auth(
    tcp_payload: bytes,
    sessions: NtlmSessions,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
) -> list[CapturedHash] | None:
    """Extract LM/NT responses from SMB1 basic security (WordCount=13).

    This legacy path has no NTLMSSP wrapper. The LM and NT response bytes are
    directly in the SESSION_SETUP_ANDX data fields. Requires a previously
    stored challenge from the SMB1 NEGOTIATE response.
    """
    data = tcp_payload

    # Strip NetBIOS session header.
    if len(data) > 4 and data[0] == 0x00:  # noqa: PLR2004
        nb_len = struct.unpack("!I", b"\x00" + data[1:4])[0]
        if nb_len <= len(data) - 4:
            data = data[4 : 4 + nb_len]

    if len(data) < 37 or data[:4] != _SMB1_SIGNATURE:  # noqa: PLR2004
        return None

    if data[4] != _SMB1_SESSION_SETUP:
        return None

    word_count = data[32]
    if word_count != 13:  # noqa: PLR2004 - basic security
        return None

    # Parameters: 26 bytes (13 words) starting at offset 33.
    params_start = 33
    if len(data) < params_start + 26 + 2:
        return None

    # OEMPasswordLen at param offset 14, UnicodePasswordLen at param offset 16.
    oem_pw_len = struct.unpack("<H", data[params_start + 14 : params_start + 16])[0]
    uni_pw_len = struct.unpack("<H", data[params_start + 16 : params_start + 18])[0]

    # Data starts after params (33 + 26) + ByteCount (2).
    data_start = params_start + 26 + 2
    if data_start + oem_pw_len + uni_pw_len > len(data):
        return None

    lm_response = data[data_start : data_start + oem_pw_len]
    nt_response = data[data_start + oem_pw_len : data_start + oem_pw_len + uni_pw_len]

    # Identity strings follow the password fields.
    str_start = data_start + oem_pw_len + uni_pw_len
    remaining = data[str_start:]

    # Check SMB flags2 for Unicode.
    flags2 = struct.unpack("<H", data[10:12])[0] if len(data) >= 12 else 0  # noqa: PLR2004
    is_unicode = bool(flags2 & 0x8000)

    user, domain = _decode_smb1_identity_strings(remaining, is_unicode=is_unicode)

    if not user and not nt_response and (not lm_response or lm_response == b"\x00"):
        return None  # Anonymous

    # Look up challenge. Server is at (dst_ip, dst_port) for this client→server packet.
    conn_key = (dst_ip, dst_port, src_ip, src_port)
    challenge = sessions.get(conn_key)
    if challenge is None:
        return None

    return _classify_ntlm_hash(user, domain, challenge, nt_response, lm_response)


def _decode_smb1_identity_strings(data: bytes, *, is_unicode: bool) -> tuple[str, str]:
    """Decode user and domain strings from SMB1 basic security data."""
    if is_unicode:
        # Padding byte for 2-byte alignment.
        offset = 1 if len(data) > 0 and len(data) % 2 != 0 else 0
        data = data[offset:]
        strings = data.split(b"\x00\x00")
        parts = [s.replace(b"\x00", b"").decode("utf-16-le", errors="replace") for s in strings[:2]]
    else:
        parts = [s.decode("cp437", errors="replace") for s in data.split(b"\x00")[:2]]

    user = parts[0] if len(parts) > 0 else ""
    domain = parts[1] if len(parts) > 1 else ""
    return user, domain


# ---------------------------------------------------------------------------
# HTTP NTLM extraction
# ---------------------------------------------------------------------------

# Match Authorization: NTLM <base64> or WWW-Authenticate: NTLM <base64>
_HTTP_NTLM_RE = re.compile(
    rb"(?:Authorization|WWW-Authenticate|Proxy-Authenticate|Proxy-Authorization)"
    rb":\s*NTLM\s+([A-Za-z0-9+/=]+)",
    re.IGNORECASE,
)


def _extract_http_ntlm_tokens(payload: bytes) -> list[bytes]:
    """Extract NTLMSSP tokens from HTTP Authorization/Authenticate headers."""
    tokens: list[bytes] = []
    for match in _HTTP_NTLM_RE.finditer(payload):
        try:
            raw = base64.b64decode(match.group(1))
            if raw[:8] == _NTLMSSP_SIGNATURE:
                tokens.append(raw)
        except Exception:  # noqa: BLE001, S112
            continue
    return tokens


# ---------------------------------------------------------------------------
# LDAP NTLM extraction
# ---------------------------------------------------------------------------


def _extract_ldap_ntlm_token(payload: bytes) -> bytes | None:
    """Extract NTLMSSP token from LDAP SASL BindRequest/BindResponse.

    LDAP messages are BER/DER encoded. We look for the NTLMSSP signature
    or SPNEGO markers within the payload rather than fully parsing LDAP ASN.1.
    """
    # Search for NTLMSSP signature directly.
    idx = payload.find(_NTLMSSP_SIGNATURE)
    if idx >= 0:
        return payload[idx:]

    # Search for SPNEGO markers and try unwrapping.
    for marker in (0x60, 0xA1):
        idx = payload.find(bytes([marker]))
        if idx >= 0:
            token = _unwrap_spnego(payload[idx:])
            if token is not None:
                return token

    return None


# ---------------------------------------------------------------------------
# SMTP NTLM extraction (MS-SMTPNTLM, ports 25/587)
# ---------------------------------------------------------------------------

# Server challenge: "334 <base64>\r\n"
# Client authenticate: bare "<base64>\r\n" or "AUTH NTLM <base64>\r\n"
_SMTP_334_RE = re.compile(rb"334\s+([A-Za-z0-9+/=]+)")
_SMTP_AUTH_NTLM_RE = re.compile(rb"AUTH\s+NTLM\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)
_BARE_B64_RE = re.compile(rb"^([A-Za-z0-9+/=]{20,})\r?\n?$", re.MULTILINE)


def _extract_smtp_ntlm_tokens(payload: bytes) -> list[bytes]:
    """Extract NTLMSSP tokens from SMTP AUTH NTLM exchange.

    Per [MS-SMTPNTLM]:
    - Server sends challenge as ``334 <base64>``
    - Client sends Type 1 as ``AUTH NTLM <base64>`` or after ``334`` prompt
    - Client sends Type 3 as bare ``<base64>`` line
    """
    tokens: list[bytes] = []
    for match in _SMTP_334_RE.finditer(payload):
        _try_decode_b64_ntlm(match.group(1), tokens)
    for match in _SMTP_AUTH_NTLM_RE.finditer(payload):
        _try_decode_b64_ntlm(match.group(1), tokens)
    if not tokens:
        for match in _BARE_B64_RE.finditer(payload):
            _try_decode_b64_ntlm(match.group(1), tokens)
    return tokens


# ---------------------------------------------------------------------------
# POP3 NTLM extraction (MS-POP3, port 110)
# ---------------------------------------------------------------------------

# Server challenge: "+ <base64>\r\n"
_POP3_CHALLENGE_RE = re.compile(rb"\+\s+([A-Za-z0-9+/=]{20,})")


def _extract_pop3_ntlm_tokens(payload: bytes) -> list[bytes]:
    """Extract NTLMSSP tokens from POP3 AUTH NTLM exchange.

    Per [MS-POP3]:
    - Client sends ``AUTH NTLM``
    - Server responds ``+OK`` then client sends Type 1 as bare base64
    - Server sends challenge as ``+ <base64>``
    - Client sends Type 3 as bare base64
    """
    tokens: list[bytes] = []
    for match in _POP3_CHALLENGE_RE.finditer(payload):
        _try_decode_b64_ntlm(match.group(1), tokens)
    if not tokens:
        for match in _BARE_B64_RE.finditer(payload):
            _try_decode_b64_ntlm(match.group(1), tokens)
    return tokens


# ---------------------------------------------------------------------------
# IMAP NTLM extraction (MS-OXIMAP, port 143)
# ---------------------------------------------------------------------------

# IMAP uses the same challenge format as POP3: "+ <base64>"
# Client can also send Type 1 inline: "tag AUTHENTICATE NTLM <base64>"
_IMAP_AUTH_NTLM_RE = re.compile(rb"AUTHENTICATE\s+NTLM\s+([A-Za-z0-9+/=]+)", re.IGNORECASE)


def _extract_imap_ntlm_tokens(payload: bytes) -> list[bytes]:
    """Extract NTLMSSP tokens from IMAP AUTHENTICATE NTLM exchange.

    Per [MS-OXIMAP]:
    - Client sends ``tag AUTHENTICATE NTLM [base64-Type1]``
    - Server sends challenge as ``+ <base64>``
    - Client sends Type 3 as bare base64 line
    """
    tokens: list[bytes] = []
    # Server challenge: "+ <base64>" (same as POP3).
    for match in _POP3_CHALLENGE_RE.finditer(payload):
        _try_decode_b64_ntlm(match.group(1), tokens)
    # AUTHENTICATE NTLM with inline Type 1.
    for match in _IMAP_AUTH_NTLM_RE.finditer(payload):
        _try_decode_b64_ntlm(match.group(1), tokens)
    # Bare base64 lines (client Type 1 or Type 3).
    if not tokens:
        for match in _BARE_B64_RE.finditer(payload):
            _try_decode_b64_ntlm(match.group(1), tokens)
    return tokens


# ---------------------------------------------------------------------------
# Telnet NTLM extraction (MS-TNAP, port 23)
# ---------------------------------------------------------------------------

# Telnet IAC subnegotiation framing.
_IAC = 0xFF
_SB = 0xFA
_SE = 0xF0
_TELNET_AUTH_OPTION = 0x25  # Telnet Authentication Option (RFC 2941)
_TNAP_AUTH_TYPE_NTLM = 0x0F


def _extract_telnet_ntlm_tokens(payload: bytes) -> list[bytes]:
    """Extract NTLMSSP tokens from Telnet NTLM subnegotiation.

    Per [MS-TNAP], NTLM tokens are carried raw (not base64) inside
    Telnet IAC SB AUTHENTICATION subnegotiation frames::

        IAC SB AUTH IS/REPLY 0x0F 0x00 NTLM_CommandCode NTLM_DataSize(4,LE)
        NTLM_BufferType(4,LE) NTLM_Data IAC SE

    NTLM_CommandCode: 0x00=NEGOTIATE, 0x01=CHALLENGE, 0x02=AUTHENTICATE
    """
    tokens: list[bytes] = []
    idx = 0
    while idx < len(payload) - 5:
        if payload[idx] != _IAC or payload[idx + 1] != _SB or payload[idx + 2] != _TELNET_AUTH_OPTION:
            idx += 1
            continue

        end = payload.find(bytes([_IAC, _SE]), idx + 3)
        if end < 0:
            break

        subneg = payload[idx + 3 : end]
        if len(subneg) < 11 or subneg[1] != _TNAP_AUTH_TYPE_NTLM:  # noqa: PLR2004
            idx = end + 2
            continue

        ntlm_cmd = subneg[3]
        if ntlm_cmd > 2:  # noqa: PLR2004
            idx = end + 2
            continue

        if len(subneg) < 12:  # noqa: PLR2004
            idx = end + 2
            continue

        data_size = struct.unpack("<I", subneg[4:8])[0]
        ntlm_data = subneg[12 : 12 + data_size]

        if ntlm_data[:8] == _NTLMSSP_SIGNATURE:
            tokens.append(bytes(ntlm_data))

        idx = end + 2

    return tokens


# ---------------------------------------------------------------------------
# Shared base64 decode helper
# ---------------------------------------------------------------------------


def _try_decode_b64_ntlm(b64_data: bytes, tokens: list[bytes]) -> None:
    """Try to base64-decode data and append if it's a valid NTLMSSP token."""
    try:
        raw = base64.b64decode(b64_data)
        if raw[:8] == _NTLMSSP_SIGNATURE:
            tokens.append(raw)
    except Exception:  # noqa: BLE001, S110
        pass


# ---------------------------------------------------------------------------
# SPNEGO unwrapping
# ---------------------------------------------------------------------------


def _unwrap_spnego(blob: bytes) -> bytes | None:
    """Unwrap SPNEGO to get the inner NTLMSSP token.

    Returns the raw NTLMSSP token, or ``None`` if unwrapping fails.
    Handles bare NTLMSSP (no wrapping), negTokenInit (0x60), and
    negTokenResp (0xa1).
    """
    if not blob:
        return None

    # Already bare NTLMSSP.
    if blob[:8] == _NTLMSSP_SIGNATURE:
        return blob

    try:
        if blob[0] == 0x60:  # noqa: PLR2004 - negTokenInit
            neg = spnego.SPNEGO_NegTokenInit(data=blob)
            mech_token = neg["MechToken"]
            if mech_token and bytes(mech_token)[:8] == _NTLMSSP_SIGNATURE:
                return bytes(mech_token)
        elif blob[0] == 0xA1:  # noqa: PLR2004 - negTokenResp
            neg = spnego.SPNEGO_NegTokenResp(data=blob)
            resp_token = neg["ResponseToken"]
            if resp_token and bytes(resp_token)[:8] == _NTLMSSP_SIGNATURE:
                return bytes(resp_token)
    except Exception:  # noqa: BLE001, S110
        pass

    return None


# ---------------------------------------------------------------------------
# NTLMSSP Type 2 / Type 3 handling
# ---------------------------------------------------------------------------


def _handle_type2(token: bytes, conn_key: tuple[str, int, str, int], sessions: NtlmSessions) -> None:
    """Store the 8-byte server challenge from an NTLMSSP Type 2 message."""
    try:
        challenge_msg = ntlm.NTLMAuthChallenge(data=token)
        challenge_bytes = challenge_msg["challenge"]
        if challenge_bytes and len(challenge_bytes) == 8:  # noqa: PLR2004
            sessions[conn_key] = bytes(challenge_bytes)
            _log.debug("NTLM Type 2: stored challenge for %s", conn_key)
    except Exception:  # noqa: BLE001, S110
        pass


def _handle_type3(
    token: bytes,
    conn_key: tuple[str, int, str, int],
    sessions: NtlmSessions,
) -> list[CapturedHash]:
    """Extract hashes from an NTLMSSP Type 3 (AUTHENTICATE) message."""
    challenge = sessions.get(conn_key)
    if challenge is None:
        _log.debug("NTLM Type 3: no matching challenge for %s", conn_key)
        return []

    try:
        auth = ntlm.NTLMAuthChallengeResponse()
        auth.fromString(token)
    except Exception:  # noqa: BLE001
        return []

    nt_response = bytes(auth["ntlm"] or b"")
    lm_response = bytes(auth["lanman"] or b"")
    flags = int(auth["flags"] or 0)

    # Decode identity strings.
    user_raw = auth["user_name"]
    domain_raw = auth["domain_name"]
    if flags & _NTLMSSP_NEGOTIATE_UNICODE:
        user = bytes(user_raw).decode("utf-16-le", errors="replace") if user_raw else ""
        domain = bytes(domain_raw).decode("utf-16-le", errors="replace") if domain_raw else ""
    else:
        user = bytes(user_raw).decode("cp437", errors="replace") if user_raw else ""
        domain = bytes(domain_raw).decode("cp437", errors="replace") if domain_raw else ""

    # Skip anonymous authentication.
    if not user and not nt_response and (not lm_response or lm_response == b"\x00"):
        return []

    return _classify_ntlm_hash(user, domain, challenge, nt_response, lm_response)


# ---------------------------------------------------------------------------
# Hash classification
# ---------------------------------------------------------------------------


def _classify_ntlm_hash(
    user: str,
    domain: str,
    server_challenge: bytes,
    nt_response: bytes,
    lm_response: bytes,
) -> list[CapturedHash]:
    """Classify and format NTLM hashes from Type 3 fields.

    Returns one or two ``CapturedHash`` instances (NTLMv2 may include an
    LMv2 companion hash).

    Classification:
        ``len(nt_response) > 24``  → NTLMv2 (mode 5600)
        ``len(nt_response) == 24`` → NTLMv1 or NTLMv1-ESS (mode 5500)
    """
    if not nt_response:
        return []

    challenge_hex = server_challenge.hex()
    results: list[CapturedHash] = []

    if len(nt_response) > _NTLMV1_RESPONSE_LEN:
        # NTLMv2 - hashcat mode 5600.
        ntproofstr_hex = nt_response[:_NTLM_NTPROOFSTR_LEN].hex()
        blob_hex = nt_response[_NTLM_NTPROOFSTR_LEN:].hex()
        results.append(
            CapturedHash(
                attack=AttackType.NTLMV2,
                username=user,
                realm=domain,
                spn="",
                etype=0,
                cipher_hex=ntproofstr_hex,
                challenge_hex=challenge_hex,
                ntlm_blob_hex=blob_hex,
            )
        )

        # LMv2 companion (also mode 5600).
        if len(lm_response) == _NTLMV1_RESPONSE_LEN and lm_response != b"\x00" * _NTLMV1_RESPONSE_LEN:
            lmproof_hex = lm_response[:_NTLM_NTPROOFSTR_LEN].hex()
            client_challenge_hex = lm_response[_NTLM_NTPROOFSTR_LEN:_NTLMV1_RESPONSE_LEN].hex()
            results.append(
                CapturedHash(
                    attack=AttackType.NTLMV2,
                    username=user,
                    realm=domain,
                    spn="",
                    etype=0,
                    cipher_hex=lmproof_hex,
                    challenge_hex=challenge_hex,
                    ntlm_blob_hex=client_challenge_hex,
                )
            )

    elif len(nt_response) == _NTLMV1_RESPONSE_LEN:
        nt_hex = nt_response.hex()

        # NTLMv1-ESS: LM response is ClientChallenge(8) + zeros(16).
        is_ess = len(lm_response) == _NTLMV1_RESPONSE_LEN and lm_response[8:_NTLMV1_RESPONSE_LEN] == _NTLM_ESS_ZERO_PAD

        if is_ess:
            lm_hex = lm_response[:8].hex() + _NTLM_ESS_ZERO_PAD.hex()
        elif lm_response and lm_response != nt_response:
            # Plain NTLMv1 - include LM response unless it's a duplicate or empty.
            lm_hex = lm_response.hex()
        else:
            lm_hex = ""

        results.append(
            CapturedHash(
                attack=AttackType.NTLMV1,
                username=user,
                realm=domain,
                spn="",
                etype=0,
                cipher_hex=nt_hex,
                challenge_hex=challenge_hex,
                lm_hex=lm_hex,
            )
        )

    return results
