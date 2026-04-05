"""Hash formatters for all Kerberos hashcat modes across all 5 etypes.

Covers 15 attack x etype combinations (3 attacks x 5 etypes):

    etype 1  (DES-CBC-CRC)   - $krb5tgs$1$, $krb5asrep$1$, $krb5pa$1$
    etype 3  (DES-CBC-MD5)   - $krb5tgs$3$, $krb5asrep$3$, $krb5pa$3$
    etype 17 (AES128)        - $krb5tgs$17$, $krb5asrep$17$, $krb5pa$17$
    etype 18 (AES256)        - $krb5tgs$18$, $krb5asrep$18$, $krb5pa$18$
    etype 23 (RC4-HMAC)      - $krb5tgs$23$, $krb5asrep$23$, $krb5pa$23$

RC4/AES hashes crack to the account password.
DES hashes crack to the 56-bit DES key.
"""

from __future__ import annotations

from binascii import hexlify

from impacket.krb5.asn1 import AS_REP, TGS_REP
from pyasn1.codec.der import decoder

from kerbwolf.models import HashcatMode, HashFormat

# ---------------------------------------------------------------------------
# Etype → hashcat mode lookups
# ---------------------------------------------------------------------------

_TGS_MODE: dict[int, int] = {
    1: HashcatMode.KRB5_TGS_DES_CBC_CRC,
    3: HashcatMode.KRB5_TGS_DES_CBC_MD5,
    17: HashcatMode.KRB5_TGS_AES128,
    18: HashcatMode.KRB5_TGS_AES256,
    23: HashcatMode.KRB5_TGS_RC4,
}

_ASREP_MODE: dict[int, int] = {
    1: HashcatMode.KRB5_ASREP_DES_CBC_CRC,
    3: HashcatMode.KRB5_ASREP_DES_CBC_MD5,
    17: HashcatMode.KRB5_ASREP_AES128,
    18: HashcatMode.KRB5_ASREP_AES256,
    23: HashcatMode.KRB5_ASREP_RC4,
}

_PA_MODE: dict[int, int] = {
    1: HashcatMode.KRB5_PA_DES_CBC_CRC,
    3: HashcatMode.KRB5_PA_DES_CBC_MD5,
    17: HashcatMode.KRB5_PA_AES128,
    18: HashcatMode.KRB5_PA_AES256,
    23: HashcatMode.KRB5_PA_RC4,
}


def tgs_hashcat_mode(etype: int) -> int:
    """Return the hashcat mode number for a TGS-REP Roast hash."""
    return _TGS_MODE.get(etype, 0)


def asrep_hashcat_mode(etype: int) -> int:
    """Return the hashcat mode number for an AS-REP Roast hash."""
    return _ASREP_MODE.get(etype, 0)


def pa_hashcat_mode(etype: int) -> int:
    """Return the hashcat mode number for an AS-REQ Pre-Auth hash."""
    return _PA_MODE.get(etype, 0)


# ---------------------------------------------------------------------------
# TGS-REP Roast (Kerberoast) hash formatting
# ---------------------------------------------------------------------------


def format_tgs_hash(
    tgs_rep_bytes: bytes,
    username: str,
    realm: str,
    spn: str,
    *,
    fmt: HashFormat = HashFormat.HASHCAT,
    is_asreq: bool = False,
) -> str:
    """Format a TGS-REP ticket cipher as a crackable hash.

    Works identically for all etypes - extracts the ticket enc-part
    cipher and formats it with the appropriate ``$krb5tgs$`` prefix.

    Args:
        tgs_rep_bytes: Raw TGS-REP (or AS-REP when *is_asreq* is True).
        username: Service account username.
        realm: Kerberos realm (uppercase).
        spn: Service Principal Name.
        fmt: Output format.
        is_asreq: Decode as AS-REP (for AS-REQ Kerberoasting via Charlie Clark technique).

    """
    asn1_spec = AS_REP() if is_asreq else TGS_REP()
    decoded = decoder.decode(tgs_rep_bytes, asn1Spec=asn1_spec)[0]
    etype = int(decoded["ticket"]["enc-part"]["etype"])
    cipher = decoded["ticket"]["enc-part"]["cipher"].asOctets()

    return _format_krb5_hash("krb5tgs", etype, username, realm, cipher, spn=spn, fmt=fmt)


def format_tgs_hash_raw(
    cipher: bytes,
    etype: int,
    username: str,
    realm: str,
    spn: str,
    *,
    fmt: HashFormat = HashFormat.HASHCAT,
) -> str:
    """Format a TGS-REP hash from pre-extracted cipher bytes and etype."""
    return _format_krb5_hash("krb5tgs", etype, username, realm, cipher, spn=spn, fmt=fmt)


# ---------------------------------------------------------------------------
# AS-REP Roast hash formatting
# ---------------------------------------------------------------------------


def format_asrep_hash(
    as_rep_bytes: bytes,
    username: str,
    realm: str,
    *,
    fmt: HashFormat = HashFormat.HASHCAT,
) -> str:
    """Format an AS-REP enc-part cipher as a crackable hash.

    Works identically for all etypes - extracts the AS-REP enc-part
    cipher and formats it with the appropriate ``$krb5asrep$`` prefix.
    """
    decoded = decoder.decode(as_rep_bytes, asn1Spec=AS_REP())[0]
    etype = int(decoded["enc-part"]["etype"])
    cipher = decoded["enc-part"]["cipher"].asOctets()

    return _format_krb5_hash("krb5asrep", etype, username, realm, cipher, fmt=fmt)


def format_asrep_hash_raw(
    cipher: bytes,
    etype: int,
    username: str,
    realm: str,
    *,
    fmt: HashFormat = HashFormat.HASHCAT,
) -> str:
    """Format an AS-REP hash from pre-extracted cipher bytes and etype."""
    return _format_krb5_hash("krb5asrep", etype, username, realm, cipher, fmt=fmt)


# ---------------------------------------------------------------------------
# Timeroasting (MS-SNTP) hash formatting
# ---------------------------------------------------------------------------


def format_sntp_hash(md5_hash: bytes, salt: bytes, rid: int) -> str:
    """Format a 68-byte Authenticator hash for hashcat mode 31300.

    Source:
        ``md5_hash`` = response bytes [52:68] (16 bytes, the Crypto-Checksum).
        ``salt``     = response bytes [0:48]  (48 bytes, the NTP server header).
        ``rid``      = decoded from response bytes [48:52] (XOR'd with bit 31).

    Hash string: ``$sntp-ms$<RID>$<32hex_digest>$<96hex_salt>``

    The RID is metadata only - hashcat mode 31300 cracks as
    ``MD5(candidate_NT_hash || salt)`` and does not use the RID.

    Per ``hashcat/src/modules/module_31300.c``.
    """
    return f"$sntp-ms${rid}${md5_hash.hex()}${salt.hex()}"


def format_sntp_sha512_hash(checksum: bytes, salt: bytes, rid: int) -> str:
    """Format a 120-byte ExtendedAuthenticator hash (no hashcat module yet).

    Source:
        ``checksum`` = response bytes [56:120] (64 bytes, the Crypto-Checksum).
        ``salt``     = response bytes [0:48]   (48 bytes, the NTP server header).
        ``rid``      = decoded from response bytes [48:52] (full 32-bit RID).

    Hash string: ``$sntp-ms-sha512$<RID>$<128hex_digest>$<96hex_salt>``

    The RID is a **required cracking input** - it feeds the SP800-108 KDF
    as the Context parameter.  A cracker must compute:
        derived_key = KDF(candidate_NT_hash, "sntp-ms", RID)
        expected    = HMAC-SHA512(derived_key, salt)
    """
    return f"$sntp-ms-sha512${rid}${checksum.hex()}${salt.hex()}"


# ---------------------------------------------------------------------------
# NTLM hash formatting
# ---------------------------------------------------------------------------


def format_ntlmv2_hash(
    user: str,
    domain: str,
    challenge_hex: str,
    ntproofstr_hex: str,
    blob_hex: str,
) -> str:
    """Format a Net-NTLMv2 hash for hashcat mode 5600.

    Format: ``user::domain:ServerChallenge:NTProofStr:Blob``

    The ``NTProofStr`` is the first 16 bytes of the NT response (32 hex chars).
    The ``Blob`` is the remainder of the NT response after the NTProofStr.
    ``ServerChallenge`` is the 8-byte challenge from the NTLMSSP Type 2 message.
    """
    return f"{user}::{domain}:{challenge_hex}:{ntproofstr_hex}:{blob_hex}"


def format_ntlmv1_hash(
    user: str,
    domain: str,
    lm_hex: str,
    nt_hex: str,
    challenge_hex: str,
) -> str:
    """Format a Net-NTLMv1 or Net-NTLMv1-ESS hash for hashcat mode 5500.

    Format: ``user::domain:LmChallengeResponse:NtChallengeResponse:ServerChallenge``

    For NTLMv1-ESS, the LM slot contains ``ClientChallenge(8 bytes) + zeros(16 bytes)``.
    Hashcat detects ESS internally by checking if LM bytes 8-23 are zero, then
    recomputes the effective challenge as ``MD5(ServerChallenge || ClientChallenge)[:8]``.

    The ``lm_hex`` field may be empty if the LM response was a duplicate of the
    NT response or a known dummy value.
    """
    return f"{user}::{domain}:{lm_hex}:{nt_hex}:{challenge_hex}"


# ---------------------------------------------------------------------------
# AS-REQ Pre-Auth hash formatting
# ---------------------------------------------------------------------------


def format_pa_hash(
    enc_timestamp_cipher: bytes,
    etype: int,
    username: str,
    realm: str,
    *,
    fmt: HashFormat = HashFormat.HASHCAT,
) -> str:
    """Format a captured PA-ENC-TIMESTAMP cipher as a crackable hash.

    The cipher bytes are the raw encrypted timestamp extracted from
    the AS-REQ padata (PA-ENC-TIMESTAMP EncryptedData cipher field).
    """
    return _format_krb5_hash("krb5pa", etype, username, realm, enc_timestamp_cipher, fmt=fmt)


# ---------------------------------------------------------------------------
# Unified formatting engine
# ---------------------------------------------------------------------------


def _format_krb5_hash(
    prefix: str,
    etype: int,
    username: str,
    realm: str,
    cipher: bytes,
    *,
    spn: str | None = None,
    fmt: HashFormat = HashFormat.HASHCAT,
) -> str:
    """Format a Kerberos hash string for any attack type and etype.

    Hash structure by etype:

    RC4 (23):
        Checksum = first 16 bytes (HMAC-MD5).
        Edata2   = remaining bytes.

    AES (17, 18):
        Checksum = last 12 bytes (HMAC-SHA1 truncated).
        Edata2   = everything except last 12 bytes.

    DES (1, 3):
        Cipher   = full encrypted blob (confounder + checksum + data).
        No separate checksum field - the integrity check is embedded.
    """
    cipher_hex = hexlify(cipher).decode()
    safe_spn = spn.replace(":", "~") if spn else None

    if fmt == HashFormat.JOHN:
        return _john_format(prefix, etype, username, realm, cipher, safe_spn)

    # -- Hashcat format -------------------------------------------------------

    if etype == 23:  # noqa: PLR2004 - RC4
        checksum = cipher_hex[:32]
        edata2 = cipher_hex[32:]
        if prefix == "krb5pa":
            return f"${prefix}${etype}${username}${realm}$${edata2}{checksum}"
        if prefix == "krb5asrep":
            return f"${prefix}${etype}${username}@{realm}:{checksum}${edata2}"
        # krb5tgs
        return f"${prefix}${etype}$*{username}${realm}${safe_spn}*${checksum}${edata2}"

    if etype in {17, 18}:  # AES
        checksum = hexlify(cipher[-12:]).decode()
        edata2 = hexlify(cipher[:-12]).decode()
        if prefix == "krb5pa":
            return f"${prefix}${etype}${username}${realm}${edata2}{checksum}"
        if prefix == "krb5asrep":
            return f"${prefix}${etype}${username}${realm}${checksum}${edata2}"
        # krb5tgs
        return f"${prefix}${etype}${username}${realm}$*{safe_spn}*${checksum}${edata2}"

    # DES (1, 3) - full cipher, no checksum/edata2 split.
    if prefix == "krb5pa":
        return f"${prefix}${etype}${username}${realm}${cipher_hex}"
    if prefix == "krb5asrep":
        return f"${prefix}${etype}${username}${realm}${cipher_hex}"
    # krb5tgs
    return f"${prefix}${etype}${username}${realm}$*{safe_spn}*${cipher_hex}"


def _john_format(prefix: str, etype: int, username: str, realm: str, cipher: bytes, spn: str | None) -> str:
    """John the Ripper format.

    John accepts the hashcat format for most Kerberos types.  Where the
    format differs, we emit the john-native format instead.

    Verified against john source: krb5pa-md5_fmt_plug.c, krb5pa-sha1_fmt_plug.c,
    krb5_tgs_fmt_plug.c, krb5_tgsrep_common_plug.c, krb5_asrep_common_plug.c.
    """
    cipher_hex = hexlify(cipher).decode()

    if etype == 23:  # noqa: PLR2004 - RC4
        checksum = cipher_hex[:32]
        edata2 = cipher_hex[32:]
        if prefix == "krb5tgs":
            # john krb5tgs: $krb5tgs$23$*user$realm$spn*$checksum$edata2
            return f"${prefix}${etype}$*{username}${realm}${spn}*${checksum}${edata2}"
        if prefix == "krb5asrep":
            # john krb5asrep: $krb5asrep$23$checksum$edata2
            return f"${prefix}${etype}${checksum}${edata2}"
        # john krb5pa-md5: $krb5pa$23$user$realm$$edata2checksum
        return f"${prefix}${etype}${username}${realm}$${edata2}{checksum}"

    if etype in {17, 18}:  # AES
        checksum = hexlify(cipher[-12:]).decode()
        edata2 = hexlify(cipher[:-12]).decode()
        if prefix == "krb5tgs":
            # john krb5tgs-sha1: $krb5tgs$<etype>$user$realm$checksum$edata2
            return f"${prefix}${etype}${username}${realm}${checksum}${edata2}"
        if prefix == "krb5asrep":
            # john krb5asrep AES: $krb5asrep$<etype>$REALMuser$edata2$checksum
            return f"${prefix}${etype}${realm}{username}${edata2}${checksum}"
        # john krb5pa-sha1: $krb5pa$<etype>$user$realm$$edata2checksum
        return f"${prefix}${etype}${username}${realm}$${edata2}{checksum}"

    # DES (1, 3) - john krb5-3 format: $krb3$REALMuser$cipher
    if etype == 3:  # noqa: PLR2004
        return f"$krb3${realm}{username}${cipher_hex}"
    # DES-CBC-CRC (etype 1) - no john format exists, use hashcat.
    return _format_krb5_hash(prefix, etype, username, realm, cipher, spn=spn, fmt=HashFormat.HASHCAT)
