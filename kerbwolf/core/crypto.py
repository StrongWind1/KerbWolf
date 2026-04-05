"""Key derivation for all Windows Kerberos encryption types.

Wraps impacket's ``_enctype_table``, ``Key``, and ``string_to_key`` to
provide a clean interface for deriving keys from passwords and computing
Kerberos salts.
"""

from __future__ import annotations

from impacket.krb5.crypto import Key, _enctype_table, string_to_key
from impacket.ntlm import compute_nthash

from kerbwolf.models import EncryptionType

# Impacket etype int → cipher class lookup.
# Values are cipher classes with encrypt/decrypt methods - typed as Any
# because impacket has no type stubs.
ENCTYPE_TABLE = _enctype_table  # impacket has no type stubs - inferred as Any

# Maps our EncryptionType to the impacket etype ints used in _enctype_table.
# DES-CBC-CRC (1) is not in impacket's table; we use DES-CBC-MD5 (3) cipher.
_IMPACKET_ETYPE: dict[EncryptionType, int] = {
    EncryptionType.DES_CBC_CRC: 3,
    EncryptionType.DES_CBC_MD5: 3,
    EncryptionType.AES128_CTS_HMAC_SHA1_96: 17,
    EncryptionType.AES256_CTS_HMAC_SHA1_96: 18,
    EncryptionType.RC4_HMAC: 23,
}


# ---------------------------------------------------------------------------
# Salt computation
# ---------------------------------------------------------------------------


def compute_salt(username: str, domain: str) -> str:
    """Compute the Kerberos salt for a principal.

    For user accounts: ``REALM.UPPERusername``
    For machine accounts (ending with ``$``): ``REALM.UPPERhosthostname.realm.lower``
    """
    realm = domain.upper()
    if username.endswith("$"):
        hostname = username.rstrip("$").lower()
        return f"{realm}host{hostname}.{domain.lower()}"
    return f"{realm}{username}"


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_key(etype: EncryptionType, password: str, salt: str) -> Key:
    """Derive a single Kerberos key from *password* and *salt*."""
    impacket_etype = _IMPACKET_ETYPE[etype]
    if etype == EncryptionType.RC4_HMAC:
        return Key(impacket_etype, compute_nthash(password))
    return string_to_key(impacket_etype, password, salt)


def derive_all_keys(password: str, salt: str) -> dict[EncryptionType, Key]:
    """Derive Kerberos keys for all 5 Windows encryption types."""
    return {etype: derive_key(etype, password, salt) for etype in EncryptionType}


def key_from_hex(etype: EncryptionType, hex_key: str) -> Key:
    """Build a ``Key`` from a hex-encoded key string."""
    impacket_etype = _IMPACKET_ETYPE[etype]
    return Key(impacket_etype, bytes.fromhex(hex_key))
