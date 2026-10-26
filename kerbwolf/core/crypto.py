# SPDX-License-Identifier: Apache-2.0
"""Key derivation for all Windows Kerberos encryption types.

Wraps impacket's ``_enctype_table``, ``Key``, and ``string_to_key`` to
provide a clean interface for deriving keys from passwords and computing
Kerberos salts.  Adds RFC 8009 (AES-SHA2) key derivation that impacket
does not yet support.
"""

from __future__ import annotations

import hashlib
import hmac
import struct

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
    EncryptionType.AES128_CTS_HMAC_SHA256_128: 19,
    EncryptionType.AES256_CTS_HMAC_SHA384_192: 20,
    EncryptionType.RC4_HMAC: 23,
}

_RFC8009_ETYPE_SALT_PREFIX: dict[EncryptionType, str] = {
    EncryptionType.AES128_CTS_HMAC_SHA256_128: "aes128-cts-hmac-sha256-128",
    EncryptionType.AES256_CTS_HMAC_SHA384_192: "aes256-cts-hmac-sha384-192",
}

_RFC8009_WINDOWS_ITERATION_COUNT = 4096


def _rfc8009_string_to_key(password: str, salt: str, etype: EncryptionType) -> bytes:
    """RFC 8009 string-to-key for AES-SHA2 etypes (Windows parameters).

    Windows Server 2025 uses 4096 PBKDF2 iterations and prepends the enctype
    name to the salt per RFC 8009 §4, then applies the KDF-HMAC-SHA2 second
    pass from §5.
    """
    if etype == EncryptionType.AES128_CTS_HMAC_SHA256_128:
        hash_name = "sha256"
        key_bytes = 16
    else:
        hash_name = "sha384"
        key_bytes = 32
    key_bits = key_bytes * 8
    etype_prefix = _RFC8009_ETYPE_SALT_PREFIX[etype]
    saltp = (etype_prefix + "\x00" + salt).encode("utf-8")
    tkey = hashlib.pbkdf2_hmac(hash_name, password.encode("utf-8"), saltp, _RFC8009_WINDOWS_ITERATION_COUNT, dklen=key_bytes)
    kdf_input = struct.pack(">I", 1) + b"kerberos" + b"\x00" + struct.pack(">I", key_bits)
    return hmac.new(tkey, kdf_input, hash_name).digest()[:key_bytes]


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


def derive_key_raw(etype: EncryptionType, password: str, salt: str) -> bytes:
    """Derive a raw key (bytes) from *password* and *salt* for any etype."""
    if etype == EncryptionType.RC4_HMAC:
        return bytes(compute_nthash(password))
    if etype in _SHA2_ETYPES:
        return _rfc8009_string_to_key(password, salt, etype)
    impacket_etype = _IMPACKET_ETYPE[etype]
    return bytes(string_to_key(impacket_etype, password, salt).contents)


def derive_key(etype: EncryptionType, password: str, salt: str) -> Key:
    """Derive a single Kerberos key from *password* and *salt*.

    For SHA2 etypes (19/20), wraps the raw bytes in an impacket Key using the
    matching SHA1 etype (17/18) since impacket lacks native SHA2 support.
    """
    raw = derive_key_raw(etype, password, salt)
    if etype in _SHA2_ETYPES:
        aes128_key_size = 16
        compat_etype = 17 if len(raw) == aes128_key_size else 18
        return Key(compat_etype, raw)
    impacket_etype = _IMPACKET_ETYPE[etype]
    return Key(impacket_etype, raw)


_SHA2_ETYPES = {EncryptionType.AES128_CTS_HMAC_SHA256_128, EncryptionType.AES256_CTS_HMAC_SHA384_192}


def derive_all_keys(password: str, salt: str) -> dict[EncryptionType, Key]:
    """Derive Kerberos keys for all Windows encryption types that impacket supports.

    SHA2 etypes (19/20) are excluded because impacket's Key class does not
    accept those etype ints.  Use :func:`derive_key_raw` for SHA2.
    """
    return {etype: derive_key(etype, password, salt) for etype in EncryptionType if etype in _IMPACKET_ETYPE and etype not in _SHA2_ETYPES}


def key_from_hex(etype: EncryptionType, hex_key: str) -> Key:
    """Build a ``Key`` from a hex-encoded key string."""
    impacket_etype = _IMPACKET_ETYPE[etype]
    return Key(impacket_etype, bytes.fromhex(hex_key))
