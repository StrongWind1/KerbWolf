# SPDX-License-Identifier: Apache-2.0
"""Key derivation for all Windows Kerberos encryption types.

Wraps impacket's ``_enctype_table``, ``Key``, and ``string_to_key`` to
provide a clean interface for deriving keys from passwords and computing
Kerberos salts.  Adds RFC 8009 (AES-SHA2) key derivation that impacket
does not yet support, and DES-CBC-CRC (etype 1) which impacket omits.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any

from Cryptodome.Cipher import DES
from impacket.krb5.crypto import Key, _enctype_table, get_random_bytes, string_to_key
from impacket.ntlm import compute_nthash

from kerbwolf.models import EncryptionType

_CRC32_TABLE = [0] * 256
for _i in range(256):
    _crc = _i
    for _ in range(8):
        if _crc & 1:
            _crc = (_crc >> 1) ^ 0xEDB88320
        else:
            _crc >>= 1
        _crc &= 0xFFFFFFFF
    _CRC32_TABLE[_i] = _crc


def _krb5_crc32(data: bytes) -> bytes:
    """RFC 3961 section 6 CRC-32: init=0, no final complement, LE output."""
    crc = 0
    for byte in data:
        crc = _CRC32_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
        crc &= 0xFFFFFFFF
    return struct.pack("<I", crc)


class DesCbcCrc:
    """DES-CBC-CRC (etype 1) cipher per RFC 3961 section 6.2."""

    enctype = 1
    keysize = 8
    blocksize = 8
    padsize = 8
    macsize = 4

    @classmethod
    def encrypt(cls, key: Key, _keyusage: int, plaintext: bytes, confounder: bytes | None) -> bytes:
        """Encrypt with DES-CBC (IV=key) and a CRC-32 integrity check."""
        if confounder is None:
            confounder = bytes(get_random_bytes(cls.blocksize))
        header_len = cls.blocksize + cls.macsize
        pad_needed = (-header_len - len(plaintext)) % cls.padsize
        body = confounder + b"\x00" * cls.macsize + plaintext + b"\x00" * pad_needed
        checksum = _krb5_crc32(body)
        basic_plaintext = body[: cls.blocksize] + checksum + body[cls.blocksize + cls.macsize :]
        return _des_cbc_encrypt_iv(key, basic_plaintext, iv=key.contents)

    @classmethod
    def decrypt(cls, key: Key, _keyusage: int, ciphertext: bytes) -> bytes:
        """Decrypt DES-CBC (IV=key) and verify the CRC-32 integrity check."""
        if len(ciphertext) < cls.blocksize + cls.macsize:
            msg = "ciphertext too short"
            raise ValueError(msg)
        plaintext = _des_cbc_decrypt_iv(key, ciphertext, iv=key.contents)
        confounder = plaintext[: cls.padsize]
        mac = plaintext[cls.padsize : cls.padsize + cls.macsize]
        message = plaintext[cls.padsize + cls.macsize :]
        expected = _krb5_crc32(confounder + b"\x00" * cls.macsize + message)
        if mac != expected:
            msg = "ciphertext integrity failure"
            raise ValueError(msg)
        return bytes(message)

    @classmethod
    def string_to_key(cls, string: str | bytes, salt: str | bytes, params: bytes | None) -> Key:
        """Derive a DES key — delegates to DES-CBC-MD5 (same string-to-key)."""
        des_md5: Any = ENCTYPE_TABLE[3]  # impacket _DESCBC, untyped
        return des_md5.string_to_key(string, salt, params)


def _kdf_hmac_sha2(key: bytes, label: bytes, k: int, hash_name: str) -> bytes:
    """RFC 8009 KDF-HMAC-SHA2: single-iteration SP 800-108 Counter Mode."""
    kdf_input = struct.pack(">I", 1) + label + b"\x00" + struct.pack(">I", k)
    return hmac.new(key, kdf_input, hash_name).digest()[: k // 8]


class Aes128Sha256:
    """AES128-CTS-HMAC-SHA256-128 (etype 19) per RFC 8009."""

    enctype = 19
    keysize = 16
    blocksize = 16
    macsize = 16

    @classmethod
    def _derive_keys(cls, key: Key, keyusage: int) -> tuple[Key, bytes]:
        """Derive Ke (encryption) and Ki (integrity) from base key + usage."""
        label_e = struct.pack(">IB", keyusage, 0xAA)
        label_i = struct.pack(">IB", keyusage, 0x55)
        ke_raw = _kdf_hmac_sha2(key.contents, label_e, 128, "sha256")
        ki_raw = _kdf_hmac_sha2(key.contents, label_i, 128, "sha256")
        return Key(17, ke_raw), ki_raw

    @classmethod
    def encrypt(cls, key: Key, keyusage: int, plaintext: bytes, confounder: bytes | None) -> bytes:
        """Encrypt per RFC 8009 section 5: AES-CTS + HMAC-SHA256-128."""
        ke, ki = cls._derive_keys(key, keyusage)
        if confounder is None:
            confounder = bytes(get_random_bytes(cls.blocksize))
        basic_plaintext = confounder + plaintext
        aes_sha1: Any = _enctype_table[17]
        ciphertext: bytes = bytes(aes_sha1.basic_encrypt(ke, basic_plaintext))
        mac = hmac.new(ki, b"\x00" * cls.blocksize + ciphertext, "sha256").digest()[: cls.macsize]
        return ciphertext + mac

    @classmethod
    def decrypt(cls, key: Key, keyusage: int, ciphertext: bytes) -> bytes:
        """Decrypt per RFC 8009 section 5: verify HMAC-SHA256-128 then AES-CTS."""
        ke, ki = cls._derive_keys(key, keyusage)
        ciphertext = bytes(ciphertext)
        if len(ciphertext) < cls.blocksize + cls.macsize:
            msg = "ciphertext too short"
            raise ValueError(msg)
        basic_ctext = ciphertext[: -cls.macsize]
        mac = ciphertext[-cls.macsize :]
        expected = hmac.new(ki, b"\x00" * cls.blocksize + basic_ctext, "sha256").digest()[: cls.macsize]
        if not hmac.compare_digest(mac, expected):
            msg = "ciphertext integrity failure"
            raise ValueError(msg)
        aes_sha1: Any = _enctype_table[17]
        return bytes(aes_sha1.basic_decrypt(ke, basic_ctext))[cls.blocksize :]


class Aes256Sha384:
    """AES256-CTS-HMAC-SHA384-192 (etype 20) per RFC 8009."""

    enctype = 20
    keysize = 32
    blocksize = 16
    macsize = 24

    @classmethod
    def _derive_keys(cls, key: Key, keyusage: int) -> tuple[Key, bytes]:
        """Derive Ke (encryption) and Ki (integrity) from base key + usage."""
        label_e = struct.pack(">IB", keyusage, 0xAA)
        label_i = struct.pack(">IB", keyusage, 0x55)
        ke_raw = _kdf_hmac_sha2(key.contents, label_e, 256, "sha384")
        ki_raw = _kdf_hmac_sha2(key.contents, label_i, 192, "sha384")
        return Key(18, ke_raw), ki_raw

    @classmethod
    def encrypt(cls, key: Key, keyusage: int, plaintext: bytes, confounder: bytes | None) -> bytes:
        """Encrypt per RFC 8009 section 5: AES-CTS + HMAC-SHA384-192."""
        ke, ki = cls._derive_keys(key, keyusage)
        if confounder is None:
            confounder = bytes(get_random_bytes(cls.blocksize))
        basic_plaintext = confounder + plaintext
        aes_sha1: Any = _enctype_table[18]
        ciphertext: bytes = bytes(aes_sha1.basic_encrypt(ke, basic_plaintext))
        mac = hmac.new(ki, b"\x00" * cls.blocksize + ciphertext, "sha384").digest()[: cls.macsize]
        return ciphertext + mac

    @classmethod
    def decrypt(cls, key: Key, keyusage: int, ciphertext: bytes) -> bytes:
        """Decrypt per RFC 8009 section 5: verify HMAC-SHA384-192 then AES-CTS."""
        ke, ki = cls._derive_keys(key, keyusage)
        ciphertext = bytes(ciphertext)
        if len(ciphertext) < cls.blocksize + cls.macsize:
            msg = "ciphertext too short"
            raise ValueError(msg)
        basic_ctext = ciphertext[: -cls.macsize]
        mac = ciphertext[-cls.macsize :]
        expected = hmac.new(ki, b"\x00" * cls.blocksize + basic_ctext, "sha384").digest()[: cls.macsize]
        if not hmac.compare_digest(mac, expected):
            msg = "ciphertext integrity failure"
            raise ValueError(msg)
        aes_sha1: Any = _enctype_table[18]
        return bytes(aes_sha1.basic_decrypt(ke, basic_ctext))[cls.blocksize :]


def _zeropad(data: bytes, padsize: int) -> bytes:
    remainder = len(data) % padsize
    if remainder:
        return data + b"\x00" * (padsize - remainder)
    return data


def _des_cbc_encrypt(key: Key, plaintext: bytes) -> bytes:
    des = DES.new(key.contents, DES.MODE_CBC, b"\x00" * 8)
    return des.encrypt(bytes(plaintext))


def _des_cbc_decrypt(key: Key, ciphertext: bytes) -> bytes:
    des = DES.new(key.contents, DES.MODE_CBC, b"\x00" * 8)
    return des.decrypt(bytes(ciphertext))


def _des_cbc_encrypt_iv(key: Key, plaintext: bytes, *, iv: bytes) -> bytes:
    des = DES.new(key.contents, DES.MODE_CBC, iv)
    return des.encrypt(bytes(plaintext))


def _des_cbc_decrypt_iv(key: Key, ciphertext: bytes, *, iv: bytes) -> bytes:
    des = DES.new(key.contents, DES.MODE_CBC, iv)
    return des.decrypt(bytes(ciphertext))


# Etype int → cipher class lookup — mutate impacket's table in-place so that
# impacket's own Key() validation accepts the new etypes.
ENCTYPE_TABLE = _enctype_table

ENCTYPE_TABLE[1] = DesCbcCrc

ENCTYPE_TABLE[19] = Aes128Sha256
ENCTYPE_TABLE[20] = Aes256Sha384

# Maps our EncryptionType to the impacket etype ints used in _enctype_table.
# DES-CBC-CRC (1) is not in impacket's table; we use DES-CBC-MD5 (3) cipher.
_IMPACKET_ETYPE: dict[EncryptionType, int] = {
    EncryptionType.DES_CBC_CRC: 1,
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
    """Derive a single Kerberos key from *password* and *salt*."""
    raw = derive_key_raw(etype, password, salt)
    impacket_etype = _IMPACKET_ETYPE[etype]
    return Key(impacket_etype, raw)


_SHA2_ETYPES = {EncryptionType.AES128_CTS_HMAC_SHA256_128, EncryptionType.AES256_CTS_HMAC_SHA384_192}


def derive_all_keys(password: str, salt: str) -> dict[EncryptionType, Key]:
    """Derive Kerberos keys for all Windows encryption types."""
    return {etype: derive_key(etype, password, salt) for etype in EncryptionType if etype in _IMPACKET_ETYPE}


def key_from_hex(etype: EncryptionType, hex_key: str) -> Key:
    """Build a ``Key`` from a hex-encoded key string."""
    impacket_etype = _IMPACKET_ETYPE[etype]
    return Key(impacket_etype, bytes.fromhex(hex_key))
