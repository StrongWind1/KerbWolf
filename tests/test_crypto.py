"""Tests for kerbwolf.core.crypto - key derivation for all 5 etypes."""

import pytest

from kerbwolf.core.crypto import (
    ENCTYPE_TABLE,
    compute_salt,
    derive_all_keys,
    derive_key,
    key_from_hex,
)
from kerbwolf.models import EncryptionType

# ---------------------------------------------------------------------------
# compute_salt
# ---------------------------------------------------------------------------


class TestComputeSalt:
    def test_user_account(self):
        assert compute_salt("admin", "domain.local") == "DOMAIN.LOCALadmin"

    def test_machine_account(self):
        assert compute_salt("DC01$", "domain.local") == "DOMAIN.LOCALhostdc01.domain.local"

    def test_mixed_case_domain(self):
        salt = compute_salt("user", "Mixed.Domain.Com")
        assert salt == "MIXED.DOMAIN.COMuser"

    def test_machine_mixed_case(self):
        salt = compute_salt("SRV01$", "Corp.Local")
        assert salt.startswith("CORP.LOCALhost")
        assert "srv01" in salt
        assert "corp.local" in salt

    def test_empty_username(self):
        assert compute_salt("", "domain.local") == "DOMAIN.LOCAL"

    def test_dollar_only_username(self):
        salt = compute_salt("$", "d.com")
        assert salt == "D.COMhost.d.com"

    def test_single_part_domain(self):
        assert compute_salt("u", "LOCAL") == "LOCALu"


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_rc4_key_length(self):
        key = derive_key(EncryptionType.RC4_HMAC, "password", "")
        assert key.enctype == 23
        assert len(key.contents) == 16

    def test_aes256_key_length(self):
        key = derive_key(EncryptionType.AES256_CTS_HMAC_SHA1_96, "password", "DOMAIN.LOCALuser")
        assert key.enctype == 18
        assert len(key.contents) == 32

    def test_aes128_key_length(self):
        key = derive_key(EncryptionType.AES128_CTS_HMAC_SHA1_96, "password", "DOMAIN.LOCALuser")
        assert key.enctype == 17
        assert len(key.contents) == 16

    def test_des_cbc_md5_key_length(self):
        key = derive_key(EncryptionType.DES_CBC_MD5, "password", "DOMAIN.LOCALuser")
        assert key.enctype == 3
        assert len(key.contents) == 8

    def test_des_cbc_crc_key_length(self):
        key = derive_key(EncryptionType.DES_CBC_CRC, "password", "DOMAIN.LOCALuser")
        assert key.enctype == 3  # maps to DES-CBC-MD5 cipher
        assert len(key.contents) == 8

    def test_rc4_ignores_salt(self):
        k1 = derive_key(EncryptionType.RC4_HMAC, "password", "")
        k2 = derive_key(EncryptionType.RC4_HMAC, "password", "DIFFERENT.SALT")
        assert k1.contents == k2.contents

    def test_aes_depends_on_salt(self):
        k1 = derive_key(EncryptionType.AES256_CTS_HMAC_SHA1_96, "password", "SALT1")
        k2 = derive_key(EncryptionType.AES256_CTS_HMAC_SHA1_96, "password", "SALT2")
        assert k1.contents != k2.contents

    def test_des_depends_on_salt(self):
        k1 = derive_key(EncryptionType.DES_CBC_MD5, "password", "SALT1")
        k2 = derive_key(EncryptionType.DES_CBC_MD5, "password", "SALT2")
        assert k1.contents != k2.contents

    def test_different_passwords_different_keys(self):
        k1 = derive_key(EncryptionType.RC4_HMAC, "password1", "")
        k2 = derive_key(EncryptionType.RC4_HMAC, "password2", "")
        assert k1.contents != k2.contents


# ---------------------------------------------------------------------------
# derive_all_keys
# ---------------------------------------------------------------------------


class TestDeriveAllKeys:
    def test_returns_all_five(self):
        keys = derive_all_keys("password", "DOMAIN.LOCALuser")
        assert len(keys) == 5

    def test_all_etypes_present(self):
        keys = derive_all_keys("password", "DOMAIN.LOCALuser")
        for etype in EncryptionType:
            assert etype in keys

    def test_key_sizes_correct(self):
        keys = derive_all_keys("password", "DOMAIN.LOCALuser")
        assert len(keys[EncryptionType.DES_CBC_CRC].contents) == 8
        assert len(keys[EncryptionType.DES_CBC_MD5].contents) == 8
        assert len(keys[EncryptionType.AES128_CTS_HMAC_SHA1_96].contents) == 16
        assert len(keys[EncryptionType.AES256_CTS_HMAC_SHA1_96].contents) == 32
        assert len(keys[EncryptionType.RC4_HMAC].contents) == 16


# ---------------------------------------------------------------------------
# key_from_hex
# ---------------------------------------------------------------------------


class TestKeyFromHex:
    def test_rc4(self):
        key = key_from_hex(EncryptionType.RC4_HMAC, "aa" * 16)
        assert key.enctype == 23
        assert len(key.contents) == 16

    def test_des(self):
        key = key_from_hex(EncryptionType.DES_CBC_MD5, "bb" * 8)
        assert key.enctype == 3
        assert len(key.contents) == 8

    def test_aes256(self):
        key = key_from_hex(EncryptionType.AES256_CTS_HMAC_SHA1_96, "cc" * 32)
        assert key.enctype == 18
        assert len(key.contents) == 32

    def test_aes128(self):
        key = key_from_hex(EncryptionType.AES128_CTS_HMAC_SHA1_96, "dd" * 16)
        assert key.enctype == 17
        assert len(key.contents) == 16

    def test_invalid_hex_raises(self):
        with pytest.raises(ValueError, match="non-hexadecimal"):
            key_from_hex(EncryptionType.RC4_HMAC, "zzzz")


# ---------------------------------------------------------------------------
# ENCTYPE_TABLE
# ---------------------------------------------------------------------------


class TestEnctypeTable:
    def test_des_md5_present(self):
        assert 3 in ENCTYPE_TABLE

    def test_aes128_present(self):
        assert 17 in ENCTYPE_TABLE

    def test_aes256_present(self):
        assert 18 in ENCTYPE_TABLE

    def test_rc4_present(self):
        assert 23 in ENCTYPE_TABLE
