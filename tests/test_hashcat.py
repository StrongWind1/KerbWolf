# SPDX-License-Identifier: Apache-2.0
"""Tests for kerbwolf.hashcat - hash formatters for all 15 attack x etype combinations."""

from kerbwolf.hashcat import (
    asrep_hashcat_mode,
    format_asrep_hash_raw,
    format_pa_hash,
    format_tgs_hash_raw,
    pa_hashcat_mode,
    tgs_hashcat_mode,
)
from kerbwolf.models import HashcatMode

# ---------------------------------------------------------------------------
# TGS-REP Roast mode lookups
# ---------------------------------------------------------------------------


class TestTgsHashcatMode:
    def test_des_cbc_crc(self):
        assert tgs_hashcat_mode(1) == HashcatMode.KRB5_TGS_DES_CBC_CRC

    def test_des_cbc_md5(self):
        assert tgs_hashcat_mode(3) == HashcatMode.KRB5_TGS_DES_CBC_MD5

    def test_aes128(self):
        assert tgs_hashcat_mode(17) == HashcatMode.KRB5_TGS_AES128

    def test_aes256(self):
        assert tgs_hashcat_mode(18) == HashcatMode.KRB5_TGS_AES256

    def test_rc4(self):
        assert tgs_hashcat_mode(23) == HashcatMode.KRB5_TGS_RC4

    def test_unknown_returns_zero(self):
        assert tgs_hashcat_mode(999) == 0


# ---------------------------------------------------------------------------
# AS-REP Roast mode lookups
# ---------------------------------------------------------------------------


class TestAsrepHashcatMode:
    def test_des_cbc_crc(self):
        assert asrep_hashcat_mode(1) == HashcatMode.KRB5_ASREP_DES_CBC_CRC

    def test_des_cbc_md5(self):
        assert asrep_hashcat_mode(3) == HashcatMode.KRB5_ASREP_DES_CBC_MD5

    def test_aes128(self):
        assert asrep_hashcat_mode(17) == HashcatMode.KRB5_ASREP_AES128

    def test_aes256(self):
        assert asrep_hashcat_mode(18) == HashcatMode.KRB5_ASREP_AES256

    def test_rc4(self):
        assert asrep_hashcat_mode(23) == HashcatMode.KRB5_ASREP_RC4

    def test_unknown_returns_zero(self):
        assert asrep_hashcat_mode(0) == 0


# ---------------------------------------------------------------------------
# AS-REQ Roast (Pre-Auth) mode lookups
# ---------------------------------------------------------------------------


class TestPaHashcatMode:
    def test_des_cbc_crc(self):
        assert pa_hashcat_mode(1) == HashcatMode.KRB5_PA_DES_CBC_CRC

    def test_des_cbc_md5(self):
        assert pa_hashcat_mode(3) == HashcatMode.KRB5_PA_DES_CBC_MD5

    def test_aes128(self):
        assert pa_hashcat_mode(17) == HashcatMode.KRB5_PA_AES128

    def test_aes256(self):
        assert pa_hashcat_mode(18) == HashcatMode.KRB5_PA_AES256

    def test_rc4(self):
        assert pa_hashcat_mode(23) == HashcatMode.KRB5_PA_RC4

    def test_unknown_returns_zero(self):
        assert pa_hashcat_mode(42) == 0


# ---------------------------------------------------------------------------
# TGS hash formatting - RC4
# ---------------------------------------------------------------------------


class TestFormatTgsRC4:
    CIPHER = b"\xaa" * 16 + b"\xbb" * 32  # 16-byte checksum + 32-byte edata2

    def test_hashcat_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 23, "svc", "DOMAIN.LOCAL")
        assert h.startswith("$krb5tgs$23$")

    def test_hashcat_contains_user_realm(self):
        h = format_tgs_hash_raw(self.CIPHER, 23, "svc", "DOMAIN.LOCAL")
        assert "$svc$" in h
        assert "$DOMAIN.LOCAL$" in h

    def test_hashcat_checksum_is_first_32_hex(self):
        h = format_tgs_hash_raw(self.CIPHER, 23, "u", "R")
        parts = h.split("$")
        # checksum should be 32 hex chars (16 bytes)
        checksum_part = parts[-2]
        assert len(checksum_part) == 32


# ---------------------------------------------------------------------------
# TGS hash formatting - AES
# ---------------------------------------------------------------------------


class TestFormatTgsAES:
    CIPHER = b"\xcc" * 50 + b"\xdd" * 12  # data + 12-byte checksum at end

    def test_aes128_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 17, "u", "R")
        assert h.startswith("$krb5tgs$17$")

    def test_aes256_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 18, "u", "R")
        assert h.startswith("$krb5tgs$18$")

    def test_aes_checksum_is_last_24_hex(self):
        h = format_tgs_hash_raw(self.CIPHER, 17, "u", "R")
        parts = h.split("$")
        checksum_part = parts[-2]
        assert len(checksum_part) == 24  # 12 bytes = 24 hex


# ---------------------------------------------------------------------------
# TGS hash formatting - DES
# ---------------------------------------------------------------------------


class TestFormatTgsDES:
    CIPHER = b"\xee" * 64

    def test_des_md5_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 3, "u", "R")
        assert h.startswith("$krb5tgs$3$")

    def test_des_crc_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 1, "u", "R")
        assert h.startswith("$krb5tgs$1$")

    def test_des_checksum_edata2_split(self):
        h = format_tgs_hash_raw(self.CIPHER, 3, "u", "R")
        parts = h.split("$")
        checksum = parts[-2]
        edata2 = parts[-1]
        assert len(checksum) == 32
        assert len(edata2) == 96
        assert checksum + edata2 == "ee" * 64


# ---------------------------------------------------------------------------
# AS-REP hash formatting
# ---------------------------------------------------------------------------


class TestFormatAsrepHash:
    def test_rc4_prefix(self):
        cipher = b"\x11" * 48
        h = format_asrep_hash_raw(cipher, 23, "user", "REALM")
        assert h.startswith("$krb5asrep$23$user$REALM$")

    def test_aes256_prefix(self):
        cipher = b"\x22" * 60
        h = format_asrep_hash_raw(cipher, 18, "user", "REALM")
        assert h.startswith("$krb5asrep$18$")

    def test_des_prefix(self):
        cipher = b"\x33" * 40
        h = format_asrep_hash_raw(cipher, 3, "user", "REALM")
        assert h.startswith("$krb5asrep$3$")

    def test_des_crc_prefix(self):
        cipher = b"\x44" * 40
        h = format_asrep_hash_raw(cipher, 1, "user", "REALM")
        assert h.startswith("$krb5asrep$1$")


# ---------------------------------------------------------------------------
# PA hash formatting (AS-REQ Roast)
# ---------------------------------------------------------------------------


class TestFormatPaHash:
    def test_rc4_prefix(self):
        cipher = b"\x55" * 52
        h = format_pa_hash(cipher, 23, "user", "REALM")
        assert h.startswith("$krb5pa$23$")

    def test_aes128_prefix(self):
        cipher = b"\x66" * 56
        h = format_pa_hash(cipher, 17, "user", "REALM")
        assert h.startswith("$krb5pa$17$")

    def test_aes256_prefix(self):
        cipher = b"\x77" * 56
        h = format_pa_hash(cipher, 18, "user", "REALM")
        assert h.startswith("$krb5pa$18$")

    def test_des_md5_prefix(self):
        cipher = b"\x88" * 40
        h = format_pa_hash(cipher, 3, "user", "REALM")
        assert h.startswith("$krb5pa$3$")

    def test_des_crc_prefix(self):
        cipher = b"\x99" * 40
        h = format_pa_hash(cipher, 1, "user", "REALM")
        assert h.startswith("$krb5pa$1$")

    def test_des_line_is_split_like_every_other_etype(self):
        """DES pre-auth uses the shared layout: the first two cipher blocks, then the rest."""
        for etype, size in ((3, 56), (1, 40)):
            cipher = bytes(range(size))
            parts = format_pa_hash(cipher, etype, "user", "REALM").split("$")
            assert parts == ["", "krb5pa", str(etype), "user", "REALM", cipher[:16].hex(), cipher[16:].hex()]

    def test_contains_username_and_realm(self):
        cipher = b"\xaa" * 52
        h = format_pa_hash(cipher, 23, "admin", "CORP.LOCAL")
        assert "admin" in h
        assert "CORP.LOCAL" in h
