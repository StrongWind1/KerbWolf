"""Tests for kerbwolf.hashcat - hash formatters for all 15 attack x etype combinations."""

from kerbwolf.hashcat import (
    asrep_hashcat_mode,
    format_asrep_hash_raw,
    format_pa_hash,
    format_tgs_hash_raw,
    pa_hashcat_mode,
    tgs_hashcat_mode,
)
from kerbwolf.models import HashcatMode, HashFormat

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
        h = format_tgs_hash_raw(self.CIPHER, 23, "svc", "DOMAIN.LOCAL", "http/web", fmt=HashFormat.HASHCAT)
        assert h.startswith("$krb5tgs$23$")

    def test_hashcat_contains_user_realm_spn(self):
        h = format_tgs_hash_raw(self.CIPHER, 23, "svc", "DOMAIN.LOCAL", "http/web")
        assert "svc" in h
        assert "DOMAIN.LOCAL" in h
        assert "http/web" in h

    def test_hashcat_checksum_is_first_32_hex(self):
        h = format_tgs_hash_raw(self.CIPHER, 23, "u", "R", "s")
        parts = h.split("$")
        # checksum should be 32 hex chars (16 bytes)
        checksum_part = parts[-2]
        assert len(checksum_part) == 32

    def test_spn_colon_escaped(self):
        h = format_tgs_hash_raw(self.CIPHER, 23, "u", "R", "svc:1433")
        assert "svc~1433" in h


# ---------------------------------------------------------------------------
# TGS hash formatting - AES
# ---------------------------------------------------------------------------


class TestFormatTgsAES:
    CIPHER = b"\xcc" * 50 + b"\xdd" * 12  # data + 12-byte checksum at end

    def test_aes128_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 17, "u", "R", "s")
        assert h.startswith("$krb5tgs$17$")

    def test_aes256_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 18, "u", "R", "s")
        assert h.startswith("$krb5tgs$18$")

    def test_aes_checksum_is_last_24_hex(self):
        h = format_tgs_hash_raw(self.CIPHER, 17, "u", "R", "s")
        parts = h.split("$")
        # After *spn* comes checksum then edata2
        checksum_part = parts[-2]
        assert len(checksum_part) == 24  # 12 bytes = 24 hex


# ---------------------------------------------------------------------------
# TGS hash formatting - DES
# ---------------------------------------------------------------------------


class TestFormatTgsDES:
    CIPHER = b"\xee" * 64

    def test_des_md5_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 3, "u", "R", "s")
        assert h.startswith("$krb5tgs$3$")

    def test_des_crc_prefix(self):
        h = format_tgs_hash_raw(self.CIPHER, 1, "u", "R", "s")
        assert h.startswith("$krb5tgs$1$")

    def test_des_full_cipher_no_split(self):
        h = format_tgs_hash_raw(self.CIPHER, 3, "u", "R", "s")
        # DES has the full cipher as one blob (128 hex chars for 64 bytes)
        assert "ee" * 64 in h


# ---------------------------------------------------------------------------
# AS-REP hash formatting
# ---------------------------------------------------------------------------


class TestFormatAsrepHash:
    def test_rc4_prefix(self):
        cipher = b"\x11" * 48
        h = format_asrep_hash_raw(cipher, 23, "user", "REALM")
        assert h.startswith("$krb5asrep$23$")
        assert "user@REALM" in h

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

    def test_contains_username_and_realm(self):
        cipher = b"\xaa" * 52
        h = format_pa_hash(cipher, 23, "admin", "CORP.LOCAL")
        assert "admin" in h
        assert "CORP.LOCAL" in h


# ---------------------------------------------------------------------------
# John format
# ---------------------------------------------------------------------------


class TestJohnFormat:
    def test_tgs_rc4_john(self):
        cipher = b"\xaa" * 16 + b"\xbb" * 32
        h = format_tgs_hash_raw(cipher, 23, "u", "R", "http/web", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5tgs$23$*u$R$http/web*$")

    def test_asrep_rc4_john(self):
        cipher = b"\xcc" * 48
        h = format_asrep_hash_raw(cipher, 23, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5asrep$23$")

    def test_tgs_aes_john(self):
        cipher = b"\xdd" * 62
        h = format_tgs_hash_raw(cipher, 18, "u", "R", "s", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5tgs$18$u$R$")

    def test_asrep_aes_john(self):
        cipher = b"\xee" * 62
        h = format_asrep_hash_raw(cipher, 17, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5asrep$17$REALMuser$")

    def test_pa_rc4_john(self):
        cipher = b"\xff" * 52
        h = format_pa_hash(cipher, 23, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5pa$23$user$REALM$$")

    def test_pa_aes_john(self):
        cipher = b"\xaa" * 56
        h = format_pa_hash(cipher, 18, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5pa$18$user$REALM$$")

    def test_des_john(self):
        cipher = b"\xbb" * 40
        h = format_tgs_hash_raw(cipher, 3, "user", "REALM", "spn", fmt=HashFormat.JOHN)
        assert h.startswith("$krb3$REALMuser$")
