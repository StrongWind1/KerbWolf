# SPDX-License-Identifier: Apache-2.0
"""Additional hashcat tests - checksum splits, DES formats, mode lookups."""

from kerbwolf.hashcat import format_asrep_hash_raw, format_tgs_hash_raw

# ---------------------------------------------------------------------------
# Hashcat checksum/edata2 split accuracy
# ---------------------------------------------------------------------------


class TestHashcatChecksumSplit:
    """Verify the checksum/edata2 split positions are correct."""

    def test_rc4_checksum_first_16_bytes(self):
        checksum = b"\x11" * 16
        edata2 = b"\x22" * 48
        cipher = checksum + edata2
        h = format_tgs_hash_raw(cipher, 23, "u", "R")
        # checksum hex should be 1111...1111 (32 chars)
        assert "$" + "11" * 16 + "$" in h
        assert "22" * 48 in h

    def test_aes_checksum_last_12_bytes(self):
        edata2 = b"\x33" * 50
        checksum = b"\x44" * 12
        cipher = edata2 + checksum
        h = format_tgs_hash_raw(cipher, 18, "u", "R")
        # checksum hex should be 4444...4444 (24 chars)
        assert "$" + "44" * 12 + "$" in h
        assert "33" * 50 in h

    def test_asrep_rc4_checksum_split(self):
        checksum = b"\x55" * 16
        edata2 = b"\x66" * 32
        cipher = checksum + edata2
        h = format_asrep_hash_raw(cipher, 23, "u", "R")
        parts = h.split("$")
        assert parts[-2] == "55" * 16
        assert parts[-1] == "66" * 32

    def test_asrep_aes_checksum_last(self):
        edata2 = b"\x77" * 40
        checksum = b"\x88" * 12
        cipher = edata2 + checksum
        h = format_asrep_hash_raw(cipher, 18, "u", "R")
        # $krb5asrep$18$user$realm$checksum$edata2
        parts = h.split("$")
        # checksum is second to last part, 24 hex chars
        assert any(len(p) == 24 and all(c in "0123456789abcdef" for c in p) for p in parts)


# ---------------------------------------------------------------------------
# DES AS-REP canonical split format (mode 38600)
# ---------------------------------------------------------------------------


class TestDesAsrepCanonicalFormat:
    """Verify DES AS-REP emits the canonical split format matching hashcat's ST_HASH."""

    CIPHER = b"\xaa" * 64

    def test_des_md5_uses_split_format(self):
        h = format_asrep_hash_raw(self.CIPHER, 3, "user", "REALM")
        assert h.startswith("$krb5asrep$3$user$REALM$")
        assert "@" not in h
        assert ":" not in h.split("$", 4)[-1]

    def test_des_crc_uses_split_format(self):
        h = format_asrep_hash_raw(self.CIPHER, 1, "user", "REALM")
        assert h.startswith("$krb5asrep$1$user$REALM$")
        assert "@" not in h

    def test_des_md5_full_structure(self):
        h = format_asrep_hash_raw(self.CIPHER, 3, "svc", "EVIL.CORP")
        parts = h.split("$")
        assert parts[1] == "krb5asrep"
        assert parts[2] == "3"
        assert parts[3] == "svc"
        assert parts[4] == "EVIL.CORP"
        assert len(parts[5]) == 32
        assert len(parts[6]) == 96
        assert parts[5] + parts[6] == "aa" * 64


# ---------------------------------------------------------------------------
# Negative sentinel mode numbers
# ---------------------------------------------------------------------------


class TestNewModeMappings:
    """Verify all etype → mode mappings return valid positive mode numbers."""

    def test_tgs_des_cbc_crc(self):
        from kerbwolf.hashcat import tgs_hashcat_mode

        assert tgs_hashcat_mode(1) == 39100

    def test_asrep_des_cbc_crc(self):
        from kerbwolf.hashcat import asrep_hashcat_mode

        assert asrep_hashcat_mode(1) == 39200

    def test_pa_des_cbc_crc(self):
        from kerbwolf.hashcat import pa_hashcat_mode

        assert pa_hashcat_mode(1) == 39300

    def test_pa_des_cbc_md5(self):
        from kerbwolf.hashcat import pa_hashcat_mode

        assert pa_hashcat_mode(3) == 39000

    def test_tgs_sha2(self):
        from kerbwolf.hashcat import tgs_hashcat_mode

        assert tgs_hashcat_mode(19) == 0
        assert tgs_hashcat_mode(20) == 0

    def test_asrep_sha2(self):
        from kerbwolf.hashcat import asrep_hashcat_mode

        assert asrep_hashcat_mode(19) == 0
        assert asrep_hashcat_mode(20) == 0

    def test_pa_sha2(self):
        from kerbwolf.hashcat import pa_hashcat_mode

        assert pa_hashcat_mode(19) == 0
        assert pa_hashcat_mode(20) == 0

    def test_all_modes_are_positive(self):
        from kerbwolf.models import HashcatMode

        for m in HashcatMode:
            assert m.value > 0, f"{m.name} has non-positive mode {m.value}"
