# SPDX-License-Identifier: Apache-2.0
"""Tests verifying KerbWolf hash output matches hashcat's canonical format 1 exactly.

Each test constructs a known cipher and checks:
1. Exact field structure (correct delimiters, field order)
2. Correct checksum/edata2 split position
3. Correct hex encoding
4. Field lengths match what hashcat's tokenizer expects

Based on the module_*.c parsers in hashcat.
"""

import re

from kerbwolf.hashcat import format_asrep_hash_raw, format_pa_hash, format_tgs_hash_raw

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# RC4: checksum = first 16 bytes, edata2 = rest
RC4_CHECKSUM = b"\xaa" * 16  # 16 bytes → 32 hex
RC4_EDATA2 = b"\xbb" * 40  # 40 bytes → 80 hex (minimum 32 bytes for hashcat)
RC4_CIPHER = RC4_CHECKSUM + RC4_EDATA2  # 56 bytes total

# AES: edata2 = all but last 12, checksum = last 12 bytes
AES_EDATA2 = b"\xcc" * 40  # 40 bytes → 80 hex
AES_CHECKSUM = b"\xdd" * 12  # 12 bytes → 24 hex
AES_CIPHER = AES_EDATA2 + AES_CHECKSUM  # 52 bytes total

# RC4 PA: checksum = first 16 bytes, enc_timestamp = remaining 36 bytes
PA_RC4_CHECKSUM = b"\x11" * 16  # 16 bytes → 32 hex
PA_RC4_TIMESTAMP = b"\x22" * 36  # 36 bytes → 72 hex
PA_RC4_CIPHER = PA_RC4_CHECKSUM + PA_RC4_TIMESTAMP  # 52 bytes

# AES PA: enc_timestamp = all but last 12, checksum = last 12
PA_AES_TIMESTAMP = b"\x33" * 44  # 44 bytes → 88 hex
PA_AES_CHECKSUM = b"\x44" * 12  # 12 bytes → 24 hex
PA_AES_CIPHER = PA_AES_TIMESTAMP + PA_AES_CHECKSUM  # 56 bytes → 112 hex total


# ---------------------------------------------------------------------------
# Mode 13100: RC4 TGS-REP
# Canonical: $krb5tgs$23$user$realm$checksum$edata2
# ---------------------------------------------------------------------------


class TestMode13100Format:
    def test_structure(self):
        h = format_tgs_hash_raw(RC4_CIPHER, 23, "svc_sql", "EVIL.CORP", "MSSQLSvc/db01.evil.corp")
        assert h.startswith("$krb5tgs$23$svc_sql$EVIL.CORP$")

    def test_full_format_regex(self):
        h = format_tgs_hash_raw(RC4_CIPHER, 23, "svc", "REALM", "http/web")
        pattern = r"^\$krb5tgs\$23\$svc\$REALM\$[a-f0-9]{32}\$[a-f0-9]+$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_checksum_is_first_16_bytes(self):
        h = format_tgs_hash_raw(RC4_CIPHER, 23, "u", "R", "s")
        parts = h.split("$")
        checksum = parts[-2]
        assert checksum == "aa" * 16

    def test_edata2_is_remaining_bytes(self):
        h = format_tgs_hash_raw(RC4_CIPHER, 23, "u", "R", "s")
        edata2 = h.split("$")[-1]
        assert edata2 == "bb" * 40

    def test_edata2_minimum_64_hex(self):
        h = format_tgs_hash_raw(RC4_CIPHER, 23, "u", "R", "s")
        edata2 = h.split("$")[-1]
        assert len(edata2) >= 64

    def test_spn_not_in_canonical_hash(self):
        h = format_tgs_hash_raw(RC4_CIPHER, 23, "u", "R", "MSSQLSvc/db01:1433")
        assert "*" not in h
        assert "MSSQLSvc" not in h


# ---------------------------------------------------------------------------
# Mode 19600: AES128 TGS-REP
# Canonical: $krb5tgs$17$user$realm$checksum$edata2
# ---------------------------------------------------------------------------


class TestMode19600Format:
    def test_structure(self):
        h = format_tgs_hash_raw(AES_CIPHER, 17, "svc", "EVIL.CORP", "http/web")
        assert h.startswith("$krb5tgs$17$svc$EVIL.CORP$")

    def test_full_format_regex(self):
        h = format_tgs_hash_raw(AES_CIPHER, 17, "svc", "REALM", "http/web")
        pattern = r"^\$krb5tgs\$17\$svc\$REALM\$[a-f0-9]{24}\$[a-f0-9]+$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_checksum_is_last_12_bytes(self):
        h = format_tgs_hash_raw(AES_CIPHER, 17, "u", "R", "s")
        parts = h.split("$")
        checksum = parts[-2]  # second to last (before edata2)
        assert checksum == "dd" * 12
        assert len(checksum) == 24

    def test_edata2_is_all_but_last_12(self):
        h = format_tgs_hash_raw(AES_CIPHER, 17, "u", "R", "s")
        edata2 = h.split("$")[-1]
        assert edata2 == "cc" * 40

    def test_user_required_nonempty(self):
        """Hashcat requires user field >= 1 char for AES."""
        h = format_tgs_hash_raw(AES_CIPHER, 17, "a", "R", "s")
        parts = h.split("$")
        assert parts[3] == "a"


# ---------------------------------------------------------------------------
# Mode 19700: AES256 TGS-REP
# Same as 19600 but etype 18
# ---------------------------------------------------------------------------


class TestMode19700Format:
    def test_signature(self):
        h = format_tgs_hash_raw(AES_CIPHER, 18, "svc", "REALM", "http/web")
        assert h.startswith("$krb5tgs$18$")

    def test_same_structure_as_19600(self):
        h17 = format_tgs_hash_raw(AES_CIPHER, 17, "u", "R", "s")
        h18 = format_tgs_hash_raw(AES_CIPHER, 18, "u", "R", "s")
        assert h17.replace("$17$", "$18$") == h18


# ---------------------------------------------------------------------------
# Mode 18200: RC4 AS-REP
# Canonical: $krb5asrep$23$user$realm$checksum$edata2
# ---------------------------------------------------------------------------


class TestMode18200Format:
    def test_structure(self):
        h = format_asrep_hash_raw(RC4_CIPHER, 23, "jsmith", "EVIL.CORP")
        assert h.startswith("$krb5asrep$23$jsmith$EVIL.CORP$")

    def test_full_format_regex(self):
        h = format_asrep_hash_raw(RC4_CIPHER, 23, "user", "REALM")
        pattern = r"^\$krb5asrep\$23\$user\$REALM\$[a-f0-9]{32}\$[a-f0-9]+$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_dollar_separator(self):
        h = format_asrep_hash_raw(RC4_CIPHER, 23, "user", "REALM")
        parts = h.split("$")
        assert parts[3] == "user"
        assert parts[4] == "REALM"

    def test_checksum_after_realm(self):
        h = format_asrep_hash_raw(RC4_CIPHER, 23, "user", "REALM")
        parts = h.split("$")
        checksum = parts[-2]
        assert checksum == "aa" * 16

    def test_edata2_is_last(self):
        h = format_asrep_hash_raw(RC4_CIPHER, 23, "user", "REALM")
        edata2 = h.split("$")[-1]
        assert edata2 == "bb" * 40


# ---------------------------------------------------------------------------
# Mode 32100: AES128 AS-REP
# Hashcat format 1: $krb5asrep$17$user$realm$checksum$edata2
# ---------------------------------------------------------------------------


class TestMode32100Format:
    def test_structure(self):
        h = format_asrep_hash_raw(AES_CIPHER, 17, "jsmith", "EVIL.CORP")
        assert h.startswith("$krb5asrep$17$jsmith$EVIL.CORP$")

    def test_full_format_regex(self):
        h = format_asrep_hash_raw(AES_CIPHER, 17, "user", "REALM")
        pattern = r"^\$krb5asrep\$17\$user\$REALM\$[a-f0-9]{24}\$[a-f0-9]+$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_checksum_before_edata2(self):
        h = format_asrep_hash_raw(AES_CIPHER, 17, "user", "REALM")
        parts = h.split("$")
        checksum = parts[-2]
        assert checksum == "dd" * 12
        assert len(checksum) == 24

    def test_edata2_is_last(self):
        h = format_asrep_hash_raw(AES_CIPHER, 17, "user", "REALM")
        edata2 = h.split("$")[-1]
        assert edata2 == "cc" * 40


# ---------------------------------------------------------------------------
# Mode 32200: AES256 AS-REP
# Same as 32100 but etype 18
# ---------------------------------------------------------------------------


class TestMode32200Format:
    def test_signature(self):
        h = format_asrep_hash_raw(AES_CIPHER, 18, "user", "REALM")
        assert h.startswith("$krb5asrep$18$")

    def test_same_structure_as_32100(self):
        h17 = format_asrep_hash_raw(AES_CIPHER, 17, "u", "R")
        h18 = format_asrep_hash_raw(AES_CIPHER, 18, "u", "R")
        assert h17.replace("$17$", "$18$") == h18


# ---------------------------------------------------------------------------
# Mode 7500: RC4 Pre-Auth
# Canonical: $krb5pa$23$user$realm$data
# ---------------------------------------------------------------------------


class TestMode7500Format:
    def test_structure(self):
        h = format_pa_hash(PA_RC4_CIPHER, 23, "admin", "EVIL.CORP")
        assert h.startswith("$krb5pa$23$admin$EVIL.CORP$")

    def test_full_format_regex(self):
        h = format_pa_hash(PA_RC4_CIPHER, 23, "user", "REALM")
        pattern = r"^\$krb5pa\$23\$user\$REALM\$[a-f0-9]{104}$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_no_empty_salt_field(self):
        h = format_pa_hash(PA_RC4_CIPHER, 23, "user", "REALM")
        assert "$$" not in h

    def test_data_field_total_length(self):
        h = format_pa_hash(PA_RC4_CIPHER, 23, "user", "REALM")
        data_field = h.split("$")[-1]
        assert len(data_field) == 104

    def test_data_preserves_cipher_order(self):
        h = format_pa_hash(PA_RC4_CIPHER, 23, "user", "REALM")
        data_field = h.split("$")[-1]
        assert data_field[:32] == "11" * 16  # PA_RC4_CHECKSUM (first in cipher)
        assert data_field[32:] == "22" * 36  # PA_RC4_TIMESTAMP (rest of cipher)

    def test_user_can_be_empty(self):
        h = format_pa_hash(PA_RC4_CIPHER, 23, "", "REALM")
        assert h.startswith("$krb5pa$23$$REALM$")


# ---------------------------------------------------------------------------
# Mode 19800: AES128 Pre-Auth
# Hashcat format: $krb5pa$17$user$realm$data
# data = enc_timestamp + checksum concatenated (104-112 hex)
# ---------------------------------------------------------------------------


class TestMode19800Format:
    def test_structure(self):
        h = format_pa_hash(PA_AES_CIPHER, 17, "admin", "EVIL.CORP")
        assert h.startswith("$krb5pa$17$admin$EVIL.CORP$")

    def test_full_format_regex(self):
        h = format_pa_hash(PA_AES_CIPHER, 17, "user", "REALM")
        # $krb5pa$17$user$REALM$<104-112hex>
        pattern = r"^\$krb5pa\$17\$user\$REALM\$[a-f0-9]{104,112}$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_data_field_length(self):
        h = format_pa_hash(PA_AES_CIPHER, 17, "user", "REALM")
        data = h.split("$")[-1]
        assert 104 <= len(data) <= 112

    def test_checksum_at_end_of_data(self):
        """Hashcat splits internally: last 24 hex = checksum."""
        h = format_pa_hash(PA_AES_CIPHER, 17, "user", "REALM")
        data = h.split("$")[-1]
        checksum = data[-24:]
        assert checksum == "44" * 12  # PA_AES_CHECKSUM

    def test_enc_timestamp_before_checksum(self):
        h = format_pa_hash(PA_AES_CIPHER, 17, "user", "REALM")
        data = h.split("$")[-1]
        enc_timestamp = data[:-24]
        assert enc_timestamp == "33" * 44  # PA_AES_TIMESTAMP

    def test_user_required_nonempty(self):
        """Hashcat requires user >= 1 char for AES modes."""
        h = format_pa_hash(PA_AES_CIPHER, 17, "a", "R")
        parts = h.split("$")
        assert parts[3] == "a"


# ---------------------------------------------------------------------------
# Mode 19900: AES256 Pre-Auth
# Same as 19800 but etype 18
# ---------------------------------------------------------------------------


class TestMode19900Format:
    def test_signature(self):
        h = format_pa_hash(PA_AES_CIPHER, 18, "user", "REALM")
        assert h.startswith("$krb5pa$18$")

    def test_same_structure_as_19800(self):
        h17 = format_pa_hash(PA_AES_CIPHER, 17, "u", "R")
        h18 = format_pa_hash(PA_AES_CIPHER, 18, "u", "R")
        assert h17.replace("$17$", "$18$") == h18


# ---------------------------------------------------------------------------
# Cross-mode: hex is always lowercase
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Mode 31300: MS-SNTP Timeroasting
# Hashcat format: $sntp-ms$<RID>$<32hex_digest>$<96hex_salt>
# ---------------------------------------------------------------------------


class TestMode31300Format:
    MD5 = b"\xaa" * 16  # 16 bytes = 32 hex
    SALT = b"\xbb" * 48  # 48 bytes = 96 hex
    RID = 1000

    def test_structure(self):
        from kerbwolf.hashcat import format_sntp_hash

        h = format_sntp_hash(self.MD5, self.SALT, self.RID)
        assert h.startswith("$sntp-ms$")
        parts = h.split("$")
        assert len(parts) == 5  # ['', 'sntp-ms', rid, digest, salt]

    def test_rid_field(self):
        from kerbwolf.hashcat import format_sntp_hash

        h = format_sntp_hash(self.MD5, self.SALT, 1234)
        assert h.split("$")[2] == "1234"

    def test_digest_32_hex(self):
        from kerbwolf.hashcat import format_sntp_hash

        h = format_sntp_hash(self.MD5, self.SALT, self.RID)
        digest = h.split("$")[3]
        assert len(digest) == 32

    def test_salt_96_hex(self):
        from kerbwolf.hashcat import format_sntp_hash

        h = format_sntp_hash(self.MD5, self.SALT, self.RID)
        salt = h.split("$")[4]
        assert len(salt) == 96

    def test_full_regex(self):
        from kerbwolf.hashcat import format_sntp_hash

        h = format_sntp_hash(self.MD5, self.SALT, self.RID)
        pattern = r"^\$sntp-ms\$\d+\$[a-f0-9]{32}\$[a-f0-9]{96}$"
        assert re.match(pattern, h), f"Format mismatch: {h}"

    def test_matches_expected(self):
        from kerbwolf.hashcat import format_sntp_hash

        md5 = bytes.fromhex("cfc7023381cf6bb474cdcbeb0a67bdb3")
        salt = bytes.fromhex("907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380")
        h = format_sntp_hash(md5, salt, 1103)
        expected = "$sntp-ms$1103$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380"
        assert h == expected


class TestHexCase:
    def test_tgs_rc4_lowercase(self):
        cipher = bytes(range(256)) * 2  # includes all byte values
        h = format_tgs_hash_raw(cipher[:64], 23, "u", "R", "s")
        hex_parts = h.split("$")[-2:]
        for part in hex_parts:
            assert part == part.lower()

    def test_asrep_aes_lowercase(self):
        cipher = bytes(range(256))[:52]
        h = format_asrep_hash_raw(cipher, 17, "u", "R")
        hex_parts = h.split("$")[-2:]
        for part in hex_parts:
            assert part == part.lower()

    def test_pa_rc4_lowercase(self):
        cipher = bytes(range(256))[:52]
        h = format_pa_hash(cipher, 23, "u", "R")
        data = h.split("$")[-1]
        assert data == data.lower()
