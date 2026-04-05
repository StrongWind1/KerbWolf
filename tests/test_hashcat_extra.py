"""Additional hashcat tests - John format edge cases, DES fallback, checksum splits."""

from kerbwolf.hashcat import format_asrep_hash_raw, format_pa_hash, format_tgs_hash_raw
from kerbwolf.models import HashFormat

# ---------------------------------------------------------------------------
# John format - detailed structure verification
# ---------------------------------------------------------------------------


class TestJohnTgsStructure:
    """Verify John TGS hash structure matches john source code expectations."""

    def test_rc4_has_star_delimiters(self):
        cipher = b"\xaa" * 16 + b"\xbb" * 32
        h = format_tgs_hash_raw(cipher, 23, "svc", "REALM", "http/web", fmt=HashFormat.JOHN)
        # $krb5tgs$23$*user$realm$spn*$checksum$edata2
        assert "$*svc$REALM$http/web*$" in h

    def test_aes_no_star_delimiters(self):
        cipher = b"\xcc" * 50 + b"\xdd" * 12
        h = format_tgs_hash_raw(cipher, 18, "svc", "REALM", "http/web", fmt=HashFormat.JOHN)
        # $krb5tgs$18$user$realm$checksum$edata2 (no star)
        assert "*" not in h
        assert "$svc$REALM$" in h

    def test_aes128_john(self):
        cipher = b"\xee" * 50 + b"\xff" * 12
        h = format_tgs_hash_raw(cipher, 17, "u", "R", "s", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5tgs$17$u$R$")


class TestJohnAsrepStructure:
    """Verify John AS-REP hash structure."""

    def test_rc4_no_username(self):
        cipher = b"\xaa" * 16 + b"\xbb" * 32
        h = format_asrep_hash_raw(cipher, 23, "user", "REALM", fmt=HashFormat.JOHN)
        # $krb5asrep$23$checksum$edata2 (no username for john RC4)
        parts = h.split("$")
        assert parts[1] == "krb5asrep"
        assert parts[2] == "23"
        # checksum is 32 hex
        assert len(parts[3]) == 32

    def test_aes_has_realm_user(self):
        cipher = b"\xcc" * 50 + b"\xdd" * 12
        h = format_asrep_hash_raw(cipher, 17, "user", "REALM", fmt=HashFormat.JOHN)
        # $krb5asrep$17$REALMuser$edata2$checksum
        assert "$REALMuser$" in h


class TestJohnPaStructure:
    """Verify John PA hash structure - same as hashcat for both RC4 and AES."""

    def test_rc4_same_as_hashcat(self):
        cipher = b"\xaa" * 16 + b"\xbb" * 36
        john = format_pa_hash(cipher, 23, "user", "REALM", fmt=HashFormat.JOHN)
        hashcat = format_pa_hash(cipher, 23, "user", "REALM", fmt=HashFormat.HASHCAT)
        assert john == hashcat

    def test_aes_has_user_realm_edata_checksum(self):
        cipher = b"\xcc" * 44 + b"\xdd" * 12
        h = format_pa_hash(cipher, 18, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb5pa$18$user$REALM$")
        # John PA AES format includes edata+checksum concatenated
        assert "cc" * 44 in h
        assert "dd" * 12 in h


class TestJohnDesFormat:
    """Verify John DES format - $krb3$ for etype 3, hashcat fallback for etype 1."""

    def test_des_md5_uses_krb3(self):
        cipher = b"\xaa" * 40
        h = format_tgs_hash_raw(cipher, 3, "user", "REALM", "spn", fmt=HashFormat.JOHN)
        assert h.startswith("$krb3$")
        assert "REALMuser" in h

    def test_des_crc_falls_back_to_hashcat(self):
        cipher = b"\xbb" * 40
        john = format_tgs_hash_raw(cipher, 1, "user", "REALM", "spn", fmt=HashFormat.JOHN)
        hashcat = format_tgs_hash_raw(cipher, 1, "user", "REALM", "spn", fmt=HashFormat.HASHCAT)
        assert john == hashcat

    def test_asrep_des_md5_john(self):
        cipher = b"\xcc" * 40
        h = format_asrep_hash_raw(cipher, 3, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb3$")

    def test_pa_des_md5_john(self):
        cipher = b"\xdd" * 40
        h = format_pa_hash(cipher, 3, "user", "REALM", fmt=HashFormat.JOHN)
        assert h.startswith("$krb3$")


# ---------------------------------------------------------------------------
# Hashcat checksum/edata2 split accuracy
# ---------------------------------------------------------------------------


class TestHashcatChecksumSplit:
    """Verify the checksum/edata2 split positions are correct."""

    def test_rc4_checksum_first_16_bytes(self):
        checksum = b"\x11" * 16
        edata2 = b"\x22" * 48
        cipher = checksum + edata2
        h = format_tgs_hash_raw(cipher, 23, "u", "R", "s")
        # checksum hex should be 1111...1111 (32 chars)
        assert "$" + "11" * 16 + "$" in h
        assert "22" * 48 in h

    def test_aes_checksum_last_12_bytes(self):
        edata2 = b"\x33" * 50
        checksum = b"\x44" * 12
        cipher = edata2 + checksum
        h = format_tgs_hash_raw(cipher, 18, "u", "R", "s")
        # checksum hex should be 4444...4444 (24 chars)
        assert "$" + "44" * 12 + "$" in h
        assert "33" * 50 in h

    def test_asrep_rc4_checksum_split(self):
        checksum = b"\x55" * 16
        edata2 = b"\x66" * 32
        cipher = checksum + edata2
        h = format_asrep_hash_raw(cipher, 23, "u", "R")
        # $krb5asrep$23$user@REALM:checksum$edata2
        assert "55" * 16 in h
        assert "66" * 32 in h

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
# SPN colon escaping in all formats
# ---------------------------------------------------------------------------


class TestSpnColonEscaping:
    def test_hashcat_tgs_rc4(self):
        cipher = b"\xaa" * 48
        h = format_tgs_hash_raw(cipher, 23, "u", "R", "MSSQLSvc/db01:1433")
        assert "MSSQLSvc/db01~1433" in h

    def test_hashcat_tgs_aes(self):
        cipher = b"\xbb" * 62
        h = format_tgs_hash_raw(cipher, 18, "u", "R", "MSSQLSvc/db01:1433")
        assert "MSSQLSvc/db01~1433" in h

    def test_hashcat_tgs_des(self):
        cipher = b"\xcc" * 40
        h = format_tgs_hash_raw(cipher, 3, "u", "R", "svc:port")
        assert "svc~port" in h

    def test_john_tgs_rc4(self):
        cipher = b"\xdd" * 48
        h = format_tgs_hash_raw(cipher, 23, "u", "R", "svc:1433", fmt=HashFormat.JOHN)
        assert "svc~1433" in h
