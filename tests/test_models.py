"""Tests for kerbwolf.models - enums, dataclasses, constants, errors."""

from kerbwolf.models import (
    AES128_KEY_HEX_LEN,
    AES256_KEY_HEX_LEN,
    DES_KEY_HEX_LEN,
    ETYPE_BY_NAME,
    RC4_KEY_HEX_LEN,
    UF_ACCOUNTDISABLE,
    UF_DONT_REQUIRE_PREAUTH,
    UF_SERVER_TRUST_ACCOUNT,
    UF_TRUST_ACCOUNT_SWAP_MASK,
    UF_USE_DES_KEY_ONLY,
    UF_WORKSTATION_TRUST_ACCOUNT,
    EncryptionType,
    HashcatMode,
    HashFormat,
    KDCError,
    KerberosCredential,
    KerbWolfError,
    LDAPError,
    RoastResult,
    TargetAccount,
    TransportProtocol,
)

# ---------------------------------------------------------------------------
# EncryptionType enum
# ---------------------------------------------------------------------------


class TestEncryptionType:
    def test_des_cbc_crc_value(self):
        assert EncryptionType.DES_CBC_CRC == 1

    def test_des_cbc_md5_value(self):
        assert EncryptionType.DES_CBC_MD5 == 3

    def test_aes128_value(self):
        assert EncryptionType.AES128_CTS_HMAC_SHA1_96 == 17

    def test_aes256_value(self):
        assert EncryptionType.AES256_CTS_HMAC_SHA1_96 == 18

    def test_rc4_value(self):
        assert EncryptionType.RC4_HMAC == 23

    def test_is_des_true_for_crc(self):
        assert EncryptionType.DES_CBC_CRC.is_des is True

    def test_is_des_true_for_md5(self):
        assert EncryptionType.DES_CBC_MD5.is_des is True

    def test_is_des_false_for_rc4(self):
        assert EncryptionType.RC4_HMAC.is_des is False

    def test_is_des_false_for_aes128(self):
        assert EncryptionType.AES128_CTS_HMAC_SHA1_96.is_des is False

    def test_is_des_false_for_aes256(self):
        assert EncryptionType.AES256_CTS_HMAC_SHA1_96.is_des is False

    def test_is_aes_true_for_128(self):
        assert EncryptionType.AES128_CTS_HMAC_SHA1_96.is_aes is True

    def test_is_aes_true_for_256(self):
        assert EncryptionType.AES256_CTS_HMAC_SHA1_96.is_aes is True

    def test_is_aes_false_for_rc4(self):
        assert EncryptionType.RC4_HMAC.is_aes is False

    def test_is_aes_false_for_des(self):
        assert EncryptionType.DES_CBC_MD5.is_aes is False

    def test_total_enum_members(self):
        assert len(EncryptionType) == 5

    def test_int_conversion(self):
        assert int(EncryptionType.RC4_HMAC) == 23

    def test_from_int(self):
        assert EncryptionType(23) == EncryptionType.RC4_HMAC


# ---------------------------------------------------------------------------
# ETYPE_BY_NAME mapping
# ---------------------------------------------------------------------------


class TestEtypeByName:
    def test_des_cbc_crc(self):
        assert ETYPE_BY_NAME["des-cbc-crc"] == EncryptionType.DES_CBC_CRC

    def test_des_cbc_md5_explicit(self):
        assert ETYPE_BY_NAME["des-cbc-md5"] == EncryptionType.DES_CBC_MD5

    def test_rc4(self):
        assert ETYPE_BY_NAME["rc4"] == EncryptionType.RC4_HMAC

    def test_aes128(self):
        assert ETYPE_BY_NAME["aes128"] == EncryptionType.AES128_CTS_HMAC_SHA1_96

    def test_aes256(self):
        assert ETYPE_BY_NAME["aes256"] == EncryptionType.AES256_CTS_HMAC_SHA1_96

    def test_missing_key_raises(self):
        import pytest

        with pytest.raises(KeyError):
            ETYPE_BY_NAME["invalid"]

    def test_all_names_count(self):
        assert len(ETYPE_BY_NAME) == 5


# ---------------------------------------------------------------------------
# TransportProtocol / HashFormat
# ---------------------------------------------------------------------------


class TestTransportProtocol:
    def test_udp_value(self):
        assert TransportProtocol.UDP == "udp"

    def test_tcp_value(self):
        assert TransportProtocol.TCP == "tcp"

    def test_from_string(self):
        assert TransportProtocol("tcp") == TransportProtocol.TCP


class TestHashFormat:
    def test_hashcat(self):
        assert HashFormat.HASHCAT == "hashcat"

    def test_john(self):
        assert HashFormat.JOHN == "john"


# ---------------------------------------------------------------------------
# HashcatMode
# ---------------------------------------------------------------------------


class TestHashcatMode:
    def test_tgs_rc4(self):
        assert HashcatMode.KRB5_TGS_RC4 == 13100

    def test_tgs_aes128(self):
        assert HashcatMode.KRB5_TGS_AES128 == 19600

    def test_tgs_aes256(self):
        assert HashcatMode.KRB5_TGS_AES256 == 19700

    def test_asrep_rc4(self):
        assert HashcatMode.KRB5_ASREP_RC4 == 18200

    def test_asrep_aes128(self):
        assert HashcatMode.KRB5_ASREP_AES128 == 32100

    def test_asrep_aes256(self):
        assert HashcatMode.KRB5_ASREP_AES256 == 32200

    def test_pa_rc4(self):
        assert HashcatMode.KRB5_PA_RC4 == 7500

    def test_pa_aes128(self):
        assert HashcatMode.KRB5_PA_AES128 == 19800

    def test_pa_aes256(self):
        assert HashcatMode.KRB5_PA_AES256 == 19900

    def test_des_modes_are_negative(self):
        assert HashcatMode.KRB5_TGS_DES_CBC_CRC < 0
        assert HashcatMode.KRB5_TGS_DES_CBC_MD5 < 0
        assert HashcatMode.KRB5_ASREP_DES_CBC_CRC < 0
        assert HashcatMode.KRB5_ASREP_DES_CBC_MD5 < 0
        assert HashcatMode.KRB5_PA_DES_CBC_CRC < 0
        assert HashcatMode.KRB5_PA_DES_CBC_MD5 < 0

    def test_total_modes(self):
        assert len(HashcatMode) == 18


# ---------------------------------------------------------------------------
# UAC constants
# ---------------------------------------------------------------------------


class TestUACConstants:
    def test_accountdisable(self):
        assert UF_ACCOUNTDISABLE == 0x2

    def test_use_des_key_only(self):
        assert UF_USE_DES_KEY_ONLY == 0x200000

    def test_dont_require_preauth(self):
        assert UF_DONT_REQUIRE_PREAUTH == 0x400000

    def test_server_trust(self):
        assert UF_SERVER_TRUST_ACCOUNT == 0x2000

    def test_workstation_trust(self):
        assert UF_WORKSTATION_TRUST_ACCOUNT == 0x1000

    def test_swap_mask_covers_both(self):
        assert UF_TRUST_ACCOUNT_SWAP_MASK == (UF_SERVER_TRUST_ACCOUNT | UF_WORKSTATION_TRUST_ACCOUNT)

    def test_bitwise_set_des_flag(self):
        uac = 0x10200
        uac |= UF_USE_DES_KEY_ONLY
        assert uac & UF_USE_DES_KEY_ONLY

    def test_bitwise_clear_des_flag(self):
        uac = UF_USE_DES_KEY_ONLY | 0x200
        uac &= ~UF_USE_DES_KEY_ONLY
        assert not uac & UF_USE_DES_KEY_ONLY
        assert uac & 0x200


# ---------------------------------------------------------------------------
# Key hex lengths
# ---------------------------------------------------------------------------


class TestKeyHexLengths:
    def test_des(self):
        assert DES_KEY_HEX_LEN == 16

    def test_rc4(self):
        assert RC4_KEY_HEX_LEN == 32

    def test_aes128(self):
        assert AES128_KEY_HEX_LEN == 32

    def test_aes256(self):
        assert AES256_KEY_HEX_LEN == 64


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


class TestRoastResult:
    def test_creation(self):
        r = RoastResult(username="u", realm="R", spn="s", etype=EncryptionType.RC4_HMAC, hash_string="h", hashcat_mode=13100)
        assert r.username == "u"
        assert r.hashcat_mode == 13100

    def test_frozen(self):
        import pytest

        r = RoastResult(username="u", realm="R", spn="s", etype=EncryptionType.RC4_HMAC, hash_string="h", hashcat_mode=13100)
        with pytest.raises(AttributeError):
            r.username = "changed"


class TestTargetAccount:
    def test_defaults(self):
        t = TargetAccount(samaccountname="svc", dn="CN=svc,DC=test")
        assert t.spns == ()
        assert t.uac == 0
        assert t.use_des_key_only is False
        assert t.dont_require_preauth is False

    def test_with_spns(self):
        t = TargetAccount(samaccountname="svc", dn="DN", spns=("http/web", "cifs/fs"))
        assert len(t.spns) == 2

    def test_frozen(self):
        import pytest

        t = TargetAccount(samaccountname="x", dn="y")
        with pytest.raises(AttributeError):
            t.samaccountname = "z"


class TestKerberosCredential:
    def test_defaults(self):
        c = KerberosCredential(username="u", domain="d")
        assert c.password is None
        assert c.nthash == b""
        assert c.des_key == b""
        assert c.aes128_key == b""
        assert c.aes256_key == b""

    def test_mutable(self):
        c = KerberosCredential(username="u", domain="d")
        c.password = "test"
        assert c.password == "test"

    def test_with_nthash(self):
        c = KerberosCredential(username="u", domain="d", nthash=b"\xaa" * 16)
        assert len(c.nthash) == 16


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TestKerberosContext:
    def test_creation(self):
        from kerbwolf.models import KerberosContext

        ctx = KerberosContext(domain="evil.corp", realm="EVIL.CORP", dc_ip="10.0.0.1")
        assert ctx.domain == "evil.corp"
        assert ctx.realm == "EVIL.CORP"
        assert ctx.dc_ip == "10.0.0.1"
        assert ctx.dc_hostname is None
        assert ctx.username is None
        assert ctx.timeout == 10.0

    def test_full_fields(self):
        from kerbwolf.models import KerberosContext

        ctx = KerberosContext(
            domain="evil.corp",
            realm="EVIL.CORP",
            dc_ip="10.0.0.1",
            dc_hostname="DC01.evil.corp",
            username="admin",
            timeout=30.0,
        )
        assert ctx.dc_hostname == "DC01.evil.corp"
        assert ctx.username == "admin"
        assert ctx.timeout == 30.0

    def test_mutable(self):
        from kerbwolf.models import KerberosContext

        ctx = KerberosContext(domain="a", realm="A", dc_ip="1.2.3.4")
        ctx.dc_hostname = "dc.a"
        assert ctx.dc_hostname == "dc.a"


class TestExceptions:
    def test_kerbwolf_error_base(self):
        assert issubclass(KDCError, KerbWolfError)
        assert issubclass(LDAPError, KerbWolfError)

    def test_kdc_error_code(self):
        e = KDCError(error_code=25, message="PREAUTH_REQUIRED")
        assert e.error_code == 25
        assert "PREAUTH_REQUIRED" in str(e)

    def test_kdc_error_default_message(self):
        e = KDCError(error_code=14)
        assert "14" in str(e)

    def test_ldap_error(self):
        e = LDAPError("bind failed")
        assert "bind failed" in str(e)
