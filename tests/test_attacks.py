"""Tests for attack modules - kerberoast, asreproast, extract, gettgt."""

from unittest.mock import patch

from kerbwolf.core.capture import AttackType, CapturedHash
from kerbwolf.models import HashFormat, RoastResult

# ---------------------------------------------------------------------------
# kerberoast._spn_to_username
# ---------------------------------------------------------------------------


class TestTargetToDisplayName:
    def test_service_host(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("http/webserver") == "webserver"

    def test_service_fqdn(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("http/web.domain.com") == "web"

    def test_no_slash(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("svcaccount") == "svcaccount"

    def test_multiple_slashes(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("MSSQLSvc/sql01.corp.local:1433") == "sql01"

    def test_trailing_slash(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("svc/") == ""

    def test_upn(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("svc_sql@corp.local") == "svc_sql"

    def test_samaccountname(self):
        from kerbwolf.attacks.kerberoast import _target_to_display_name

        assert _target_to_display_name("svc_sql") == "svc_sql"


# ---------------------------------------------------------------------------
# kerberoast - empty targets
# ---------------------------------------------------------------------------


class TestKerberoastEmptyTargets:
    def test_none_targets(self):
        from kerbwolf.attacks.kerberoast import kerberoast
        from kerbwolf.models import KerberosCredential

        cred = KerberosCredential(username="u", domain="d")
        assert kerberoast(cred, dc_ip="1.2.3.4", target_spns=None) == []

    def test_empty_list(self):
        from kerbwolf.attacks.kerberoast import kerberoast
        from kerbwolf.models import KerberosCredential

        cred = KerberosCredential(username="u", domain="d")
        assert kerberoast(cred, dc_ip="1.2.3.4", target_spns=[]) == []


# ---------------------------------------------------------------------------
# asreproast - empty targets
# ---------------------------------------------------------------------------


class TestAsreproastEmptyTargets:
    def test_none_targets(self):
        from kerbwolf.attacks.asreproast import asreproast

        assert asreproast(domain="d", dc_ip="1.2.3.4", target_users=None) == []

    def test_empty_list(self):
        from kerbwolf.attacks.asreproast import asreproast

        assert asreproast(domain="d", dc_ip="1.2.3.4", target_users=[]) == []


# ---------------------------------------------------------------------------
# extract - _captured_to_result
# ---------------------------------------------------------------------------


class TestCapturedToResult:
    def test_asreq_attack(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(attack=AttackType.AS_REQ, username="u", realm="R", spn="krbtgt/R", etype=23, cipher_hex="aa" * 52)
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert isinstance(result, RoastResult)
        assert result.hash_string.startswith("$krb5pa$23$")
        assert result.username == "u"

    def test_asrep_attack(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(attack=AttackType.AS_REP, username="u", realm="R", spn="krbtgt/R", etype=18, cipher_hex="bb" * 60)
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert result.hash_string.startswith("$krb5asrep$18$")

    def test_tgsrep_attack(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(attack=AttackType.TGS_REP, username="u", realm="R", spn="http/web", etype=23, cipher_hex="cc" * 48)
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert result.hash_string.startswith("$krb5tgs$23$")

    def test_des_etype(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(attack=AttackType.TGS_REP, username="u", realm="R", spn="s", etype=3, cipher_hex="dd" * 64)
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert result.hash_string.startswith("$krb5tgs$3$")

    def test_john_format(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(attack=AttackType.AS_REQ, username="u", realm="R", spn="krbtgt/R", etype=23, cipher_hex="ee" * 52)
        result = _captured_to_result(h, HashFormat.JOHN)
        assert "$krb5pa$" in result.hash_string

    def test_sntp_md5(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(
            attack=AttackType.SNTP_MD5,
            username="1000",
            realm="",
            spn="",
            etype=0,
            cipher_hex="aa" * 16,
            salt_hex="bb" * 48,
            rid=1000,
        )
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert result.hash_string.startswith("$sntp-ms$1000$")
        assert result.hashcat_mode == 31300

    def test_sntp_sha512(self):
        from kerbwolf.attacks.extract import _captured_to_result

        h = CapturedHash(
            attack=AttackType.SNTP_SHA512,
            username="2000",
            realm="",
            spn="",
            etype=0,
            cipher_hex="cc" * 64,
            salt_hex="dd" * 48,
            rid=2000,
        )
        result = _captured_to_result(h, HashFormat.HASHCAT)
        assert result.hash_string.startswith("$sntp-ms-sha512$2000$")
        assert result.hashcat_mode == 0


# ---------------------------------------------------------------------------
# extract - extract_from_pcap with mocked parse_pcap
# ---------------------------------------------------------------------------


class TestExtractFromPcap:
    def test_empty_pcap(self):
        from kerbwolf.attacks.extract import extract_from_pcap

        with patch("kerbwolf.attacks.extract.parse_pcap", return_value=[]):
            assert extract_from_pcap("test.pcap") == []

    def test_mixed_attacks(self):
        from kerbwolf.attacks.extract import extract_from_pcap

        captures = [
            CapturedHash(attack=AttackType.AS_REQ, username="u1", realm="R", spn="krbtgt/R", etype=23, cipher_hex="aa" * 52),
            CapturedHash(attack=AttackType.AS_REP, username="u2", realm="R", spn="krbtgt/R", etype=17, cipher_hex="bb" * 60),
            CapturedHash(attack=AttackType.TGS_REP, username="u3", realm="R", spn="http/w", etype=18, cipher_hex="cc" * 62),
        ]
        with patch("kerbwolf.attacks.extract.parse_pcap", return_value=captures):
            results = extract_from_pcap("test.pcap")
            assert len(results) == 3
            prefixes = {r.hash_string.split("$")[1] for r in results}
            assert "krb5pa" in prefixes
            assert "krb5asrep" in prefixes
            assert "krb5tgs" in prefixes
