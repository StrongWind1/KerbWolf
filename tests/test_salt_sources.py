# SPDX-License-Identifier: Apache-2.0
"""Tests for the places a string-to-key salt is read from: PA-DATA, AS-REP, and the salt probe."""

from unittest.mock import patch

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP, AS_REQ, ETYPE_INFO2, KRB_ERROR, METHOD_DATA, seq_set_iter
from impacket.krb5.types import Principal
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue

from kerbwolf.core.asreq import extract_salt_from_asrep, probe_account_salt, salt_from_padata
from kerbwolf.models import TransportProtocol

PA_PW_SALT = int(constants.PreAuthenticationDataTypes.PA_PW_SALT.value)
PA_ETYPE_INFO2 = int(constants.PreAuthenticationDataTypes.PA_ETYPE_INFO2.value)


def _etype_info2(salt: str, etype: int = 18) -> bytes:
    info = ETYPE_INFO2()
    info[0] = noValue
    info[0]["etype"] = etype
    info[0]["salt"] = salt
    return encoder.encode(info)


def _padata(*entries: tuple[int, bytes]):
    """Return a decoded SEQUENCE OF PA-DATA, as it comes out of a parsed message."""
    method_data = METHOD_DATA()
    for i, (pa_type, value) in enumerate(entries):
        method_data[i] = noValue
        method_data[i]["padata-type"] = pa_type
        method_data[i]["padata-value"] = value
    return decoder.decode(encoder.encode(method_data), asn1Spec=METHOD_DATA())[0]


def _as_rep(*entries: tuple[int, bytes], user: str = "svc", realm: str = "CORP.LOCAL", etype: int = 18) -> bytes:
    rep = AS_REP()
    rep["pvno"] = 5
    rep["msg-type"] = int(constants.ApplicationTagNumbers.AS_REP.value)
    rep["padata"] = noValue
    for i, (pa_type, value) in enumerate(entries):
        rep["padata"][i] = noValue
        rep["padata"][i]["padata-type"] = pa_type
        rep["padata"][i]["padata-value"] = value
    rep["crealm"] = realm
    client = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
    rep["cname"]["name-type"] = client.type
    rep["cname"]["name-string"][0] = user
    rep["ticket"]["tkt-vno"] = 5
    rep["ticket"]["realm"] = realm
    rep["ticket"]["sname"]["name-type"] = 2
    rep["ticket"]["sname"]["name-string"][0] = "krbtgt"
    rep["ticket"]["sname"]["name-string"][1] = realm
    rep["ticket"]["enc-part"]["etype"] = 18
    rep["ticket"]["enc-part"]["cipher"] = b"\x00" * 32
    rep["enc-part"]["etype"] = etype
    rep["enc-part"]["cipher"] = b"\x00" * 64
    return encoder.encode(rep)


class TestSaltFromPadata:
    def test_etype_info2(self):
        assert salt_from_padata(_padata((PA_ETYPE_INFO2, _etype_info2("CORP.LOCALsvc")))) == "CORP.LOCALsvc"

    def test_pa_pw_salt_is_used_for_des_replies(self):
        assert salt_from_padata(_padata((PA_PW_SALT, b"CORP.LOCALsvc_des"))) == "CORP.LOCALsvc_des"

    def test_etype_info2_wins_over_pa_pw_salt(self):
        padata = _padata((PA_PW_SALT, b"CORP.LOCALfrom_pw_salt"), (PA_ETYPE_INFO2, _etype_info2("CORP.LOCALfrom_info2")))
        assert salt_from_padata(padata) == "CORP.LOCALfrom_info2"

    def test_no_salt(self):
        assert salt_from_padata(_padata((128, b"\x30\x05\xa0\x03\x01\x01\xff"))) is None
        assert salt_from_padata(None) is None


class TestExtractSaltFromAsrep:
    def test_des_reply_gives_real_casing(self):
        raw = _as_rep((PA_PW_SALT, b"CORP.LOCALSvc_Des"), user="SVC_DES")
        assert extract_salt_from_asrep(raw, "corp.local") == ("Svc_Des", "CORP.LOCAL")

    def test_aes_reply(self):
        raw = _as_rep((PA_ETYPE_INFO2, _etype_info2("CORP.LOCALSvc_Aes")), user="svc_aes")
        assert extract_salt_from_asrep(raw, "corp.local") == ("Svc_Aes", "CORP.LOCAL")

    def test_salt_not_starting_with_realm_is_ignored(self):
        raw = _as_rep((PA_PW_SALT, b"\x01\x02\x03\x04"))
        assert extract_salt_from_asrep(raw, "corp.local") is None


class TestSaltProbe:
    def test_no_preauth_account_answers_with_as_rep(self):
        """A DONT_REQ_PREAUTH account returns an AS-REP, not PREAUTH_REQUIRED; its padata has the salt."""
        raw = _as_rep((PA_ETYPE_INFO2, _etype_info2("CORP.LOCALSvc_NoPre")), user="svc_nopre")
        with patch("kerbwolf.core.asreq.send_receive", return_value=raw):
            result = probe_account_salt("SVC_NOPRE", "CORP.LOCAL", dc_ip="192.0.2.1", transport=TransportProtocol.TCP)
        assert result == ("Svc_NoPre", "CORP.LOCAL")


class TestMachineNameWithoutSalt:
    """A machine name ends in ``$``, which would split the hash line, so it is written in its host form."""

    def test_kw_asrep_rc4_reply_for_a_machine_account(self):
        from kerbwolf.attacks.asreproast import asreproast

        raw = _as_rep(user="WS01$", etype=23)
        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", return_value=raw):
            results = asreproast(domain="corp.local", dc_ip="10.0.0.1", target_users=["WS01$"])

        assert len(results) == 1
        assert results[0].username == "hostws01.corp.local"
        assert results[0].hash_string.startswith("$krb5asrep$23$hostws01.corp.local$CORP.LOCAL$")
        assert len(results[0].hash_string.split("$")) == 7

    def test_kw_extract_rc4_as_rep_for_a_machine_account(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import AttackType, CapturedHash

        h = CapturedHash(attack=AttackType.AS_REP, username="WS01$", realm="CORP.LOCAL", spn="", etype=23, cipher_hex="ab" * 64)
        result = _captured_to_result(h, {})
        assert result.hash_string.startswith("$krb5asrep$23$hostws01.corp.local$CORP.LOCAL$")

    def test_kw_extract_ticket_for_a_machine_account_without_a_salt(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import AttackType, CapturedHash

        h = CapturedHash(attack=AttackType.TGS_REP, username="WS01$", realm="CORP.LOCAL", spn="WS01$", etype=18, cipher_hex="ab" * 64)
        result = _captured_to_result(h, {})
        assert result.hash_string.startswith("$krb5tgs$18$hostws01.corp.local$CORP.LOCAL$")

    def test_kw_extract_pre_auth_for_a_machine_account_without_a_salt(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import AttackType, CapturedHash

        h = CapturedHash(attack=AttackType.AS_REQ, username="ws01$", realm="CORP.LOCAL", spn="", etype=18, cipher_hex="ab" * 56)
        result = _captured_to_result(h, {})
        assert result.hash_string.startswith("$krb5pa$18$hostws01.corp.local$CORP.LOCAL$")

    def test_kw_extract_keeps_an_spn_and_a_user_name(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import AttackType, CapturedHash

        spn = CapturedHash(attack=AttackType.TGS_REP, username="HTTP/web01.corp.local", realm="CORP.LOCAL", spn="HTTP/web01.corp.local", etype=23, cipher_hex="ab" * 64)
        user = CapturedHash(attack=AttackType.AS_REP, username="alice", realm="CORP.LOCAL", spn="", etype=23, cipher_hex="ab" * 64)
        assert _captured_to_result(spn, {}).hash_string.startswith("$krb5tgs$23$HTTP/web01.corp.local$CORP.LOCAL$")
        assert _captured_to_result(user, {}).hash_string.startswith("$krb5asrep$23$alice$CORP.LOCAL$")


def _as_req(user: str, realm: str = "CORP.LOCAL") -> bytes:
    """An AS-REQ without pre-authentication, as a salt probe or the first leg of a logon sends it."""
    req = AS_REQ()
    req["pvno"] = 5
    req["msg-type"] = int(constants.ApplicationTagNumbers.AS_REQ.value)
    body = req["req-body"]
    body["kdc-options"] = constants.encodeFlags([])
    body["cname"]["name-type"] = constants.PrincipalNameType.NT_PRINCIPAL.value
    body["cname"]["name-string"][0] = user
    body["realm"] = realm
    body["sname"]["name-type"] = 2
    body["sname"]["name-string"][0] = "krbtgt"
    body["sname"]["name-string"][1] = realm
    body["till"] = "20370913024805Z"
    body["nonce"] = 1
    seq_set_iter(body, "etype", (18,))
    return encoder.encode(req)


def _preauth_required(salt: str, realm: str = "CORP.LOCAL") -> bytes:
    """The KRB-ERROR a KDC answers such a request with: no cname, the salt in ETYPE-INFO2."""
    method_data = METHOD_DATA()
    method_data[0] = noValue
    method_data[0]["padata-type"] = PA_ETYPE_INFO2
    method_data[0]["padata-value"] = _etype_info2(salt)
    err = KRB_ERROR()
    err["pvno"] = 5
    err["msg-type"] = int(constants.ApplicationTagNumbers.KRB_ERROR.value)
    err["stime"] = "20261126000000Z"
    err["susec"] = 0
    err["error-code"] = int(constants.ErrorCodes.KDC_ERR_PREAUTH_REQUIRED.value)
    err["realm"] = realm
    err["sname"]["name-type"] = 2
    err["sname"]["name-string"][0] = "krbtgt"
    err["sname"]["name-string"][1] = realm
    err["e-data"] = encoder.encode(method_data)
    return encoder.encode(err)


CLIENT = ("10.0.0.5", 50000, "10.0.0.1", 88)
KDC = ("10.0.0.1", 88, "10.0.0.5", 50000)


class TestPreauthErrorSaltPairing:
    """The salt in a PREAUTH_REQUIRED error is filed under the name of the request it answers."""

    def _hints(self, messages):
        from kerbwolf.core.capture import _kerberos_hashes

        requests: dict = {}
        hints = {}
        for key, data in messages:
            for h in _kerberos_hashes(data, key, requests):
                hints[h.username] = h.padata_salt
        return hints

    def test_machine_account_salt_is_filed_under_its_name(self):
        hints = self._hints([(CLIENT, _as_req("WS01$")), (KDC, _preauth_required("CORP.LOCALhostws01.corp.local"))])
        assert hints["WS01$"] == "CORP.LOCALhostws01.corp.local"

    def test_renamed_account_keeps_its_old_salt(self):
        from kerbwolf.attacks.extract import _captured_to_result
        from kerbwolf.models import AttackType, CapturedHash

        salt = "CORP.LOCALhostold01.corp.local"
        hints = self._hints([(CLIENT, _as_req("NEW01$")), (KDC, _preauth_required(salt))])
        lowered = {name.lower(): value for name, value in hints.items()}
        ticket = CapturedHash(attack=AttackType.TGS_REP, username="NEW01$", realm="CORP.LOCAL", spn="NEW01$", etype=18, cipher_hex="ab" * 64)
        assert _captured_to_result(ticket, lowered).hash_string.startswith("$krb5tgs$18$hostold01.corp.local$CORP.LOCAL$")

    def test_user_typed_in_another_case(self):
        hints = self._hints([(CLIENT, _as_req("JSMITH")), (KDC, _preauth_required("CORP.LOCALJSmith"))])
        assert hints["JSMITH"] == "CORP.LOCALJSmith"
        assert hints["JSmith"] == "CORP.LOCALJSmith"

    def test_error_without_its_request_falls_back_to_the_name_in_the_salt(self):
        hints = self._hints([(KDC, _preauth_required("CORP.LOCALJSmith"))])
        assert hints == {"JSmith": "CORP.LOCALJSmith"}

    def test_error_on_another_connection_does_not_take_the_name(self):
        other_kdc = ("10.0.0.1", 88, "10.0.0.9", 51000)
        hints = self._hints([(CLIENT, _as_req("WS01$")), (other_kdc, _preauth_required("CORP.LOCALAlice"))])
        assert hints == {"Alice": "CORP.LOCALAlice"}

    def test_stream_extractor_pairs_request_and_error(self):
        import struct

        from kerbwolf.core.capture import _extract_kerberos_from_stream

        requests: dict = {}
        req = _as_req("WS01$")
        err = _preauth_required("CORP.LOCALhostws01.corp.local")
        assert _extract_kerberos_from_stream(bytearray(struct.pack("!I", len(req)) + req), CLIENT, requests) == []
        found = _extract_kerberos_from_stream(bytearray(struct.pack("!I", len(err)) + err), KDC, requests)
        assert {h.username for h in found} == {"WS01$", "hostws01.corp.local"}

    def test_as_req_without_any_padata_is_parsed(self):
        from kerbwolf.core.capture import _as_req_cname, _try_parse_asreq

        raw = _as_req("alice")
        assert _try_parse_asreq(raw) == []
        assert _as_req_cname(raw) == "alice"

    def test_parser_alone_still_reads_the_name_from_the_salt(self):
        from kerbwolf.core.capture import _try_parse_krberror_salt

        found = _try_parse_krberror_salt(_preauth_required("CORP.LOCALJSmith"))
        assert [h.username for h in found] == ["JSmith"]
