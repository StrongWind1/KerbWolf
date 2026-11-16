# SPDX-License-Identifier: Apache-2.0
"""Tests for the places a string-to-key salt is read from: PA-DATA, AS-REP, and the salt probe."""

from unittest.mock import patch

from impacket.krb5 import constants
from impacket.krb5.asn1 import AS_REP, ETYPE_INFO2, METHOD_DATA
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


def _as_rep(*entries: tuple[int, bytes], user: str = "svc", realm: str = "CORP.LOCAL") -> bytes:
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
    rep["enc-part"]["etype"] = 18
    rep["enc-part"]["cipher"] = b"\x00" * 32
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
