"""Tests for kerbwolf.attacks.asreproast - AS-REP Roast attack logic."""

from unittest.mock import patch

from kerbwolf.attacks.asreproast import asreproast
from kerbwolf.models import EncryptionType, KDCError, TransportProtocol


class TestAsreproastSkipBehavior:
    """Verify that KDCError and unexpected exceptions are silently skipped."""

    def test_kdc_error_skipped(self):
        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", side_effect=KDCError(24, "PREAUTH_REQUIRED")):
            results = asreproast(domain="evil.corp", dc_ip="10.0.0.1", target_users=["locked_user"])
        assert results == []

    def test_unexpected_error_skipped(self):
        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", side_effect=ConnectionError("network down")):
            results = asreproast(domain="evil.corp", dc_ip="10.0.0.1", target_users=["user1"])
        assert results == []

    def test_mixed_success_and_failure(self):
        """First user fails (KDCError), second succeeds - should get 1 result."""

        # Build a minimal AS-REP that can be decoded
        # We'll mock the decoder path instead for simplicity
        fake_asrep = b"\x6b" + b"\x00" * 100  # Not valid, but we'll mock

        call_count = [0]

        def mock_request(username, domain, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise KDCError(24, "PREAUTH_REQUIRED")
            return fake_asrep

        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", side_effect=mock_request), patch("kerbwolf.attacks.asreproast.decoder.decode") as mock_decode, patch("kerbwolf.attacks.asreproast.format_asrep_hash", return_value="$krb5asrep$23$hash"):
            mock_decoded = mock_decode.return_value = (
                type(
                    "Obj",
                    (),
                    {
                        "__getitem__": lambda self, key: type(
                            "EncPart",
                            (),
                            {
                                "__getitem__": lambda self, key: 23  # etype
                            },
                        )()
                    },
                )(),
                None,
            )

            results = asreproast(
                domain="evil.corp",
                dc_ip="10.0.0.1",
                target_users=["locked_user", "vuln_user"],
            )

        assert len(results) == 1
        assert results[0].username == "vuln_user"


class TestAsreproastParameters:
    """Verify parameters are passed through correctly."""

    def test_timeout_passed_through(self):
        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", side_effect=KDCError(0, "")) as mock:
            asreproast(domain="d", dc_ip="1.2.3.4", target_users=["u"], timeout=30.0)
            assert mock.call_args.kwargs["timeout"] == 30.0

    def test_transport_passed_through(self):
        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", side_effect=KDCError(0, "")) as mock:
            asreproast(domain="d", dc_ip="1.2.3.4", target_users=["u"], transport=TransportProtocol.UDP)
            assert mock.call_args.kwargs["transport"] == TransportProtocol.UDP

    def test_etype_passed_through(self):
        with patch("kerbwolf.attacks.asreproast.request_asrep_no_preauth", side_effect=KDCError(0, "")) as mock:
            asreproast(domain="d", dc_ip="1.2.3.4", target_users=["u"], etype=EncryptionType.AES256_CTS_HMAC_SHA1_96)
            assert mock.call_args.kwargs["etypes"] == (18,)
