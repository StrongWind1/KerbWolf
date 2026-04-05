"""Tests for kerbwolf.attacks.kerberoast - Kerberoast and no-preauth attack logic."""

from unittest.mock import MagicMock, patch

from kerbwolf.attacks.kerberoast import kerberoast, kerberoast_no_preauth
from kerbwolf.models import EncryptionType, KDCError, KerberosCredential

# ---------------------------------------------------------------------------
# kerberoast - no credentials and no TGT
# ---------------------------------------------------------------------------


class TestKerberoastNoAuth:
    def test_no_cred_and_no_tgt_raises(self):
        """Must provide either credentials or a TGT."""
        with __import__("pytest").raises(KDCError, match="credentials or a TGT"):
            kerberoast(dc_ip="1.2.3.4", target_spns=["http/web"])


# ---------------------------------------------------------------------------
# kerberoast - KDC error handling
# ---------------------------------------------------------------------------


class TestKerberoastErrorHandling:
    def test_kdc_error_skipped(self):
        """KDCError on TGS request should skip the target."""
        mock_session_key = MagicMock()
        mock_session_key.enctype = 23

        with patch("kerbwolf.attacks.kerberoast.request_tgt", return_value=(b"tgt", b"key", mock_session_key)), patch("kerbwolf.attacks.kerberoast.ENCTYPE_TABLE", {23: MagicMock()}), patch("kerbwolf.attacks.kerberoast.request_tgs", side_effect=KDCError(7, "S_PRINCIPAL_UNKNOWN")):
            results = kerberoast(
                KerberosCredential(username="admin", domain="evil.corp", password="pass"),
                dc_ip="10.0.0.1",
                target_spns=["bogus/spn"],
            )
        assert results == []

    def test_unexpected_error_skipped(self):
        mock_session_key = MagicMock()
        mock_session_key.enctype = 23

        with patch("kerbwolf.attacks.kerberoast.request_tgt", return_value=(b"tgt", b"key", mock_session_key)), patch("kerbwolf.attacks.kerberoast.ENCTYPE_TABLE", {23: MagicMock()}), patch("kerbwolf.attacks.kerberoast.request_tgs", side_effect=ConnectionError("timeout")):
            results = kerberoast(
                KerberosCredential(username="admin", domain="evil.corp", password="pass"),
                dc_ip="10.0.0.1",
                target_spns=["http/web"],
            )
        assert results == []


# ---------------------------------------------------------------------------
# kerberoast - ccache (pre-loaded TGT) path
# ---------------------------------------------------------------------------


class TestKerberoastCcache:
    def test_uses_provided_tgt(self):
        """When tgt/session_key/cipher_cls are provided, no request_tgt call."""
        mock_session_key = MagicMock()
        mock_cipher_cls = MagicMock()

        with patch("kerbwolf.attacks.kerberoast.request_tgt") as mock_req, patch("kerbwolf.attacks.kerberoast.request_tgs", side_effect=KDCError(0, "")):
            kerberoast(
                dc_ip="10.0.0.1",
                target_spns=["http/web"],
                tgt=b"tgt_bytes",
                tgt_session_key=mock_session_key,
                tgt_cipher_cls=mock_cipher_cls,
            )
            mock_req.assert_not_called()


# ---------------------------------------------------------------------------
# kerberoast - parameter passthrough
# ---------------------------------------------------------------------------


class TestKerberoastParams:
    def test_etype_default_rc4(self):
        mock_sk = MagicMock()
        mock_sk.enctype = 23

        with patch("kerbwolf.attacks.kerberoast.request_tgt", return_value=(b"t", b"k", mock_sk)), patch("kerbwolf.attacks.kerberoast.ENCTYPE_TABLE", {23: MagicMock()}), patch("kerbwolf.attacks.kerberoast.request_tgs", side_effect=KDCError(0, "")) as mock_tgs:
            kerberoast(
                KerberosCredential(username="u", domain="d", password="p"),
                dc_ip="1.2.3.4",
                target_spns=["s"],
            )
            assert mock_tgs.call_args.kwargs["etypes"] == (23,)

    def test_timeout_passed_through(self):
        mock_sk = MagicMock()
        mock_sk.enctype = 23

        with patch("kerbwolf.attacks.kerberoast.request_tgt", return_value=(b"t", b"k", mock_sk)) as mock_req, patch("kerbwolf.attacks.kerberoast.ENCTYPE_TABLE", {23: MagicMock()}), patch("kerbwolf.attacks.kerberoast.request_tgs", side_effect=KDCError(0, "")):
            kerberoast(
                KerberosCredential(username="u", domain="d", password="p"),
                dc_ip="1.2.3.4",
                target_spns=["s"],
                timeout=30.0,
            )
            assert mock_req.call_args.kwargs["timeout"] == 30.0


# ---------------------------------------------------------------------------
# kerberoast_no_preauth
# ---------------------------------------------------------------------------


class TestKerberoastNoPreauth:
    def test_empty_targets(self):
        assert kerberoast_no_preauth("vuln_user", domain="d", dc_ip="1.2.3.4", target_users=[]) == []

    def test_none_targets(self):
        assert kerberoast_no_preauth("vuln_user", domain="d", dc_ip="1.2.3.4", target_users=None) == []

    def test_kdc_error_skipped(self):
        with patch("kerbwolf.attacks.kerberoast.request_asrep_no_preauth", side_effect=KDCError(0, "")):
            results = kerberoast_no_preauth("vuln", domain="d", dc_ip="1.2.3.4", target_users=["target"])
        assert results == []

    def test_unexpected_error_skipped(self):
        with patch("kerbwolf.attacks.kerberoast.request_asrep_no_preauth", side_effect=RuntimeError("oops")):
            results = kerberoast_no_preauth("vuln", domain="d", dc_ip="1.2.3.4", target_users=["target"])
        assert results == []

    def test_timeout_passed(self):
        with patch("kerbwolf.attacks.kerberoast.request_asrep_no_preauth", side_effect=KDCError(0, "")) as mock:
            kerberoast_no_preauth("vuln", domain="d", dc_ip="1.2.3.4", target_users=["t"], timeout=25.0)
            assert mock.call_args.kwargs["timeout"] == 25.0

    def test_etype_passed(self):
        with patch("kerbwolf.attacks.kerberoast.request_asrep_no_preauth", side_effect=KDCError(0, "")) as mock:
            kerberoast_no_preauth("vuln", domain="d", dc_ip="1.2.3.4", target_users=["t"], etype=EncryptionType.AES256_CTS_HMAC_SHA1_96)
            assert mock.call_args.kwargs["etypes"] == (18,)
