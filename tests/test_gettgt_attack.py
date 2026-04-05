"""Tests for kerbwolf.attacks.gettgt - TGT acquisition logic."""

from unittest.mock import MagicMock, patch

from kerbwolf.attacks.gettgt import get_tgt
from kerbwolf.models import EncryptionType, KerberosCredential, TransportProtocol


class TestGetTgt:
    def test_returns_ccache_bytes_and_session_key(self):
        mock_session_key = MagicMock()
        mock_session_key.enctype = 23

        with patch("kerbwolf.attacks.gettgt.request_tgt", return_value=(b"raw_asrep", b"client_key", mock_session_key)), patch("kerbwolf.attacks.gettgt.CCache") as mock_ccache_cls:
            mock_ccache = MagicMock()
            mock_ccache.getData.return_value = b"ccache_data"
            mock_ccache_cls.return_value = mock_ccache

            ccache_bytes, session_key = get_tgt(
                KerberosCredential(username="admin", domain="evil.corp", password="pass"),
                dc_ip="10.0.0.1",
            )

        assert ccache_bytes == b"ccache_data"
        assert session_key == mock_session_key
        mock_ccache.fromTGT.assert_called_once_with(b"raw_asrep", b"client_key", mock_session_key)

    def test_passes_etype_and_transport(self):
        mock_session_key = MagicMock()

        with patch("kerbwolf.attacks.gettgt.request_tgt", return_value=(b"r", b"k", mock_session_key)) as mock_req, patch("kerbwolf.attacks.gettgt.CCache") as mock_ccache_cls:
            mock_ccache_cls.return_value = MagicMock(getData=MagicMock(return_value=b""))

            get_tgt(
                KerberosCredential(username="u", domain="d"),
                dc_ip="1.2.3.4",
                etype=EncryptionType.AES256_CTS_HMAC_SHA1_96,
                transport=TransportProtocol.UDP,
                timeout=30.0,
            )

        call_kwargs = mock_req.call_args
        assert call_kwargs.kwargs["etype"] == EncryptionType.AES256_CTS_HMAC_SHA1_96
        assert call_kwargs.kwargs["transport"] == TransportProtocol.UDP
        assert call_kwargs.kwargs["timeout"] == 30.0
