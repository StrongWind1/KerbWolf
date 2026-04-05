"""Tests for kerbwolf.core.transport - TCP and UDP KDC communication."""

from unittest.mock import MagicMock, patch

import pytest

from kerbwolf.core.transport import _is_response_too_big, _recv_exact, _send_receive_tcp, _send_receive_udp, send_receive
from kerbwolf.models import KDCError, TransportProtocol


def _build_krb_error(error_code: int) -> bytes:
    """Build a minimal DER-encoded KRB-ERROR with the given error code.

    Manually constructs DER bytes since impacket's ASN.1 schema uses
    complex tagged types that are difficult to populate externally.
    """

    def _der_int(value: int) -> bytes:
        """DER-encode a non-negative integer."""
        if value == 0:
            return b"\x02\x01\x00"
        octets = []
        v = value
        while v > 0:
            octets.append(v & 0xFF)
            v >>= 8
        if octets[-1] & 0x80:
            octets.append(0)
        octets.reverse()
        return b"\x02" + bytes([len(octets)]) + bytes(octets)

    def _ctx_wrap(tag_num: int, content: bytes, constructed: bool = False) -> bytes:
        cls = 0xA0 if constructed else 0x80
        tag_byte = cls | tag_num
        length = len(content)
        if length < 0x80:
            return bytes([tag_byte, length]) + content
        # Long form length
        len_bytes = []
        l = length
        while l > 0:
            len_bytes.append(l & 0xFF)
            l >>= 8
        len_bytes.reverse()
        return bytes([tag_byte, 0x80 | len(len_bytes)]) + bytes(len_bytes) + content

    def _der_gentime(val: bytes) -> bytes:
        return b"\x18" + bytes([len(val)]) + val

    def _der_genstring(val: bytes) -> bytes:
        return b"\x1b" + bytes([len(val)]) + val

    def _der_seq(content: bytes) -> bytes:
        length = len(content)
        if length < 0x80:
            return b"\x30" + bytes([length]) + content
        len_bytes = []
        l = length
        while l > 0:
            len_bytes.append(l & 0xFF)
            l >>= 8
        len_bytes.reverse()
        return b"\x30" + bytes([0x80 | len(len_bytes)]) + bytes(len_bytes) + content

    # Build KRB-ERROR fields
    pvno = _ctx_wrap(0, _der_int(5), constructed=True)
    msg_type = _ctx_wrap(1, _der_int(30), constructed=True)
    stime = _ctx_wrap(4, _der_gentime(b"19700101000000Z"), constructed=True)
    susec = _ctx_wrap(5, _der_int(0), constructed=True)
    err_code = _ctx_wrap(6, _der_int(error_code), constructed=True)
    realm = _ctx_wrap(9, _der_genstring(b"TEST"), constructed=True)
    # sname: SEQUENCE { name-type [0] INT, name-string [1] SEQ OF GeneralString }
    sname_inner = _ctx_wrap(0, _der_int(2), constructed=True) + _ctx_wrap(1, _der_seq(_der_genstring(b"krbtgt")), constructed=True)
    sname = _ctx_wrap(10, _der_seq(sname_inner), constructed=True)

    # Inner SEQUENCE content
    seq_content = pvno + msg_type + stime + susec + err_code + realm + sname
    inner = _der_seq(seq_content)

    # APPLICATION 30 wrapper (tag = 0x7E, constructed)
    length = len(inner)
    if length < 0x80:
        return b"\x7e" + bytes([length]) + inner
    len_bytes = []
    l = length
    while l > 0:
        len_bytes.append(l & 0xFF)
        l >>= 8
    len_bytes.reverse()
    return b"\x7e" + bytes([0x80 | len(len_bytes)]) + bytes(len_bytes) + inner


class TestSendReceiveDispatch:
    def test_tcp_default(self):
        with patch("kerbwolf.core.transport._send_receive_tcp", return_value=b"resp") as mock:
            result = send_receive(b"data", "1.2.3.4")
            mock.assert_called_once()
            assert result == b"resp"

    def test_udp_explicit(self):
        with patch("kerbwolf.core.transport._send_receive_udp", return_value=b"resp") as mock:
            result = send_receive(b"data", "1.2.3.4", protocol=TransportProtocol.UDP)
            mock.assert_called_once()
            assert result == b"resp"

    def test_tcp_explicit(self):
        with patch("kerbwolf.core.transport._send_receive_tcp", return_value=b"resp") as mock:
            result = send_receive(b"data", "1.2.3.4", protocol=TransportProtocol.TCP)
            mock.assert_called_once()
            assert result == b"resp"

    def test_custom_port(self):
        with patch("kerbwolf.core.transport._send_receive_tcp", return_value=b"r") as mock:
            send_receive(b"d", "host", port=8888)
            args = mock.call_args[0]
            assert args[2] == 8888


class TestTCP:
    def test_connection_error_raises_kdc_error(self):
        with patch("kerbwolf.core.transport.socket.create_connection", side_effect=OSError("refused")), pytest.raises(KDCError, match="TCP connection"):
            _send_receive_tcp(b"data", "1.2.3.4", 88, 5.0)

    def test_timeout_raises_kdc_error(self):
        with patch("kerbwolf.core.transport.socket.create_connection", side_effect=TimeoutError), pytest.raises(KDCError, match="TCP connection"):
            _send_receive_tcp(b"data", "1.2.3.4", 88, 1.0)


class TestUDP:
    def test_timeout_raises_kdc_error(self):
        with patch("kerbwolf.core.transport.socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_sock.__enter__ = MagicMock(return_value=mock_sock)
            mock_sock.__exit__ = MagicMock(return_value=False)
            mock_sock.recvfrom.side_effect = TimeoutError
            mock_cls.return_value = mock_sock
            with pytest.raises(KDCError, match="UDP communication"):
                _send_receive_udp(b"data", "1.2.3.4", 88, 1.0)


class TestIsResponseTooBig:
    """_is_response_too_big detects KRB_ERROR with error code 52."""

    def test_error_52_returns_true(self):
        raw = _build_krb_error(52)
        assert raw[0] == 0x7E  # APPLICATION 30
        assert _is_response_too_big(raw) is True

    def test_other_error_returns_false(self):
        raw = _build_krb_error(6)  # KDC_ERR_C_PRINCIPAL_UNKNOWN
        assert _is_response_too_big(raw) is False

    def test_empty_returns_false(self):
        assert _is_response_too_big(b"") is False

    def test_garbage_returns_false(self):
        assert _is_response_too_big(b"\x00\x01\x02\x03") is False

    def test_wrong_tag_returns_false(self):
        assert _is_response_too_big(b"\x30\x03\x02\x01\x34") is False


class TestUdpFallback:
    """UDP auto-fallback to TCP when response is too big."""

    def test_fallback_on_error_52(self):
        too_big = _build_krb_error(52)
        with (
            patch("kerbwolf.core.transport._send_receive_udp", return_value=too_big) as mock_udp,
            patch("kerbwolf.core.transport._send_receive_tcp", return_value=b"tcp_resp") as mock_tcp,
        ):
            result = send_receive(b"data", "1.2.3.4", protocol=TransportProtocol.UDP)
            mock_udp.assert_called_once()
            mock_tcp.assert_called_once()
            assert result == b"tcp_resp"

    def test_no_fallback_on_normal_response(self):
        with (
            patch("kerbwolf.core.transport._send_receive_udp", return_value=b"udp_resp") as mock_udp,
            patch("kerbwolf.core.transport._send_receive_tcp") as mock_tcp,
        ):
            result = send_receive(b"data", "1.2.3.4", protocol=TransportProtocol.UDP)
            mock_udp.assert_called_once()
            mock_tcp.assert_not_called()
            assert result == b"udp_resp"

    def test_no_fallback_on_other_error(self):
        other_err = _build_krb_error(6)
        with (
            patch("kerbwolf.core.transport._send_receive_udp", return_value=other_err) as mock_udp,
            patch("kerbwolf.core.transport._send_receive_tcp") as mock_tcp,
        ):
            result = send_receive(b"data", "1.2.3.4", protocol=TransportProtocol.UDP)
            mock_udp.assert_called_once()
            mock_tcp.assert_not_called()
            assert result == other_err


class TestRecvExact:
    def test_full_read(self):
        sock = MagicMock()
        sock.recv.return_value = b"abcd"
        assert _recv_exact(sock, 4) == b"abcd"

    def test_chunked_read(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"ab", b"cd"]
        assert _recv_exact(sock, 4) == b"abcd"

    def test_connection_closed_raises(self):
        sock = MagicMock()
        sock.recv.return_value = b""
        with pytest.raises(KDCError, match="Connection closed"):
            _recv_exact(sock, 4)
