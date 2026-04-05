"""Tests for kerbwolf.attacks.timeroast, hash formatting, and CLI."""

import re
from unittest.mock import patch

from kerbwolf.attacks.timeroast import timeroast
from kerbwolf.core.ntp import NtpResponse
from kerbwolf.hashcat import format_sntp_hash, format_sntp_sha512_hash
from kerbwolf.models import HashcatMode

# ---------------------------------------------------------------------------
# format_sntp_hash (MD5, hashcat 31300)
# ---------------------------------------------------------------------------


class TestFormatSntpHash:
    def test_format_structure(self):
        h = format_sntp_hash(b"\xaa" * 16, b"\xbb" * 48, 1000)
        assert h.startswith("$sntp-ms$")
        assert h.count("$") == 4

    def test_rid_field(self):
        h = format_sntp_hash(b"\xaa" * 16, b"\xbb" * 48, 1234)
        parts = h.split("$")
        assert parts[2] == "1234"

    def test_digest_32_hex(self):
        parts = format_sntp_hash(b"\xcc" * 16, b"\xdd" * 48, 1000).split("$")
        assert len(parts[3]) == 32

    def test_salt_96_hex(self):
        parts = format_sntp_hash(b"\xee" * 16, b"\xff" * 48, 1000).split("$")
        assert len(parts[4]) == 96

    def test_regex(self):
        h = format_sntp_hash(b"\x12\x34" * 8, b"\x56\x78" * 24, 500)
        assert re.match(r"^\$sntp-ms\$\d+\$[a-f0-9]{32}\$[a-f0-9]{96}$", h)

    def test_known_values(self):
        md5 = bytes.fromhex("cfc7023381cf6bb474cdcbeb0a67bdb3")
        salt = bytes.fromhex("907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380")
        assert format_sntp_hash(md5, salt, 1103) == "$sntp-ms$1103$cfc7023381cf6bb474cdcbeb0a67bdb3$907733697536811342962140955567108526489624716566696971338784438986103976327367763739445744705380"


# ---------------------------------------------------------------------------
# format_sntp_sha512_hash
# ---------------------------------------------------------------------------


class TestFormatSntpSha512Hash:
    def test_format_structure(self):
        h = format_sntp_sha512_hash(b"\xaa" * 64, b"\xbb" * 48, 1000)
        assert h.startswith("$sntp-ms-sha512$")
        assert h.count("$") == 4

    def test_rid_field(self):
        h = format_sntp_sha512_hash(b"\xaa" * 64, b"\xbb" * 48, 1234)
        parts = h.split("$")
        assert parts[2] == "1234"

    def test_digest_128_hex(self):
        parts = format_sntp_sha512_hash(b"\xcc" * 64, b"\xdd" * 48, 1000).split("$")
        assert len(parts[3]) == 128

    def test_salt_96_hex(self):
        parts = format_sntp_sha512_hash(b"\xee" * 64, b"\xff" * 48, 1000).split("$")
        assert len(parts[4]) == 96


# ---------------------------------------------------------------------------
# timeroast attack
# ---------------------------------------------------------------------------


def _mock_response(rid, is_extended=False, sig_hash_id=0):
    checksum = b"\xaa" * (64 if is_extended else 16)
    return NtpResponse(rid, b"\xbb" * 48, checksum, sig_hash_id=sig_hash_id, is_extended=is_extended)


class TestTimeroastAttack:
    def test_empty_rids(self):
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=[]):
            results = timeroast(dc_ip="10.0.0.1", rids=[])
        assert results.current == []
        assert results.previous == []

    def test_md5_results(self):
        current = [_mock_response(1000)]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=current):
            results = timeroast(dc_ip="10.0.0.1", rids=[1000])
        assert len(results.current) == 1
        assert results.current[0].hashcat_mode == HashcatMode.SNTP_MS
        assert results.current[0].hash_string.startswith("$sntp-ms$")

    def test_sha512_results(self):
        """120-byte response with SigHashID=0x01 goes into current list as SHA512."""
        current = [_mock_response(1000, is_extended=True, sig_hash_id=0x01)]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=current):
            results = timeroast(dc_ip="10.0.0.1", rids=[1000], fmt="extended")
        assert len(results.current) == 1
        assert results.current[0].hash_string.startswith("$sntp-ms-sha512$")
        assert results.current[0].hashcat_mode == 0

    def test_sha512_in_results(self):
        """120-byte response with SigHashID=0x01 produces SHA512 hash."""
        resp = [_mock_response(1000, is_extended=True, sig_hash_id=0x01)]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=resp):
            results = timeroast(dc_ip="10.0.0.1", rids=[1000], fmt="extended")
        # SHA512 goes into current list
        assert len(results.current) == 1
        assert results.current[0].hash_string.startswith("$sntp-ms-sha512$")
        assert results.current[0].hashcat_mode == 0

    def test_extended_always_sha512(self):
        """120-byte response always produces SHA512 hash, even with SigHashID=0x00."""
        current = [_mock_response(1000, is_extended=True, sig_hash_id=0x00)]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=current):
            results = timeroast(dc_ip="10.0.0.1", rids=[1000], fmt="extended")
        assert len(results.current) == 1
        assert results.current[0].hash_string.startswith("$sntp-ms-sha512$")

    def test_rid_stored_as_username(self):
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=[_mock_response(1234)]):
            results = timeroast(dc_ip="10.0.0.1", rids=[1234])
        assert results.current[0].username == "1234"

    def test_multiple_rids(self):
        responses = [_mock_response(rid) for rid in [500, 501, 502]]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=responses):
            results = timeroast(dc_ip="10.0.0.1", rids=range(500, 503))
        assert len(results.current) == 3

    def test_password_previous(self):
        """--password previous only queries old passwords."""
        responses = [_mock_response(1000)]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=responses) as mock:
            results = timeroast(dc_ip="10.0.0.1", rids=[1000], password="previous")
        assert results.current == []
        assert len(results.previous) == 1
        # Verify old_pwd=True was passed
        mock.assert_called_once()
        assert mock.call_args.kwargs["old_pwd"] is True

    def test_password_both(self):
        """--password both queries current, then previous for discovered RIDs."""
        responses = [_mock_response(1000)]
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=responses) as mock:
            results = timeroast(dc_ip="10.0.0.1", rids=[1000], password="both")
        assert len(results.current) == 1
        assert len(results.previous) == 1
        assert mock.call_count == 2
        # First call: old_pwd=False (current), second: old_pwd=True (previous)
        assert mock.call_args_list[0].kwargs["old_pwd"] is False
        assert mock.call_args_list[1].kwargs["old_pwd"] is True

    def test_port_passthrough(self):
        """Custom port is passed to ntp_roast."""
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=[]) as mock:
            timeroast(dc_ip="10.0.0.1", rids=[1000], port=12345)
        assert mock.call_args.kwargs["port"] == 12345

    def test_format_extended_passthrough(self):
        """--format extended passes extended=True."""
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=[]) as mock:
            timeroast(dc_ip="10.0.0.1", rids=[1000], fmt="extended")
        assert mock.call_args.kwargs["extended"] is True

    def test_format_auth_passthrough(self):
        """--format auth passes extended=False."""
        with patch("kerbwolf.attacks.timeroast.ntp_roast", return_value=[]) as mock:
            timeroast(dc_ip="10.0.0.1", rids=[1000], fmt="auth")
        assert mock.call_args.kwargs["extended"] is False


# ---------------------------------------------------------------------------
# RID range parser
# ---------------------------------------------------------------------------


class TestRidRangeParsing:
    def _parse(self, arg):
        from kerbwolf.cli.timeroast import _parse_rid_ranges

        return list(_parse_rid_ranges(arg))

    def _parse_iter(self, arg):
        from kerbwolf.cli.timeroast import _parse_rid_ranges

        return _parse_rid_ranges(arg)

    def test_single(self):
        assert self._parse("1000") == [1000]

    def test_range(self):
        assert self._parse("500-502") == [500, 501, 502]

    def test_open_end(self):
        rids = self._parse("2147483645-")
        assert rids[0] == 2147483645
        assert len(rids) == 3

    def test_open_start(self):
        assert self._parse("-3") == [0, 1, 2, 3]

    def test_dash_all(self):
        from itertools import islice

        rids = self._parse_iter("-")
        first_10 = list(islice(rids, 10))
        assert first_10[0] == 0
        assert first_10[9] == 9

    def test_comma(self):
        assert self._parse("1,3,5") == [1, 3, 5]

    def test_mixed(self):
        assert self._parse("1-3,10,20-22") == [1, 2, 3, 10, 20, 21, 22]


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------


class TestTimeroastCLI:
    def test_help(self):
        import pytest

        from kerbwolf.cli.timeroast import main

        with pytest.raises(SystemExit, match="0"):
            main(["--help"])

    def test_defaults(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1"])
        assert args.dc == "10.0.0.1"
        assert args.fmt == "auth"
        assert args.password == "current"
        assert args.rate == 180
        assert args.port == 123
        assert args.rid_prefix is False

    def test_format_extended(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--format", "extended"])
        assert args.fmt == "extended"

    def test_format_both(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--format", "both"])
        assert args.fmt == "both"

    def test_password_previous(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--password", "previous"])
        assert args.password == "previous"

    def test_password_both(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--password", "both"])
        assert args.password == "both"

    def test_port(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--port", "12345"])
        assert args.port == 12345

    def test_rid_prefix(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--rid-prefix"])
        assert args.rid_prefix is True

    def test_src_port(self):
        from kerbwolf.cli.timeroast import _build_parser

        args = _build_parser().parse_args(["10.0.0.1", "--src-port", "123"])
        assert args.src_port == 123


# ---------------------------------------------------------------------------
# CLI output formatting
# ---------------------------------------------------------------------------


class TestFormatLine:
    def test_default_no_rid_prefix(self):
        from kerbwolf.cli.timeroast import _format_line
        from kerbwolf.models import RoastResult

        r = RoastResult(username="1000", realm="", spn="", etype=0, hash_string="$sntp-ms$1000$aabb$ccdd", hashcat_mode=31300)
        assert _format_line(r, rid_prefix=False) == "$sntp-ms$1000$aabb$ccdd"

    def test_with_rid_prefix(self):
        from kerbwolf.cli.timeroast import _format_line
        from kerbwolf.models import RoastResult

        r = RoastResult(username="1000", realm="", spn="", etype=0, hash_string="$sntp-ms$1000$aabb$ccdd", hashcat_mode=31300)
        assert _format_line(r, rid_prefix=True) == "1000:$sntp-ms$1000$aabb$ccdd"


# ---------------------------------------------------------------------------
# safe_output_path
# ---------------------------------------------------------------------------


class TestSafeOutputPath:
    def test_new_file(self, tmp_path):
        from kerbwolf.cli._common import safe_output_path

        p = safe_output_path(str(tmp_path / "test.txt"))
        assert p == tmp_path / "test.txt"

    def test_existing_increments(self, tmp_path):
        from kerbwolf.cli._common import safe_output_path

        (tmp_path / "test.txt").write_text("existing")
        p = safe_output_path(str(tmp_path / "test.txt"))
        assert p == tmp_path / "test_1.txt"

    def test_multiple_increments(self, tmp_path):
        from kerbwolf.cli._common import safe_output_path

        (tmp_path / "test.txt").write_text("1")
        (tmp_path / "test_1.txt").write_text("2")
        (tmp_path / "test_2.txt").write_text("3")
        p = safe_output_path(str(tmp_path / "test.txt"))
        assert p == tmp_path / "test_3.txt"
