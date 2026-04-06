"""Tests for kerbwolf.cli.extract - kw-extract CLI entry point."""

from unittest.mock import patch

import pytest

from kerbwolf.models import RoastResult

# ---------------------------------------------------------------------------
# _output_results
# ---------------------------------------------------------------------------


class TestExtractOutputResults:
    def test_no_results(self, capsys):
        from kerbwolf.cli.extract import _output_results
        from kerbwolf.log import Logger

        _output_results([], None, Logger())
        assert "No hashes" in capsys.readouterr().err

    def test_stdout_output(self, capsys):
        from kerbwolf.cli.extract import _output_results
        from kerbwolf.log import Logger

        results = [
            RoastResult(username="u", realm="R", spn="s", etype=23, hash_string="$krb5tgs$23$test", hashcat_mode=13100),
        ]
        _output_results(results, None, Logger())
        out = capsys.readouterr().out
        assert "$krb5tgs$23$test" in out

    def test_file_output(self, tmp_path, capsys):
        from kerbwolf.cli.extract import _output_results
        from kerbwolf.log import Logger

        results = [
            RoastResult(username="u", realm="R", spn="s", etype=23, hash_string="$krb5pa$23$hash1", hashcat_mode=7500),
            RoastResult(username="u", realm="R", spn="s", etype=18, hash_string="$krb5asrep$18$hash2", hashcat_mode=32200),
        ]
        outfile = tmp_path / "out.txt"
        _output_results(results, str(outfile), Logger())
        content = outfile.read_text()
        assert "$krb5pa$23$hash1" in content
        assert "$krb5asrep$18$hash2" in content

    def test_attack_type_summary(self, capsys):
        from kerbwolf.cli.extract import _output_results
        from kerbwolf.log import Logger

        results = [
            RoastResult(username="u", realm="R", spn="s", etype=23, hash_string="$krb5pa$23$a", hashcat_mode=7500),
            RoastResult(username="u", realm="R", spn="s", etype=23, hash_string="$krb5asrep$23$b", hashcat_mode=18200),
            RoastResult(username="u", realm="R", spn="s", etype=23, hash_string="$krb5tgs$23$c", hashcat_mode=13100),
        ]
        _output_results(results, None, Logger())
        err = capsys.readouterr().err
        assert "AS-REQ" in err
        assert "AS-REP" in err
        assert "TGS-REP" in err

    def test_sntp_summary(self, capsys):
        from kerbwolf.cli.extract import _output_results
        from kerbwolf.log import Logger

        results = [
            RoastResult(username="1000", realm="", spn="", etype=0, hash_string="$sntp-ms$1000$aa$bb", hashcat_mode=31300),
            RoastResult(username="2000", realm="", spn="", etype=0, hash_string="$sntp-ms-sha512$2000$cc$dd", hashcat_mode=0),
        ]
        _output_results(results, None, Logger())
        err = capsys.readouterr().err
        assert "SNTP-MD5" in err
        assert "SNTP-SHA512" in err


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


class TestExtractParser:
    def test_single_pcap(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["capture.pcap"])
        assert args.pcap == ["capture.pcap"]

    def test_multiple_pcaps(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["a.pcap", "b.pcapng"])
        assert args.pcap == ["a.pcap", "b.pcapng"]

    def test_stdin_dash(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["-"])
        assert args.pcap == ["-"]

    def test_output_flag(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["f.pcap", "-o", "out.txt"])
        assert args.output == "out.txt"

    def test_format_flag(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["f.pcap", "--format", "john"])
        assert args.hash_format == "john"

    def test_verbose_flag(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["-vv", "f.pcap"])
        assert args.verbose == 2

    def test_no_pcap_exits(self):
        from kerbwolf.cli.extract import main

        with pytest.raises(SystemExit):
            main([])


# ---------------------------------------------------------------------------
# main() integration
# ---------------------------------------------------------------------------


class TestExtractMain:
    def test_main_parses_pcap(self, capsys):
        from kerbwolf.cli.extract import main

        results = [
            RoastResult(username="u", realm="R", spn="s", etype=23, hash_string="$krb5tgs$23$test", hashcat_mode=13100),
        ]
        with patch("kerbwolf.cli.extract.extract_from_pcap", return_value=results):
            main(["test.pcap"])
        out = capsys.readouterr().out
        assert "$krb5tgs$23$test" in out

    def test_main_handles_parse_error(self, capsys):
        from kerbwolf.cli.extract import main

        with patch("kerbwolf.cli.extract.extract_from_pcap", side_effect=Exception("corrupt file")):
            main(["bad.pcap"])
        err = capsys.readouterr().err
        assert "corrupt file" in err

    def test_main_multiple_files(self, capsys):
        from kerbwolf.cli.extract import main

        r1 = [RoastResult(username="u1", realm="R", spn="s", etype=23, hash_string="$krb5pa$23$h1", hashcat_mode=7500)]
        r2 = [RoastResult(username="u2", realm="R", spn="s", etype=23, hash_string="$krb5tgs$23$h2", hashcat_mode=13100)]

        call_count = [0]

        def mock_extract(path, **kwargs):
            call_count[0] += 1
            return r1 if call_count[0] == 1 else r2

        with patch("kerbwolf.cli.extract.extract_from_pcap", side_effect=mock_extract):
            main(["a.pcap", "b.pcap"])

        out = capsys.readouterr().out
        assert "$krb5pa$23$h1" in out
        assert "$krb5tgs$23$h2" in out

    def test_main_header_shows_file_count(self, capsys):
        from kerbwolf.cli.extract import main

        with patch("kerbwolf.cli.extract.extract_from_pcap", return_value=[]):
            main(["a.pcap", "b.pcap", "c.pcap", "d.pcap"])
        err = capsys.readouterr().err
        assert "4 file(s)" in err


# ---------------------------------------------------------------------------
# Directory scanning (-d / --dir)
# ---------------------------------------------------------------------------


class TestExtractDirFlag:
    def test_dir_flag_parsed(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["-d", "/pcaps"])
        assert args.dirs == ["/pcaps"]

    def test_dir_flag_repeatable(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["-d", "/a", "-d", "/b"])
        assert args.dirs == ["/a", "/b"]

    def test_find_pcaps_in_dir(self, tmp_path):
        from kerbwolf.cli.extract import _find_pcaps_in_dir

        (tmp_path / "a.pcap").touch()
        (tmp_path / "b.pcapng").touch()
        (tmp_path / "c.txt").touch()
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "d.pcap").touch()

        found = _find_pcaps_in_dir(str(tmp_path))
        names = {p.split("/")[-1] for p in found}
        assert "a.pcap" in names
        assert "b.pcapng" in names
        assert "d.pcap" in names
        assert "c.txt" not in names

    def test_dir_only_no_positional_allowed(self, tmp_path):
        """Passing only -d (no positional pcap) should work when dir has files."""
        from unittest.mock import patch

        (tmp_path / "cap.pcap").touch()

        with patch("kerbwolf.cli.extract.extract_from_pcap", return_value=[]):
            from kerbwolf.cli.extract import main

            main(["-d", str(tmp_path)])  # should not raise

    def test_no_args_exits(self):
        from kerbwolf.cli.extract import main

        with pytest.raises(SystemExit):
            main([])

    def test_dir_with_no_pcaps_exits(self, tmp_path):
        """A directory with no pcap files causes an error."""
        from kerbwolf.cli.extract import main

        (tmp_path / "readme.txt").touch()
        with pytest.raises(SystemExit):
            main(["-d", str(tmp_path)])
