"""Tests for all CLI modules - argument parsing, credentials, targets, output."""

import pytest


class TestParseNthash:
    def test_lm_colon_nt(self):
        from kerbwolf.cli._common import parse_nthash

        result = parse_nthash("aabbccdd11223344:aabbccddaabbccddaabbccddaabbccdd")
        assert len(result) == 16

    def test_colon_nt(self):
        from kerbwolf.cli._common import parse_nthash

        result = parse_nthash(":aabbccddaabbccddaabbccddaabbccdd")
        assert len(result) == 16

    def test_nt_only(self):
        from kerbwolf.cli._common import parse_nthash

        result = parse_nthash("aabbccddaabbccddaabbccddaabbccdd")
        assert len(result) == 16

    def test_whitespace_stripped(self):
        from kerbwolf.cli._common import parse_nthash

        result = parse_nthash("  :aabbccddaabbccddaabbccddaabbccdd  ")
        assert len(result) == 16


class TestBuildCredential:
    def _parse_roast(self, extra_args):
        from kerbwolf.cli.kerberoast import _build_parser

        return _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", *extra_args])

    def _parse_tgt(self, extra_args):
        from kerbwolf.cli.gettgt import _build_parser

        return _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", *extra_args])

    def test_password(self):
        from kerbwolf.cli._common import build_credential

        cred = build_credential(self._parse_roast(["-u", "admin", "-p", "pass123"]))
        assert cred.username == "admin"
        assert cred.password == "pass123"

    def test_nthash_via_H(self):
        from kerbwolf.cli._common import build_credential

        cred = build_credential(self._parse_roast(["-u", "u", "-H", ":aabbccddaabbccddaabbccddaabbccdd"]))
        assert len(cred.nthash) == 16

    def test_nthash_bare(self):
        from kerbwolf.cli._common import build_credential

        cred = build_credential(self._parse_roast(["-u", "u", "-H", "aabbccddaabbccddaabbccddaabbccdd"]))
        assert len(cred.nthash) == 16

    def test_rc4_key(self):
        from kerbwolf.cli._common import build_credential_full

        cred = build_credential_full(self._parse_tgt(["-u", "u", "--rc4-key", "aa" * 16]))
        assert len(cred.nthash) == 16

    def test_aes128_key(self):
        from kerbwolf.cli._common import build_credential_full

        cred = build_credential_full(self._parse_tgt(["-u", "u", "--aes128-key", "bb" * 16]))
        assert len(cred.aes128_key) == 16

    def test_aes256_key(self):
        from kerbwolf.cli._common import build_credential_full

        cred = build_credential_full(self._parse_tgt(["-u", "u", "--aes256-key", "cc" * 32]))
        assert len(cred.aes256_key) == 32

    def test_des_md5_key(self):
        from kerbwolf.cli._common import build_credential_full

        cred = build_credential_full(self._parse_tgt(["-u", "u", "--des-md5-key", "dd" * 8]))
        assert len(cred.des_key) == 8

    def test_des_crc_key(self):
        from kerbwolf.cli._common import build_credential_full

        cred = build_credential_full(self._parse_tgt(["-u", "u", "--des-crc-key", "ee" * 8]))
        assert len(cred.des_key) == 8


class TestCollectTargets:
    def test_from_flag(self):
        from kerbwolf.cli._common import collect_targets
        from kerbwolf.cli.kerberoast import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-t", "http/web", "-t", "cifs/fs"])
        assert collect_targets(args) == ["http/web", "cifs/fs"]

    def test_from_file(self, tmp_path):
        from kerbwolf.cli._common import collect_targets
        from kerbwolf.cli.kerberoast import _build_parser

        f = tmp_path / "targets.txt"
        f.write_text("http/web\ncifs/fs\n\n# comment\n")
        parser = _build_parser()
        args = parser.parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-T", str(f)])
        targets = collect_targets(args)
        assert "http/web" in targets
        assert "cifs/fs" in targets
        assert len(targets) == 2

    def test_combined(self, tmp_path):
        from kerbwolf.cli._common import collect_targets
        from kerbwolf.cli.kerberoast import _build_parser

        f = tmp_path / "targets.txt"
        f.write_text("from_file\n")
        parser = _build_parser()
        args = parser.parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-t", "from_flag", "-T", str(f)])
        targets = collect_targets(args)
        assert "from_flag" in targets
        assert "from_file" in targets


class TestKwRoastCLI:
    def test_help(self):
        from kerbwolf.cli.kerberoast import main

        with pytest.raises(SystemExit, match="0"):
            main(["--help"])

    def test_missing_domain(self):
        from kerbwolf.cli.kerberoast import main

        with pytest.raises(SystemExit):
            main(["--dc-ip", "1.2.3.4"])

    def test_missing_dc_ip(self):
        from kerbwolf.cli.kerberoast import main

        with pytest.raises(SystemExit):
            main(["-d", "D"])

    def test_enctype_short_flag(self):
        from kerbwolf.cli.kerberoast import _build_parser

        parser = _build_parser()
        for choice in ["des-cbc-crc", "des-cbc-md5", "rc4", "aes128", "aes256"]:
            args = parser.parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-e", choice])
            assert args.enctype == choice

    def test_invalid_enctype(self):
        from kerbwolf.cli.kerberoast import _build_parser

        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-e", "blowfish"])


class TestKwAsrepCLI:
    def test_help(self):
        from kerbwolf.cli.asreproast import main

        with pytest.raises(SystemExit, match="0"):
            main(["--help"])

    def test_targets(self):
        from kerbwolf.cli._common import collect_targets
        from kerbwolf.cli.asreproast import _build_parser

        parser = _build_parser()
        args = parser.parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-t", "user1", "-t", "user2"])
        assert collect_targets(args) == ["user1", "user2"]

    def test_targets_from_file(self, tmp_path):
        from kerbwolf.cli._common import collect_targets
        from kerbwolf.cli.asreproast import _build_parser

        f = tmp_path / "users.txt"
        f.write_text("alice\nbob\n# skip\n")
        parser = _build_parser()
        args = parser.parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-T", str(f)])
        targets = collect_targets(args)
        assert targets == ["alice", "bob"]


class TestKwExtractCLI:
    def test_help(self):
        from kerbwolf.cli.extract import main

        with pytest.raises(SystemExit, match="0"):
            main(["--help"])

    def test_requires_pcap(self):
        from kerbwolf.cli.extract import main

        with pytest.raises(SystemExit):
            main([])

    def test_multiple_pcaps(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["a.pcap", "b.pcapng"])
        assert args.pcap == ["a.pcap", "b.pcapng"]

    def test_stdin(self):
        from kerbwolf.cli.extract import _build_parser

        args = _build_parser().parse_args(["-"])
        assert args.pcap == ["-"]


class TestKwTgtCLI:
    def test_help(self):
        from kerbwolf.cli.gettgt import main

        with pytest.raises(SystemExit, match="0"):
            main(["--help"])

    def test_missing_user(self):
        from kerbwolf.cli.gettgt import main

        with pytest.raises(SystemExit):
            main(["-d", "D", "--dc-ip", "1.2.3.4"])

    def test_credential_flags_mutually_exclusive(self):
        from kerbwolf.cli.gettgt import _build_parser

        # Each credential flag works alone.
        args = _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "u", "-p", "pass"])
        assert args.password == "pass"
        args = _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "u", "-H", ":aabb"])
        assert args.hashes == ":aabb"
        args = _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "u", "--aes256-key", "ee" * 32])
        assert args.aes256_key == "ee" * 32

        # Two at once is rejected.
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-d", "D", "-u", "u", "-p", "pass", "-H", ":aabb"])

        # None is rejected.
        with pytest.raises(SystemExit):
            _build_parser().parse_args(["-d", "D", "-u", "u"])

    def test_enctype_all_choices(self):
        from kerbwolf.cli.gettgt import _build_parser

        for choice in ["des-cbc-crc", "des-cbc-md5", "rc4", "aes128", "aes256"]:
            args = _build_parser().parse_args(["-d", "D", "--dc-ip", "1.2.3.4", "-u", "u", "-p", "pass", "-e", choice])
            assert args.enctype == choice


class TestPrintHeader:
    def test_outputs_to_stderr(self, capsys):
        from kerbwolf.cli._common import print_header

        print_header("kw-test", [("Domain", "evil.corp"), ("DC", "10.0.0.1")])
        captured = capsys.readouterr()
        assert "evil.corp" in captured.err
        assert "10.0.0.1" in captured.err
        assert captured.out == ""

    def test_includes_version(self, capsys):
        from kerbwolf import __version__
        from kerbwolf.cli._common import print_header

        print_header("kw-test", [])
        captured = capsys.readouterr()
        assert __version__ in captured.err

    def test_field_alignment(self, capsys):
        from kerbwolf.cli._common import print_header

        print_header("kw-test", [("A", "1"), ("Longer", "2")])
        captured = capsys.readouterr()
        lines = captured.err.strip().split("\n")
        # Both field lines should have aligned colons
        field_lines = [l for l in lines if ":" in l and "kw-test" not in l]
        assert len(field_lines) == 2

    def test_empty_fields(self, capsys):
        from kerbwolf.cli._common import print_header

        print_header("kw-test", [])
        captured = capsys.readouterr()
        assert "kw-test" in captured.err


class TestOutputResults:
    def test_to_file(self, tmp_path, capsys):
        from kerbwolf.cli._common import output_results
        from kerbwolf.log import Logger
        from kerbwolf.models import EncryptionType, RoastResult

        results = [RoastResult(username="u", realm="R", spn="s", etype=EncryptionType.RC4_HMAC, hash_string="$krb5tgs$23$test", hashcat_mode=13100)]
        outfile = tmp_path / "out.txt"
        output_results(results, str(outfile), Logger())
        assert outfile.read_text().strip() == "$krb5tgs$23$test"
        assert "$krb5tgs$23$test" in capsys.readouterr().out

    def test_no_results(self, capsys):
        from kerbwolf.cli._common import output_results
        from kerbwolf.log import Logger

        output_results([], None, Logger())
        assert "No hashes" in capsys.readouterr().err

    def test_stdout_only(self, capsys):
        from kerbwolf.cli._common import output_results
        from kerbwolf.log import Logger
        from kerbwolf.models import EncryptionType, RoastResult

        results = [RoastResult(username="u", realm="R", spn="s", etype=EncryptionType.AES256_CTS_HMAC_SHA1_96, hash_string="$krb5tgs$18$test", hashcat_mode=19700)]
        output_results(results, None, Logger())
        assert "$krb5tgs$18$test" in capsys.readouterr().out
