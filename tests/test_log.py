"""Tests for kerbwolf.log - structured ANSI logger."""

from kerbwolf.log import DEBUG, VERBOSE, Logger


class TestLoggerVerbosity:
    def test_default_verbosity_is_zero(self):
        logger = Logger()
        assert logger.verbosity == 0

    def test_custom_verbosity(self):
        logger = Logger(verbosity=2)
        assert logger.verbosity == 2

    def test_debug_suppressed_at_zero(self, capsys):
        logger = Logger(verbosity=0)
        logger.debug("hidden")
        assert capsys.readouterr().err == ""

    def test_debug_suppressed_at_verbose(self, capsys):
        logger = Logger(verbosity=VERBOSE)
        logger.debug("hidden")
        assert capsys.readouterr().err == ""

    def test_debug_shown_at_debug(self, capsys):
        logger = Logger(verbosity=DEBUG)
        logger.debug("visible")
        assert "visible" in capsys.readouterr().err

    def test_verbose_suppressed_at_zero(self, capsys):
        logger = Logger(verbosity=0)
        logger.verbose("hidden")
        assert capsys.readouterr().err == ""

    def test_verbose_shown_at_verbose(self, capsys):
        logger = Logger(verbosity=VERBOSE)
        logger.verbose("visible")
        assert "visible" in capsys.readouterr().err

    def test_verbose_shown_at_debug(self, capsys):
        logger = Logger(verbosity=DEBUG)
        logger.verbose("visible")
        assert "visible" in capsys.readouterr().err


class TestLoggerAlwaysShown:
    def test_info_at_zero(self, capsys):
        Logger(verbosity=0).info("msg")
        assert "msg" in capsys.readouterr().err

    def test_success_at_zero(self, capsys):
        Logger(verbosity=0).success("msg")
        assert "msg" in capsys.readouterr().err

    def test_warning_at_zero(self, capsys):
        Logger(verbosity=0).warning("msg")
        assert "msg" in capsys.readouterr().err

    def test_error_at_zero(self, capsys):
        Logger(verbosity=0).error("msg")
        assert "msg" in capsys.readouterr().err


class TestLoggerFormatting:
    def test_lazy_format_string(self, capsys):
        Logger(verbosity=0).info("user=%s count=%d", "admin", 42)
        assert "user=admin count=42" in capsys.readouterr().err

    def test_no_args_no_format(self, capsys):
        Logger(verbosity=0).info("plain message")
        assert "plain message" in capsys.readouterr().err

    def test_fmt_static_no_args(self):
        assert Logger._fmt("hello", ()) == "hello"

    def test_fmt_static_with_args(self):
        assert Logger._fmt("x=%s", ("y",)) == "x=y"

    def test_fmt_multiple_args(self):
        assert Logger._fmt("%s:%d", ("a", 1)) == "a:1"
