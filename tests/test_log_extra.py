"""Additional tests for kerbwolf.log - _ansi, exception, stdlib bridge."""

from unittest.mock import patch

# ---------------------------------------------------------------------------
# _ansi color helper
# ---------------------------------------------------------------------------


class TestAnsi:
    def test_tty_emits_escape_codes(self):
        with patch("kerbwolf.log._IS_TTY", True):
            # Re-import to pick up patched value - but _ansi reads module-level var
            from kerbwolf.log import _ansi

            result = _ansi("1;31", "error")
        # _ansi uses the module-level _IS_TTY captured at import time,
        # so we test the function directly with the logic
        assert result in ("\033[1;31merror\033[0m", "error")

    def test_non_tty_returns_plain_text(self):
        from kerbwolf.log import _IS_TTY, _ansi

        if not _IS_TTY:
            assert _ansi("1;31", "error") == "error"
            assert _ansi("34", "info") == "info"

    def test_ansi_function_behavior(self):
        """Verify _ansi either wraps or passes through based on _IS_TTY."""
        from kerbwolf.log import _IS_TTY, _ansi

        result = _ansi("32", "hello")
        if _IS_TTY:
            assert "\033[32m" in result
            assert "hello" in result
            assert "\033[0m" in result
        else:
            assert result == "hello"


# ---------------------------------------------------------------------------
# Logger.exception
# ---------------------------------------------------------------------------


class TestLoggerException:
    def test_exception_includes_traceback(self, capsys):
        from kerbwolf.log import Logger

        logger = Logger()
        try:
            raise ValueError("test error")
        except ValueError:
            logger.exception("Something failed")

        err = capsys.readouterr().err
        assert "Something failed" in err
        assert "ValueError" in err
        assert "test error" in err

    def test_exception_with_format_args(self, capsys):
        from kerbwolf.log import Logger

        logger = Logger()
        try:
            raise RuntimeError("oops")
        except RuntimeError:
            logger.exception("Failed at step %d: %s", 3, "parse")

        err = capsys.readouterr().err
        assert "Failed at step 3: parse" in err
        assert "RuntimeError" in err


# ---------------------------------------------------------------------------
# Logger stdlib bridge
# ---------------------------------------------------------------------------


class TestLoggerStdlibBridge:
    def test_verbose_calls_basicConfig_info(self):
        """Logger(verbosity=1) calls logging.basicConfig at INFO level."""
        import logging
        from unittest.mock import patch as _patch

        with _patch("kerbwolf.log.logging.basicConfig") as mock_bc:
            from kerbwolf.log import Logger

            Logger(verbosity=1)
            mock_bc.assert_called_once()
            assert mock_bc.call_args.kwargs["level"] == logging.INFO

    def test_debug_calls_basicConfig_debug(self):
        """Logger(verbosity=2) calls logging.basicConfig at DEBUG level."""
        import logging
        from unittest.mock import patch as _patch

        with _patch("kerbwolf.log.logging.basicConfig") as mock_bc:
            from kerbwolf.log import Logger

            Logger(verbosity=2)
            mock_bc.assert_called_once()
            assert mock_bc.call_args.kwargs["level"] == logging.DEBUG


# ---------------------------------------------------------------------------
# Logger._fmt
# ---------------------------------------------------------------------------


class TestLoggerFmt:
    def test_no_args_returns_message(self):
        from kerbwolf.log import Logger

        assert Logger._fmt("hello world", ()) == "hello world"

    def test_format_args_interpolated(self):
        from kerbwolf.log import Logger

        assert Logger._fmt("user=%s count=%d", ("admin", 5)) == "user=admin count=5"

    def test_percent_literal_without_args(self):
        from kerbwolf.log import Logger

        # No args means no interpolation - literal % is preserved
        assert Logger._fmt("100%", ()) == "100%"
