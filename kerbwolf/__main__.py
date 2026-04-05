"""Allow ``python -m kerbwolf`` to launch the kerberoast CLI by default."""

from __future__ import annotations

from kerbwolf.cli.kerberoast import main  # default: kw-roast

if __name__ == "__main__":
    main()
