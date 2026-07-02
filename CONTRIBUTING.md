# Contributing to KerbWolf

Thanks for your interest in improving KerbWolf. This document covers how to get set up and what's expected in a pull request.

## Getting started

```bash
git clone https://github.com/StrongWind1/KerbWolf.git
cd KerbWolf
uv sync          # install dependencies + dev tools
```

This project uses [uv](https://docs.astral.sh/uv/) for everything. Do not use bare `pip` or `python` — always go through `uv`.

## Development workflow

```bash
make test        # run tests
make lint        # ruff check + ruff format check
make typecheck   # ty check
make check       # all of the above + docs build
```

Or without Make:

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
uv run ty check
```

## Code style

- Python 3.11+ — use modern syntax (type unions with `|`, `match`, etc.).
- All code is linted with [Ruff](https://docs.astral.sh/ruff/) (`select = ["ALL"]` with targeted ignores).
- Type-checked with [ty](https://github.com/astral-sh/ty).
- Line length limit is 320 (effectively unlimited) — use judgment.
- Run `make format` to auto-fix before committing, or install the pre-commit hooks with `uv run pre-commit install`.

## Submitting a pull request

1. Fork the repo and create a branch from `main`.
2. Make your changes and add tests.
3. Run `make check` and ensure everything passes.
4. Open a PR against `main` with a clear description of what and why.

## Reporting bugs

Use the [bug report template](https://github.com/StrongWind1/KerbWolf/issues/new?template=bug_report.md). Include the exact command, full output, and your environment details.

## Reporting security issues

Do not open a public issue for security reports. See [SECURITY.md](SECURITY.md) for the private disclosure process.
