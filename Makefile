.PHONY: test lint format typecheck check build clean install install-dev docs docs-serve

test:
	uv run pytest

lint:
	uv run ruff format --check .
	uv run ruff check .

format:
	uv run ruff format
	uv run ruff check --fix

typecheck:
	uv run ty check

check: lint typecheck test

build: check docs
	uv build --wheel

install:
	uv pip install .

install-dev:
	uv sync

docs:
	uv run --group docs mkdocs build --strict

docs-serve:
	uv run --group docs mkdocs serve

clean:
	rm -rf dist/ build/ *.egg-info site/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache .ty .cache
	find . -type f \( -name "*.pyc" -o -name "*.pyo" \) -delete 2>/dev/null || true
