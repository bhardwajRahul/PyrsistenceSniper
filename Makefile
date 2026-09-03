.PHONY: all lint format fix typecheck test cov clean

PACKAGE := pyrsistencesniper/
SOURCES := pyrsistencesniper/ tests/

all: fix typecheck test

lint:
	poetry run ruff check $(SOURCES)

format:
	poetry run ruff format $(SOURCES)

fix: format
	poetry run ruff check --fix $(SOURCES)

typecheck:
	poetry run mypy $(PACKAGE)

test:
	poetry run pytest

cov:
	poetry run pytest --cov=pyrsistencesniper --cov-branch --cov-report=term-missing

clean:
	find . -type d \( -name __pycache__ -o -name .mypy_cache -o -name .pytest_cache \) -exec rm -rf {} + 2>/dev/null || true
	rm -rf .coverage htmlcov/
