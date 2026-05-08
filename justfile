# iStrix build and development commands

default: help

help:
    @just --list

install:
    python3 -m venv .venv
    .venv/bin/pip install -e ".[all]"
    @echo "iStrix installed. Activate: source .venv/bin/activate"

install-minimal:
    python3 -m venv .venv
    .venv/bin/pip install -e "."
    @echo "iStrix (minimal) installed."

test:
    .venv/bin/python -m pytest tests/ -v

test-cov:
    .venv/bin/python -m pytest tests/ -v --cov=istrix --cov-report=term-missing

lint:
    .venv/bin/ruff check src/

format:
    .venv/bin/ruff format src/

clean:
    rm -rf build/ dist/ *.egg-info .venv/ .pytest_cache/ __pycache__/ src/**/__pycache__/

build:
    .venv/bin/python -m build

smoke-test:
    .venv/bin/istrix scan 127.0.0.1 --tier quick
