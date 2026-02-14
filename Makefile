# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

.PHONY: headers check-headers setup-hooks check clean distclean unit-tests \
	cargo-test test-scripts cargo-check coverage lint-python lint-shell
DEFAULT: all

# add headers to covered text files (mutates files)
headers:
	python3 scripts/update_headers.py

# Lint Python scripts (black, pylint, mypy, bandit).
# Bootstrap .venv-lint with linters if missing
.venv-lint/bin/black:
	python3 -m venv .venv-lint
	.venv-lint/bin/pip install black pylint mypy bandit

lint-python: .venv-lint/bin/black
	@V=.venv-lint/bin; ERR=0; \
	B=$${V}/black; [ -x "$$B" ] || B=black; \
	"$$B" scripts/ --check --line-length 79 || ERR=1; \
	P=$${V}/pylint; [ -x "$$P" ] || P=pylint; \
	"$$P" scripts/ --max-line-length=79 || ERR=1; \
	M=$${V}/mypy; [ -x "$$M" ] || M=mypy; \
	"$$M" scripts/ || ERR=1; \
	X=$${V}/bandit; [ -x "$$X" ] || X=bandit; \
	"$$X" -r scripts/ || ERR=1; \
	exit $$ERR

# Lint shell scripts (NFR-022). Requires shellcheck.
lint-shell:
	shellcheck scripts/*.sh

# check-only (exit nonzero if any file missing header)
check-headers:
	@./scripts/ensure-reuse.sh lint

# install git hooks (REUSE headers on new files)
setup-hooks:
	./scripts/install-hooks.sh

cargo-check:
	cargo check

cargo-test:
	cargo test

# Run script tests (NFR-021). Requires pytest; create .venv-test with dev deps
# if needed: python3 -m venv .venv-test && .venv-test/bin/pip install -e ".[dev]"
test-scripts:
	@V=.venv-test/bin; P=$${V}/python; [ -x "$$P" ] || P=python3; \
	"$$P" -m pytest tests/scripts/ -v

unit-tests: cargo-test test-scripts

# Generate Cobertura XML (see CONTRIBUTING.md and NFR-012) and HTML coverage
# reports.
coverage: fuzz
	./scripts/coverage.sh

# AFL fuzz targets (NFR-020). Requires cargo-afl and AFL++.
fuzz:
	./scripts/fuzz.sh

check: check-headers cargo-check unit-tests lint-python lint-shell

debug: check-headers
	cargo build

release: check-headers
	cargo build --release

clean:
	@cargo clean
	@cargo llvm-cov clean --workspace 2>/dev/null || true
	@find . -name "*.profraw" -delete
	@find . -name spd-cache.redb -delete
	@rm -rfv reports/ .mypy_cache .cache

distclean: clean
	@rm -rfv .mypy_cache .venv-lint .venv-reuse .venv-test

all: debug
