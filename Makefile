# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# ---- Configuration ----
SCRIPTS_DIR := scripts
REUSE_SCRIPT := $(SCRIPTS_DIR)/ensure-reuse.sh
COVERAGE_SCRIPT := $(SCRIPTS_DIR)/coverage.sh
FUZZ_SCRIPT := $(SCRIPTS_DIR)/fuzz.sh
LINT_PYTHON_SCRIPT := $(SCRIPTS_DIR)/lint-python.sh
VENV_LINT := .venv-lint
VENV_REUSE := .venv-reuse
VENV_TEST := .venv-test

.PHONY: help all debug release
.PHONY: setup setup-hooks check check-headers headers
.PHONY: update-doc-diagrams check-doc-diagrams
.PHONY: cargo-check cargo-test unit-tests test-scripts
.PHONY: lint-python lint-shell
.PHONY: fuzz coverage coverage-quick
.PHONY: clean distclean

.DEFAULT_GOAL := help

# ---- Help ----
help:
	@echo "super-duper development targets:"
	@echo ""
	@echo "  Onboarding:"
	@echo "    make setup       - Bootstrap Python venvs (.venv-lint, .venv-test)"
	@echo "    make setup-hooks - Install git pre-commit hook (REUSE headers)"
	@echo ""
	@echo "  Quick iteration:"
	@echo "    make cargo-check - Run cargo check"
	@echo "    make debug       - Build debug binary (after check-headers)"
	@echo "    make unit-tests  - Run cargo test + script tests"
	@echo ""
	@echo "  Full CI check:"
	@echo "    make check       - Headers, build, tests, lint (pre-commit gate)"
	@echo ""
	@echo "  Lint:"
	@echo "    make check-headers     - Verify REUSE headers"
	@echo "    make headers           - Add/update headers (mutates files)"
	@echo "    make update-doc-diagrams - Embed Mermaid diagrams into README/CONTRIBUTING"
	@echo "    make check-doc-diagrams  - Verify diagram content is in sync"
	@echo "    make lint-python   - black, pylint, mypy, bandit"
	@echo "    make lint-shell    - ShellCheck (requires shellcheck)"
	@echo ""
	@echo "  Advanced (slower):"
	@echo "    make fuzz         - AFL fuzz smoke test (needs cargo-afl, AFL++)"
	@echo "    make coverage     - Coverage report (runs fuzz first; needs cargo-llvm-cov)"
	@echo "    make coverage-quick - Coverage without fuzz (faster dev iteration)"
	@echo ""
	@echo "  Clean:"
	@echo "    make clean      - Remove build artifacts, reports"
	@echo "    make distclean  - clean + remove venvs"
	@echo ""
	@echo "  Other:"
	@echo "    make all       - Build release-ready (debug build)"
	@echo "    make release   - Build release binary"

# ---- Setup & environment ----
# Prepare dev environment: bootstrap Python venvs for lint and tests.
# System deps (rust, python3, shellcheck, afl++) must be installed separately;
# see CONTRIBUTING.md "Quick setup".
setup: $(VENV_LINT)/bin/black $(VENV_TEST)/bin/pytest
	@echo "Dev environment ready. Run: make check"
	@echo "Recommended:"
	@echo "  make setup-hooks # git pre-commit (auto update file headers)"
	@echo "  make fuzz # needs cargo-afl, AFL++"
	@echo "  make coverage # runs fuzz first; needs cargo-llvm-cov"
	@echo "  make coverage-quick # coverage without fuzz (faster)"

setup-hooks:
	./$(SCRIPTS_DIR)/install-hooks.sh

# ---- Headers ----
# check-headers: verify REUSE compliance (exit nonzero if any file missing header)
check-headers:
	@./$(REUSE_SCRIPT) lint

# headers: add headers to covered text files (mutates files)
headers:
	python3 $(SCRIPTS_DIR)/update_headers.py

# ---- Build ----
cargo-check:
	cargo check

debug: check-headers
	cargo build

release: check-headers
	cargo build --release

# ---- Tests ----
cargo-test:
	cargo test

# Bootstrap .venv-test with pytest and pytest-cov (NFR-021)
$(VENV_TEST)/bin/pytest:
	python3 -m venv $(VENV_TEST)
	$(VENV_TEST)/bin/pip install pytest pytest-cov

test-scripts: $(VENV_TEST)/bin/pytest lint-shell
	@$(VENV_TEST)/bin/python -m pytest tests/scripts/ -v

unit-tests: cargo-test test-scripts

# ---- Lint ----
# Bootstrap .venv-lint with linters if missing
$(VENV_LINT)/bin/black:
	python3 -m venv $(VENV_LINT)
	$(VENV_LINT)/bin/pip install black pylint mypy bandit

# lint-python: black, pylint, mypy, bandit (aggregates failures; NFR-021)
lint-python: $(VENV_LINT)/bin/black
	./$(LINT_PYTHON_SCRIPT)

# lint-shell: ShellCheck (NFR-022). Requires shellcheck.
lint-shell:
	shellcheck $(SCRIPTS_DIR)/*.sh

# ---- Advanced (fuzz, coverage) ----
# fuzz: AFL smoke test (NFR-020, SEC-017). Requires cargo-afl and AFL++.
fuzz:
	./$(FUZZ_SCRIPT)

# coverage: Rust + script coverage; runs fuzz first (cargo-llvm-cov + AFL, NFR-012, NFR-020)
# coverage-quick: same but skips fuzz for faster dev iteration
# Prereqs: cargo-llvm-cov, rustup nightly, .venv-test (via setup)
coverage: fuzz
	./$(COVERAGE_SCRIPT)

coverage-quick:
	./$(COVERAGE_SCRIPT)

# ---- Doc diagrams ----
# Embed Mermaid diagrams from architecture/*.mmd into README and CONTRIBUTING
update-doc-diagrams:
	python3 $(SCRIPTS_DIR)/embed-diagrams.py README.md CONTRIBUTING.md

check-doc-diagrams:
	python3 $(SCRIPTS_DIR)/embed-diagrams.py --check README.md CONTRIBUTING.md

# ---- Check (full CI gate) ----
# check: full pre-commit/CI gate (NFR-021, NFR-022, DOC-007)
check: check-headers check-doc-diagrams cargo-check unit-tests lint-python lint-shell

# ---- Clean ----
clean:
	@cargo clean
	@cargo llvm-cov clean --workspace 2>/dev/null || true
	@find . -name "*.profraw" -delete
	@find . -name spd-cache.redb -delete
	@rm -rfv reports/ .mypy_cache .cache

distclean: clean
	@rm -rfv .mypy_cache $(VENV_LINT) $(VENV_REUSE) $(VENV_TEST)

# ---- Default build ----
all: debug
