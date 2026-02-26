# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# ---- Configuration ----
# Requires GNU Make 4.0+ (abspath). Portable per OP-017: run from any dir via
# make -f <path/to/Makefile> <target>
MKFILE_DIR := $(abspath $(lastword $(MAKEFILE_LIST)))
MKFILE_DIR := $(patsubst %/,%,$(dir $(MKFILE_DIR)))
SCRIPTS_DIR := $(MKFILE_DIR)/scripts
REUSE_SCRIPT := $(SCRIPTS_DIR)/ensure-reuse.sh
COVERAGE_SCRIPT := $(SCRIPTS_DIR)/coverage.sh
FUZZ_SCRIPT := $(SCRIPTS_DIR)/fuzz.sh
LINT_PYTHON_SCRIPT := $(SCRIPTS_DIR)/lint-python.sh
VENV_LINT := $(MKFILE_DIR)/.venv-lint
VENV_REUSE := $(MKFILE_DIR)/.venv-reuse
VENV_TEST := $(MKFILE_DIR)/.venv-test

.PHONY: help all debug release
.PHONY: setup setup-hooks check check-fast check-slow check-dco
.PHONY: check-headers check-header-duplicates headers
.PHONY: update-doc-diagrams check-doc-diagrams
.PHONY: cargo-check cargo-test unit-tests test-scripts
.PHONY: fmt fmt-check clippy
.PHONY: lint-python lint-shell
.PHONY: fuzz fuzz-changed fuzz-extended coverage coverage-quick
.PHONY: clean distclean

.DEFAULT_GOAL := help

# ---- Help ----
help:
	@echo "verilyze development targets:"
	@echo ""
	@echo "  Onboarding:"
	@echo "    make setup       - Bootstrap Python venvs (.venv-lint, .venv-test)"
	@echo "    make setup-hooks - Install git hooks (REUSE headers, DCO signoff)"
	@echo ""
	@echo "  Quick iteration:"
	@echo "    make cargo-check - Run cargo check"
	@echo "    make debug       - Build debug binary (after check-headers)"
	@echo "    make unit-tests  - Run cargo test + script tests"
	@echo ""
	@echo "  Full CI check:"
	@echo "    make check       - Headers, build, fmt, clippy, fuzz-changed, coverage-quick, lint"
	@echo "    make -j check    - Same, faster (runs independent targets in parallel)"
	@echo "    make check-fast  - Headers, build, fmt, clippy, lint only (~2-4 min)"
	@echo "    make check-slow  - Fuzz-changed + coverage-quick only (~5-10+ min)"
	@echo "    make check-dco   - Verify commits have DCO signoff (before push)"
	@echo ""
	@echo "  Lint:"
	@echo "    make check-headers     - Verify REUSE headers (lint + no duplicates)"
	@echo "    make check-header-duplicates - Verify no duplicate copyright holders"
	@echo "    make headers           - Add/update headers (mutates files)"
	@echo "    make update-doc-diagrams - Embed Mermaid diagrams into README/CONTRIBUTING"
	@echo "    make check-doc-diagrams  - Verify diagram content is in sync"
	@echo "    make fmt-check      - Verify Rust formatting (cargo fmt --check)"
	@echo "    make fmt           - Auto-format Rust code (cargo fmt)"
	@echo "    make clippy        - Run Clippy lints (all-targets, all-features)"
	@echo "    make lint-python   - black, pylint, mypy, bandit"
	@echo "    make lint-shell    - ShellCheck (requires shellcheck)"
	@echo ""
	@echo "  Advanced (slower):"
	@echo "    make fuzz         - AFL fuzz smoke test (needs cargo-afl, AFL++)"
	@echo "    make fuzz-changed  - Fuzz only targets for changed code (skip if none)"
	@echo "    make fuzz-extended - Fuzz all targets, extended timeout (30 min each)"
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
	@echo "  make setup-hooks # git hooks (REUSE headers, DCO signoff)"
	@echo "  make fuzz # needs cargo-afl, AFL++"
	@echo "  make coverage # runs fuzz first; needs cargo-llvm-cov"
	@echo "  make coverage-quick # coverage without fuzz (faster)"

setup-hooks:
	$(SCRIPTS_DIR)/install-hooks.sh

# ---- Headers ----
# check-header-duplicates: verify no duplicate copyright holders per .mailmap (DOC-013)
check-header-duplicates:
	cd "$(MKFILE_DIR)" && PYTHONPATH="$(MKFILE_DIR)" python3 $(SCRIPTS_DIR)/check_header_duplicates.py

# check-headers: verify REUSE compliance + no duplicate copyright holders
check-headers: check-header-duplicates
	@$(REUSE_SCRIPT) lint

# headers: add headers to covered text files (mutates files)
headers:
	python3 $(SCRIPTS_DIR)/update_headers.py

# ---- Build ----
cargo-check:
	cd "$(MKFILE_DIR)" && cargo check

debug: check-headers
	cd "$(MKFILE_DIR)" && cargo build

release: check-headers
	cd "$(MKFILE_DIR)" && cargo build --release

# ---- Tests ----
cargo-test:
	cd "$(MKFILE_DIR)" && cargo test

# Bootstrap .venv-test with pytest and pytest-cov (NFR-021)
$(VENV_TEST)/bin/pytest:
	python3 -m venv $(VENV_TEST)
	$(VENV_TEST)/bin/pip install pytest pytest-cov

test-scripts: $(VENV_TEST)/bin/pytest
	@cd "$(MKFILE_DIR)" && $(VENV_TEST)/bin/python -m pytest tests/scripts/ -v

unit-tests: cargo-test test-scripts

# ---- Lint ----
# Bootstrap .venv-lint with linters if missing
$(VENV_LINT)/bin/black:
	python3 -m venv $(VENV_LINT)
	$(VENV_LINT)/bin/pip install black pylint mypy bandit

# lint-python: black, pylint, mypy, bandit (aggregates failures; NFR-021)
lint-python: $(VENV_LINT)/bin/black
	$(LINT_PYTHON_SCRIPT)

# lint-shell: ShellCheck (NFR-022). Requires shellcheck.
lint-shell:
	shellcheck $(SCRIPTS_DIR)/*.sh

# fmt-check: verify Rust formatting without changes (used by make check)
fmt-check:
	cd "$(MKFILE_DIR)" && cargo fmt --check

# fmt: auto-format Rust code (run locally; CI uses fmt-check)
fmt:
	cd "$(MKFILE_DIR)" && cargo fmt

# clippy: Rust linter; fail on all warnings (NFR-008)
clippy:
	cd "$(MKFILE_DIR)" && RUSTFLAGS="-Dwarnings" cargo clippy --all-targets --all-features

# ---- Advanced (fuzz, coverage) ----
# fuzz: AFL smoke test (NFR-020, SEC-017). Requires cargo-afl and AFL++.
fuzz:
	$(FUZZ_SCRIPT)

# fuzz-changed: run only targets whose mapped files changed; skip if none.
fuzz-changed:
	$(FUZZ_SCRIPT) --changed

# fuzz-extended: run all targets with extended timeout (FUZZ_TIMEOUT=1800 by default).
fuzz-extended:
	$(FUZZ_SCRIPT) --extended

# coverage: Rust + script coverage; runs fuzz first (cargo-llvm-cov + AFL, NFR-012, NFR-020)
# coverage-quick: same but skips fuzz for faster dev iteration
# Prereqs: cargo-llvm-cov, rustup nightly, .venv-test (via setup)
coverage: setup fuzz
	$(COVERAGE_SCRIPT)

coverage-quick: setup
	$(COVERAGE_SCRIPT)

# ---- Doc diagrams ----
# Embed Mermaid diagrams from architecture/*.mmd into README and CONTRIBUTING
update-doc-diagrams:
	python3 $(SCRIPTS_DIR)/embed-diagrams.py README.md CONTRIBUTING.md

check-doc-diagrams:
	python3 $(SCRIPTS_DIR)/embed-diagrams.py --check README.md CONTRIBUTING.md

# check-dco: verify commits have Signed-off-by (DCO); for local use before push
check-dco:
	@cd "$(MKFILE_DIR)" && ./scripts/check-dco.sh

# ---- Check (full CI gate) ----
# check-fast: headers, build, fmt, clippy, lint (no coverage/fuzz; ~2-4 min)
check-fast: setup \
            check-headers \
            check-doc-diagrams \
            cargo-check fmt-check \
            clippy \
            lint-python \
            lint-shell

# check-slow: coverage and fuzz (~5-10+ min)
check-slow: setup fuzz-changed coverage-quick

# check: full pre-commit/CI gate (NFR-021, NFR-022, DOC-007)
check: setup \
       check-headers \
       check-doc-diagrams \
       cargo-check \
       fmt-check \
       clippy \
       lint-python \
       lint-shell \
       fuzz-changed \
       coverage-quick

# ---- Clean ----
clean:
	@cd "$(MKFILE_DIR)" && cargo clean
	@cd "$(MKFILE_DIR)" && cargo llvm-cov clean --workspace 2>/dev/null || true
	@find $(MKFILE_DIR) -type f \( -name "*.profraw" -o \
                                       -name "vlz-cache.redb" \) -delete
	@find $(MKFILE_DIR) -type d -name "__pycache__" -exec rm -rf {} +
	@rm -rfv $(MKFILE_DIR)/reports/ $(MKFILE_DIR)/.cache

distclean: clean
	@rm -rfv $(MKFILE_DIR)/.mypy_cache $(VENV_LINT) $(VENV_REUSE) $(VENV_TEST)

# ---- Default build ----
all: debug
