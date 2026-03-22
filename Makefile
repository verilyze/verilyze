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
# Override for CI or a pinned binary (NFR-009, SEC-012).
CARGO_DENY ?= cargo deny

.PHONY: help all debug release
.PHONY: setup setup-hooks check check-fast check-slow check-dco check-signatures
.PHONY: check-headers check-header-duplicates headers
.PHONY: update-doc-diagrams check-doc-diagrams
.PHONY: cargo-check cargo-test unit-tests test-scripts
.PHONY: fmt fmt-check clippy
.PHONY: lint-python lint-shell super-linter super-linter-full
.PHONY: fuzz fuzz-changed fuzz-extended coverage coverage-quick
.PHONY: generate-config-example check-config-docs
.PHONY: generate-completions completions completions-release check-completions
.PHONY: generate-packaging check-packaging
.PHONY: sync-license-config check-license-config deny-check
.PHONY: generate-third-party-licenses generate-third-party-licenses-docker
.PHONY: check-third-party-licenses
.PHONY: deb rpm aur apk docker
.PHONY: install clean distclean

.DEFAULT_GOAL := help

# ---- Help ----
help:
	@echo "verilyze development targets:"
	@echo ""
	@echo "  Onboarding:"
	@echo "    make setup       - Bootstrap Python venvs (.venv-lint, .venv-test)"
	@echo "    make setup-hooks - Install git hooks (REUSE headers, DCO signoff, signature check)"
	@echo ""
	@echo "  Quick iteration:"
	@echo "    make cargo-check - Run cargo check"
	@echo "    make debug       - Build debug binary (after check-headers)"
	@echo "    make unit-tests  - Run cargo test + script tests"
	@echo ""
	@echo "  Full CI check:"
	@echo "    make check       - Headers, build, fmt, clippy, cargo-deny, fuzz-changed, coverage-quick, lint"
	@echo "    make -j check    - Same, faster (runs independent targets in parallel)"
	@echo "    make check-fast  - Headers, build, fmt, clippy, cargo-deny, lint only (~2-4 min)"
	@echo "    make check-slow  - Fuzz-changed + coverage-quick only (~5-10+ min)"
	@echo "    make check-dco   - Verify commits have DCO signoff (before push)"
	@echo "    make check-signatures - Verify commits are signed (before push)"
	@echo ""
	@echo "  Lint:"
	@echo "    make check-headers     - Verify REUSE headers (lint + no duplicates)"
	@echo "    make check-header-duplicates - Verify no duplicate copyright holders"
	@echo "    make headers           - Add/update headers (mutates files)"
	@echo "    make update-doc-diagrams - Embed Mermaid diagrams into README/CONTRIBUTING"
	@echo "    make check-doc-diagrams  - Verify diagram content is in sync"
	@echo "    make generate-config-example - Generate verilyze.conf.example, docs, man page"
	@echo "    make check-config-docs   - Verify config docs are in sync"
	@echo "    make generate-completions - Generate shell completions (bash, zsh, fish)"
	@echo "    make check-completions   - Verify completions are in sync"
	@echo "    make generate-packaging  - Update packaging specs with version from Cargo.toml"
	@echo "    make check-packaging     - Verify packaging versions are in sync"
	@echo "    make sync-license-config - Sync deny.toml [licenses] allow to about.toml accepted"
	@echo "    make check-license-config - Verify about.toml accepted matches deny.toml"
	@echo "    make deny-check       - cargo deny check (licenses, advisories, bans, sources)"
	@echo "    make generate-third-party-licenses - Generate THIRD-PARTY-LICENSES for packaging"
	@echo "    make check-third-party-licenses - Verify THIRD-PARTY-LICENSES is up to date"
	@echo "    make fmt-check      - Verify Rust formatting (cargo fmt --check)"
	@echo "    make fmt           - Auto-format Rust code (cargo fmt)"
	@echo "    make clippy        - Run Clippy lints (all-targets, all-features)"
	@echo "    make lint-python   - black, pylint, mypy, bandit"
	@echo "    make lint-shell    - ShellCheck (requires shellcheck)"
	@echo "    make super-linter  - super-linter slim (Docker; incremental)"
	@echo "    make super-linter-full - super-linter slim full tree (like nightly CI)"
	@echo ""
	@echo "  Advanced (slower):"
	@echo "    make fuzz         - AFL fuzz smoke test (needs cargo-afl, AFL++)"
	@echo "    make fuzz-changed  - Fuzz only targets for changed code (skip if none)"
	@echo "    make fuzz-extended - Fuzz all targets, extended timeout (30 min each)"
	@echo "    make coverage     - Coverage report (runs fuzz first; needs cargo-llvm-cov)"
	@echo "    make coverage-quick - Coverage without fuzz (faster dev iteration)"
	@echo ""
	@echo "  Packaging (OP-013):"
	@echo "    make deb        - Build .deb package (needs cargo-deb)"
	@echo "    make rpm        - Build .rpm package (needs rpmbuild)"
	@echo "    make aur        - Build AUR tarball + PKGBUILD (needs cargo-aur)"
	@echo "    make apk        - Build Alpine APK (needs abuild, Alpine env)"
	@echo "    make docker     - Build Docker image (needs docker)"
	@echo ""
	@echo "  Clean:"
	@echo "    make clean      - Remove build artifacts, reports"
	@echo "    make distclean  - clean + remove venvs"
	@echo ""
	@echo "  Other:"
	@echo "    make all       - Build release-ready (debug build)"
	@echo "    make release   - Build release binary"
	@echo "    make install   - Install binary, config example, man page (PREFIX=/usr/local)"

# ---- Setup & environment ----
# Prepare dev environment: bootstrap Python venvs for lint and tests.
# System deps (rust, python3, shellcheck, afl++) must be installed separately;
# see CONTRIBUTING.md "Quick setup".
setup: $(VENV_LINT)/bin/black $(VENV_TEST)/bin/pytest
	@echo "Dev environment ready. Run: make check"
	@echo "Recommended:"
	@echo "  make setup-hooks # git hooks (REUSE headers, DCO signoff, signature check)"
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

# Binary path: use cargo metadata to respect CARGO_TARGET_DIR.
VLZ_DEBUG := $(shell cd "$(MKFILE_DIR)" && cargo metadata --no-deps --format-version 1 2>/dev/null | \
  sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1)/debug/vlz
VLZ_RELEASE := $(shell cd "$(MKFILE_DIR)" && cargo metadata --no-deps --format-version 1 2>/dev/null | \
  sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1)/release/vlz

# Implicit rule: when completions need the binary, build it.
$(VLZ_DEBUG):
	cd "$(MKFILE_DIR)" && cargo build -p vlz

debug: check-headers
	cd "$(MKFILE_DIR)" && cargo build
	$(MAKE) -C "$(MKFILE_DIR)" -f "$(MKFILE_DIR)/Makefile" completions

release: check-headers
	cd "$(MKFILE_DIR)" && cargo build --release

# ---- Shell completions (FR-028) ----
# Incremental: only regenerate when binary is newer than completion files.
# Uses scripts/generate_completions.sh (DRY: same script used by packaging).
completions: completions/vlz.bash completions/_vlz completions/vlz.fish

completions/vlz.bash completions/_vlz completions/vlz.fish: $(VLZ_DEBUG)
	cd "$(MKFILE_DIR)" && $(SCRIPTS_DIR)/generate_completions.sh "$(VLZ_DEBUG)"

generate-completions: $(VLZ_DEBUG)
	cd "$(MKFILE_DIR)" && $(SCRIPTS_DIR)/generate_completions.sh "$(VLZ_DEBUG)"

# Completions from release binary; used by packaging targets (deb, etc.).
completions-release: release
	cd "$(MKFILE_DIR)" && $(SCRIPTS_DIR)/generate_completions.sh "$(VLZ_RELEASE)"

check-completions: debug
	@cd "$(MKFILE_DIR)" && git diff --exit-code completions/ || \
		(echo "Completions out of sync; run make generate-completions and commit." && exit 1)

# ---- Tests ----
cargo-test:
	cd "$(MKFILE_DIR)" && cargo test --features vlz/testing

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
	shellcheck $(SCRIPTS_DIR)/*.sh "$(MKFILE_DIR)/completions/vlz.bash"

# super-linter: Docker slim image; VALIDATE_ALL_CODEBASE=false (changed files only).
super-linter:
	cd "$(MKFILE_DIR)" && VALIDATE_ALL_CODEBASE=false $(SCRIPTS_DIR)/super-linter.sh

# super-linter-full: full tree scan (parity with scheduled GitHub workflow).
super-linter-full:
	cd "$(MKFILE_DIR)" && VALIDATE_ALL_CODEBASE=true $(SCRIPTS_DIR)/super-linter.sh

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

# generate-config-example: produce verilyze.conf.example, docs/configuration.md, man/verilyze.conf.5
# Uses .venv-test for pytest (generate_config_example uses stdlib tomllib).
generate-config-example: debug $(VENV_TEST)/bin/pytest
	$(VENV_TEST)/bin/python $(SCRIPTS_DIR)/generate_config_example.py

# check-config-docs: verify config docs are in sync (CI)
check-config-docs: debug $(VENV_TEST)/bin/pytest
	$(VENV_TEST)/bin/python $(SCRIPTS_DIR)/generate_config_example.py --check

# generate-packaging: Update APKBUILD and PKGBUILD with version from Cargo.toml.
# Run after bumping version; required before make apk.
generate-packaging:
	python3 $(SCRIPTS_DIR)/generate_packaging_versions.py

# check-packaging: Verify packaging spec versions match Cargo.toml.
check-packaging:
	python3 $(SCRIPTS_DIR)/generate_packaging_versions.py --check

# sync-license-config: Copy deny.toml [licenses] allow to about.toml accepted.
sync-license-config:
	cd "$(MKFILE_DIR)" && python3 $(SCRIPTS_DIR)/sync_license_config.py

# check-license-config: Fail if about.toml accepted is out of sync with deny.toml.
check-license-config:
	cd "$(MKFILE_DIR)" && python3 $(SCRIPTS_DIR)/sync_license_config.py --check

# deny-check: dependency policy via deny.toml (NFR-009, SEC-012).
deny-check:
	cd "$(MKFILE_DIR)" && $(CARGO_DENY) check

# generate-third-party-licenses: Produce THIRD-PARTY-LICENSES for Docker and packages.
# Syncs license config first, then runs cargo-about.
# Uses cargo-about (cargo install cargo-about). For Docker build use --no-default-features
# --features docker; for default build omit those flags.
generate-third-party-licenses: sync-license-config
	cd "$(MKFILE_DIR)" && cargo about generate -o THIRD-PARTY-LICENSES --fail \
		-c about.toml -m crates/core/vlz/Cargo.toml about.hbs

generate-third-party-licenses-docker: sync-license-config
	cd "$(MKFILE_DIR)" && cargo about generate -o THIRD-PARTY-LICENSES --fail \
		-c about.toml -m crates/core/vlz/Cargo.toml --no-default-features --features docker about.hbs

# check-third-party-licenses: Regenerate THIRD-PARTY-LICENSES and fail if it differs from committed.
check-third-party-licenses: sync-license-config
	cd "$(MKFILE_DIR)" && cargo about generate -o THIRD-PARTY-LICENSES --fail \
		-c about.toml -m crates/core/vlz/Cargo.toml about.hbs
	@cd "$(MKFILE_DIR)" && git diff --exit-code THIRD-PARTY-LICENSES || \
		(echo "THIRD-PARTY-LICENSES is out of sync. Run: make generate-third-party-licenses" && exit 1)

# check-dco: verify commits have Signed-off-by (DCO); for local use before push
check-dco:
	@cd "$(MKFILE_DIR)" && ./scripts/check-dco.sh

# check-signatures: verify commits are signed (GPG or SSH); for local use
# before push. Uses strict mode (requires valid signature, not just presence).
check-signatures:
	@cd "$(MKFILE_DIR)" && ./scripts/check-signatures.sh

# ---- Check (full CI gate) ----
# check-fast: headers, build, fmt, clippy, cargo-deny, lint (no coverage/fuzz; ~2-4 min)
check-fast: setup \
            check-headers \
            check-doc-diagrams \
            check-config-docs \
            check-packaging \
            check-completions \
            check-license-config \
            deny-check \
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
       check-config-docs \
       check-packaging \
       check-completions \
       check-license-config \
       deny-check \
       check-third-party-licenses \
       cargo-check \
       fmt-check \
       clippy \
       lint-python \
       lint-shell \
       fuzz-changed \
       coverage-quick

# ---- Install ----
# Optional: install binary, verilyze.conf.example, and man page.
# PREFIX=/usr/local, DESTDIR= for staged installs.
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
MANDIR := $(PREFIX)/share/man
DOCDIR := $(PREFIX)/share/doc/verilyze

BASH_COMPLETION_DIR := $(PREFIX)/share/bash-completion/completions
ZSH_SITE_FUNCTIONS := $(PREFIX)/share/zsh/site-functions
FISH_VENDOR_COMPLETIONS := $(PREFIX)/share/fish/vendor_completions.d

install: release generate-config-example completions
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 755 "$(MKFILE_DIR)/target/release/vlz" "$(DESTDIR)$(BINDIR)/vlz"
	install -d "$(DESTDIR)$(DOCDIR)"
	install -m 644 "$(MKFILE_DIR)/verilyze.conf.example" "$(DESTDIR)$(DOCDIR)/"
	install -d "$(DESTDIR)$(MANDIR)/man1"
	install -d "$(DESTDIR)$(MANDIR)/man5"
	install -m 644 "$(MKFILE_DIR)/man/vlz.1" "$(DESTDIR)$(MANDIR)/man1/"
	install -m 644 "$(MKFILE_DIR)/man/verilyze.conf.5" "$(DESTDIR)$(MANDIR)/man5/"
	install -d "$(DESTDIR)$(BASH_COMPLETION_DIR)"
	install -m 644 "$(MKFILE_DIR)/completions/vlz.bash" "$(DESTDIR)$(BASH_COMPLETION_DIR)/vlz"
	install -d "$(DESTDIR)$(ZSH_SITE_FUNCTIONS)"
	install -m 644 "$(MKFILE_DIR)/completions/_vlz" "$(DESTDIR)$(ZSH_SITE_FUNCTIONS)/"
	install -d "$(DESTDIR)$(FISH_VENDOR_COMPLETIONS)"
	install -m 644 "$(MKFILE_DIR)/completions/vlz.fish" "$(DESTDIR)$(FISH_VENDOR_COMPLETIONS)/"
	@if [ -z "$(DESTDIR)" ] && [ ! -f /etc/verilyze.conf ]; then \
		echo "Installing /etc/verilyze.conf from example (file did not exist)"; \
		install -d /etc 2>/dev/null || true; \
		install -m 644 "$(MKFILE_DIR)/verilyze.conf.example" /etc/verilyze.conf 2>/dev/null || \
		echo "Note: could not install /etc/verilyze.conf (run as root or copy manually)"; \
	fi

# ---- Packaging (OP-013) ----
# Read workspace version from root Cargo.toml for packaging.
PKG_VERSION := $(shell cd "$(MKFILE_DIR)" && \
  grep -E '^\s*version\s*=' Cargo.toml | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
PKG_NAME := verilyze
RPM_TOPDIR := $(MKFILE_DIR)/packaging/rpm

# deb: Build .deb via cargo-deb. Requires: cargo install cargo-deb
deb: completions-release
	cd "$(MKFILE_DIR)" && cargo deb -p vlz --no-build

# rpm: Build .rpm via rpmbuild. Requires: rpmbuild (rpm-build package).
# Generates a source tarball from git (committed state only). Commit all
# changes before running make rpm.
rpm: release
	@mkdir -p "$(RPM_TOPDIR)/SOURCES"
	cd "$(MKFILE_DIR)" && git archive --format=tar.gz \
	  --prefix=$(PKG_NAME)-$(PKG_VERSION)/ \
	  -o "$(RPM_TOPDIR)/SOURCES/$(PKG_NAME)-$(PKG_VERSION).tar.gz" HEAD
	rpmbuild -ba "$(RPM_TOPDIR)/SPECS/verilyze.spec" \
	  --define "_topdir $(RPM_TOPDIR)" \
	  --define "version $(PKG_VERSION)" \
	  --nodeps

# aur: Generate PKGBUILD + tarball via cargo-aur. Requires: cargo install cargo-aur
aur:
	cd "$(MKFILE_DIR)" && cargo aur

# apk: Build Alpine APK. Requires Alpine build environment (abuild, alpine-sdk).
# Run inside an Alpine container or chroot. Regenerates packaging versions first.
apk: generate-packaging
	cd "$(MKFILE_DIR)/packaging/alpine" && abuild checksum && abuild -r

# docker: Build Docker image from scratch (FR-025, OP-013).
docker:
	cd "$(MKFILE_DIR)" && docker build \
	  -f packaging/docker/Dockerfile \
	  -t $(PKG_NAME):$(PKG_VERSION) \
	  -t $(PKG_NAME):latest .

# ---- Clean ----
clean:
	@cd "$(MKFILE_DIR)" && cargo clean
	@cd "$(MKFILE_DIR)" && cargo llvm-cov clean --workspace 2>/dev/null || true
	@find $(MKFILE_DIR) -type f \( -name "*.profraw" -o \
                                       -name "vlz-cache.redb" \) -delete
	@find $(MKFILE_DIR) -type d -name "__pycache__" -exec rm -rf {} +
	@rm -rfv $(MKFILE_DIR)/reports/ $(MKFILE_DIR)/.cache
	@rm -rfv $(RPM_TOPDIR)/BUILD $(RPM_TOPDIR)/BUILDROOT \
	         $(RPM_TOPDIR)/RPMS $(RPM_TOPDIR)/SRPMS \
	         $(RPM_TOPDIR)/SOURCES/*.tar.gz

distclean: clean
	@rm -rfv $(MKFILE_DIR)/.mypy_cache $(MKFILE_DIR)/.tmp-empty-xdg $(VENV_LINT) $(VENV_REUSE) $(VENV_TEST)

# ---- Default build ----
all: debug
