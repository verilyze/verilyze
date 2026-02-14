# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

.PHONY: headers check-headers setup-hooks check clean unit-tests cargo-check coverage
DEFAULT: all

# add headers to covered text files (mutates files)
headers:
	./scripts/update-headers.sh

# check-only (exit nonzero if any file missing header)
check-headers:
	@./scripts/ensure-reuse.sh lint

# install git hooks (REUSE headers on new files)
setup-hooks:
	./scripts/install-hooks.sh

cargo-check:
	cargo check

unit-tests:
	cargo test

# Generate Cobertura XML (see CONTRIBUTING.md and NFR-012) and HTML coverage
# reports.
coverage: fuzz
	./scripts/coverage.sh

# AFL fuzz targets (NFR-020). Requires cargo-afl and AFL++.
fuzz:
	./scripts/fuzz.sh

check: check-headers cargo-check unit-tests

debug: check-headers
	cargo build

release: check-headers
	cargo build --release

clean:
	cargo clean
	cargo llvm-cov clean --workspace 2>/dev/null || true
	find . -name "*.profraw" -delete
	find . -name spd-cache.redb -delete
	rm -rf reports/

all: debug
