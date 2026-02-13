.PHONY: headers check-headers check clean unit-tests cargo-check coverage
DEFAULT: all

# installs the xtask binary locally
install-xtask:
	cargo install --path tools/xtask

# equivalent one-time install helper
setup: install-xtask

# add headers to source files (mutates files)
headers: setup
	cargo run -p xtask -- replace

# check-only (exit nonzero if any file missing header)
check-headers: setup
	cargo run -p xtask -- check

cargo-check:
	cargo check

unit-tests:
	cargo test

# Generate Cobertura XML (see CONTRIBUTING.md and NFR-012) and HTML coverage reports.
coverage: fuzz
	./scripts/coverage.sh

# AFL fuzz targets (NFR-020). Requires cargo-afl and AFL++.
fuzz:
	./scripts/fuzz.sh

check: check-headers cargo-check unit-tests

debug: check-headers
	cargo build

release:
	cargo build --release

clean:
	cargo clean
	cargo llvm-cov clean --workspace 2>/dev/null || true
	find . -name "*.profraw" -delete
	find . -name spd-cache.redb -delete
	rm -rf reports/

all: debug
