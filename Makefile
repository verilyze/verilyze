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

# Generate Cobertura XML coverage report (see CONTRIBUTING.md and NFR-012).
# Uses nightly + branch instrumentation for branch coverage. Installs grcov, nightly, and llvm-tools if missing.
coverage:
	@command -v grcov >/dev/null 2>&1 || cargo install grcov; \
	rustup toolchain install nightly; \
	rustup component add llvm-tools --toolchain nightly; \
	RUSTFLAGS="-C instrument-coverage -Z coverage-options=branch" LLVM_PROFILE_FILE="%p.profraw" \
	CARGO_INCREMENTAL=0 cargo +nightly test && \
	mkdir -p reports && \
	grcov . -s . --binary-path ./target/debug -t cobertura,html \
		--ignore-not-existing --branch -o reports

check: check-headers cargo-check unit-tests

debug: check-headers
	cargo build

release:
	cargo build --release

clean:
	cargo clean

all: debug
