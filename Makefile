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
# Uses cargo-llvm-cov; includes all workspace crates. Branch coverage disabled for now
# (LLVM llvm-cov can SIGSEGV with proc-macro .so when -show-branches is used).
coverage:
	@command -v cargo-llvm-cov >/dev/null 2>&1 || cargo install cargo-llvm-cov --locked; \
	rustup toolchain install nightly; \
	rustup component add llvm-tools --toolchain nightly; \
	rm -rf reports && \
	find . -name spd-cache.redb -delete
	mkdir -p reports && \
	cargo +nightly llvm-cov clean --workspace 2>/dev/null || true; \
	cargo +nightly llvm-cov --no-report run --bin xtask -- check && \
	XTASK_FAIL=$$(mktemp -d) && XTASK_ROOT="$$XTASK_FAIL" cargo +nightly llvm-cov --no-report run --bin xtask -- check 2>/dev/null; \
	XTASK_COVER=$$(mktemp -d) && mkdir -p "$$XTASK_COVER/tools" && \
	echo "// header" > "$$XTASK_COVER/tools/header.txt" && \
	echo 'fn main() {}' > "$$XTASK_COVER/foo.rs" && \
	XTASK_ROOT="$$XTASK_COVER" cargo +nightly llvm-cov --no-report run --bin xtask -- replace 1>/dev/null 2>&1; \
	cargo +nightly llvm-cov --no-report --workspace && \
	cargo +nightly llvm-cov report --html --output-dir reports && \
	cargo +nightly llvm-cov report --cobertura --output-path reports/cobertura.xml

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
