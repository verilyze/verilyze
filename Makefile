.PHONY: headers check-headers check
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

check: check-headers

debug: check-headers
	cargo build

release:
	cargo build --release

all: debug
