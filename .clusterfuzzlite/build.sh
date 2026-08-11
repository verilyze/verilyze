#!/bin/bash -eu
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Build cargo-fuzz targets and install binaries into $OUT for ClusterFuzzLite.

cd "$SRC/verilyze"

# Root rust-toolchain.toml pins stable; cargo-fuzz needs nightly (-Zsanitizer).
# Refresh the image nightly: base-builder-rust may ship an older alias that
# cannot build current ruff_python_* crates (need rustc >= 1.95).
rustup update nightly
rustup component add rust-src --toolchain nightly
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-nightly}"

cargo fuzz build -O --debug-assertions

FUZZ_TARGET_OUTPUT_DIR="fuzz/target/x86_64-unknown-linux-gnu/release"
for f in fuzz/fuzz_targets/*.rs; do
  FUZZ_TARGET_NAME="$(basename "${f%.*}")"
  cp "${FUZZ_TARGET_OUTPUT_DIR}/${FUZZ_TARGET_NAME}" "$OUT/"
done
