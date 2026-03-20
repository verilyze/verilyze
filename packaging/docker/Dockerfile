# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Multi-stage build: static musl binary -> scratch image (FR-025, OP-013).
# Usage: docker build -f packaging/docker/Dockerfile -t verilyze .
# Context must stay small: root `.dockerignore` excludes `target/` and `.git/`.

# --- Stage 1: Build ---
FROM rust:slim AS builder

RUN apt-get update && apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

# THIRD-PARTY-LICENSES is committed (default-features variant; superset of docker deps).
RUN cargo build --release --locked --no-default-features --features docker \
    --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/vlz

# --- Stage 2: Minimal image ---
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vlz /vlz
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/LICENSES/GPL-3.0-or-later.txt /LICENSE
COPY --from=builder /build/THIRD-PARTY-LICENSES /THIRD-PARTY-LICENSES

ENTRYPOINT ["/vlz"]
