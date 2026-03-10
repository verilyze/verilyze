# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Multi-stage build: static musl binary -> scratch image (FR-025, OP-013).
# Usage: docker build -f packaging/docker/Dockerfile -t verilyze .

# --- Stage 1: Build ---
FROM rust:slim AS builder

RUN apt-get update && apt-get install -y musl-tools && \
    rustup target add x86_64-unknown-linux-musl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .

RUN cargo build --release --locked --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/vlz

# --- Stage 2: Minimal image ---
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vlz /vlz
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/vlz"]
