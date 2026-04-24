# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Multi-stage build: static musl binary -> scratch image (FR-025, OP-013).
# Usage: docker build -f packaging/docker/Dockerfile -t verilyze .
# Context must stay small: root `.dockerignore` excludes `target/` and `.git/`.

# --- Stage 1: Build ---
FROM rust:slim@sha256:81099830a1e1d244607b9a7a30f3ff6ecadc52134a933b4635faba24f52840c9 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    musl-tools=1.2.* \
    && rustup target add x86_64-unknown-linux-musl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /vlz-docker-home/.cache /vlz-docker-home/.local/share \
    && chown -R 1000:1000 /vlz-docker-home \
    && echo "verilyze:x:1000:1000:verilyze:/home/verilyze:" > /etc/passwd

WORKDIR /build
COPY . .

# THIRD-PARTY-LICENSES is committed (default-features variant; superset of docker deps).
RUN cargo build --release --locked --no-default-features --features docker \
    --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/vlz

# --- Stage 2: Minimal image ---
FROM scratch

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vlz /vlz
COPY --from=builder /etc/passwd /etc/
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/LICENSES/GPL-3.0-or-later.txt /LICENSE
COPY --from=builder /build/THIRD-PARTY-LICENSES /THIRD-PARTY-LICENSES
COPY --from=builder --chown=1000:1000 /vlz-docker-home /home/verilyze

ENV HOME=/home/verilyze
USER 1000
# FR-002: --version exits 0; satisfies Checkov CKV_DOCKER_2 / Trivy DS-0026 (OP-013).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/vlz", "--version"]
ENTRYPOINT ["/vlz"]
