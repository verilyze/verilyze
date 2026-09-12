# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Cloud Agent base image for verilyze.
#
# Provides Docker-in-Docker (fuse-overlayfs + iptables-legacy) so
# `make super-linter` / verilyze-ship-pr can run the slim super-linter
# container. Also installs the pinned Rust toolchain so `.cursor/install.sh`
# can `cargo build` after checkout (a custom Dockerfile replaces Cursor's
# default base image).
#
# Build context is the repository root (`environment.json` build.context
# `..`) so Rust is derived from `rust-toolchain.toml`. Do not COPY the rest
# of the repository; Cursor checks out the requested revision.

# rustup-init archive pin (OpenSSF Scorecard Pinned-Dependencies).
# Download+verify in a separate stage so the main image never curl|sh's an
# unpinned installer (Scorecard downloadThenRun). Checksums match
# https://static.rust-lang.org/rustup/archive/<ver>/<triple>/rustup-init.sha256
# (same scheme as rust-lang/docker-rust). After bumping RUSTUP_VERSION, refresh
# both SHA-256 ARGs from the archive .sha256 files (Renovate tracks the
# version; checksums are updated in the same PR).
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256_AMD64=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ARG RUSTUP_INIT_SHA256_ARM64=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433

# ubuntu:26.04 (resolute) @ 2026-09 (re-pin periodically via docker buildx imagetools).
# --- Stage: fetch and hash-pin rustup-init (do not execute here). ---
FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d AS rustup-fetch

# Pipefail for RUN lines that use | (Hadolint DL4006).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG RUSTUP_VERSION
ARG RUSTUP_INIT_SHA256_AMD64
ARG RUSTUP_INIT_SHA256_ARM64

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && case "${arch}" in \
         amd64) rust_arch=x86_64-unknown-linux-gnu; \
                rustup_sha="${RUSTUP_INIT_SHA256_AMD64}" ;; \
         arm64) rust_arch=aarch64-unknown-linux-gnu; \
                rustup_sha="${RUSTUP_INIT_SHA256_ARM64}" ;; \
         *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
       esac \
    && curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 5 -sSf \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${rust_arch}/rustup-init" \
      -o /rustup-init \
    && echo "${rustup_sha}  /rustup-init" | sha256sum -c - \
    && chmod +x /rustup-init

# --- Stage: Cloud Agent runtime image. ---
# ubuntu:26.04 digest must match rustup-fetch FROM (Renovate dockerfile manager).
FROM ubuntu:26.04@sha256:513c074113a871b51a8d16ab445c88779d6452d937a164fb5cc479f32668a41d

# Pipefail for RUN lines that use | (Hadolint DL4006).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Base tools required by Cloud Agents and install.sh.
# acl: setfacl for docker.sock without world-writable mode.
# Ubuntu archive package pins drift; ignore DL3008 for this layer only.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    git \
    sudo \
    acl \
    build-essential \
    pkg-config \
    libssl-dev \
    zstd \
    shellcheck \
    software-properties-common \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Docker CE (pinned engine + companions) for nested Cloud Agent VMs.
# See https://cursor.com/docs/cloud-agent/setup -- Running Docker.
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl --retry 3 --retry-delay 5 -fsSL \
      https://download.docker.com/linux/ubuntu/gpg \
      | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && chmod a+r /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
      > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      docker-ce=5:29.8.0-1~ubuntu.26.04~resolute \
      docker-ce-cli=5:29.8.0-1~ubuntu.26.04~resolute \
      containerd.io=2.3.5-1~ubuntu.26.04~resolute \
      docker-buildx-plugin=0.37.1-1~ubuntu.26.04~resolute \
      docker-compose-plugin=5.5.1-1~ubuntu.26.04~resolute \
    && rm -rf /var/lib/apt/lists/*

# Nested-container storage + legacy iptables (Cursor Docker recipe).
# vfs fallback is per-boot via dockerd --storage-driver (docker-start.sh).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends fuse-overlayfs \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/docker \
    && printf '%s\n' \
      '{' \
      '  "storage-driver": "fuse-overlayfs"' \
      '}' > /etc/docker/daemon.json \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy \
    && update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy

# Non-root agent user (matches environment.json "user": "ubuntu").
RUN if ! id -u ubuntu >/dev/null 2>&1; then \
      useradd -m -u 1000 -s /bin/bash ubuntu; \
    fi \
    && groupadd -f docker \
    && usermod -aG docker ubuntu \
    && usermod -aG sudo ubuntu \
    && echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu

# Hash-pinned rustup-init from rustup-fetch (no curl|sh).
COPY --from=rustup-fetch /rustup-init /tmp/rustup-init

# Rust channel + components from repo rust-toolchain.toml (DRY / NFR-024).
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN RUST_VERSION="$(sed -n 's/^channel = "\(.*\)"/\1/p' /tmp/rust-toolchain.toml)" \
    && test -n "${RUST_VERSION}" \
    && /tmp/rustup-init -y --default-toolchain "${RUST_VERSION}" --profile minimal \
    && rm -f /tmp/rustup-init \
    && COMPONENTS="$(sed -n 's/^components = \[\(.*\)\]/\1/p' /tmp/rust-toolchain.toml \
        | tr -d '" ')" \
    && OLDIFS="${IFS}" \
    && IFS=, \
    && for c in ${COMPONENTS}; do \
         IFS="${OLDIFS}"; \
         test -n "${c}" || continue; \
         rustup component add "${c}"; \
       done \
    && IFS="${OLDIFS}" \
    && chmod -R a+rwX "${RUSTUP_HOME}" "${CARGO_HOME}" \
    && rm -f /tmp/rust-toolchain.toml

# Numeric UID matches ubuntu user created above (Hadolint DL3066).
USER 1000:1000
WORKDIR /home/ubuntu
