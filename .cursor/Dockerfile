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

# ubuntu:24.04 @ 2026-03 (re-pin periodically via docker buildx imagetools).
FROM ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

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
      docker-ce=5:28.5.2-1~ubuntu.24.04~noble \
      docker-ce-cli=5:28.5.2-1~ubuntu.24.04~noble \
      containerd.io=1.7.28-2~ubuntu.24.04~noble \
      docker-buildx-plugin=0.29.1-1~ubuntu.24.04~noble \
      docker-compose-plugin=2.40.3-1~ubuntu.24.04~noble \
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

# Rust channel + components from repo rust-toolchain.toml (DRY / NFR-024).
COPY rust-toolchain.toml /tmp/rust-toolchain.toml
RUN RUST_VERSION="$(sed -n 's/^channel = "\(.*\)"/\1/p' /tmp/rust-toolchain.toml)" \
    && test -n "${RUST_VERSION}" \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain "${RUST_VERSION}" --profile minimal \
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
