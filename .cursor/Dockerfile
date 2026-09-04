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
# Do not COPY the repository; Cursor checks out the requested revision.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    RUST_VERSION=1.98.0

# Base tools required by Cloud Agents and install.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    git \
    sudo \
    build-essential \
    pkg-config \
    libssl-dev \
    zstd \
    shellcheck \
    software-properties-common \
    iptables \
    && rm -rf /var/lib/apt/lists/*

# Docker CE (pinned) for nested Cloud Agent VMs.
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
      containerd.io \
      docker-buildx-plugin \
      docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

# Nested-container storage + legacy iptables (Cursor Docker recipe).
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
RUN id -u ubuntu >/dev/null 2>&1 || useradd -m -s /bin/bash ubuntu \
    && groupadd -f docker \
    && usermod -aG docker ubuntu \
    && usermod -aG sudo ubuntu \
    && echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu

# Rust toolchain matching rust-toolchain.toml (install.sh expects cargo on PATH).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain "${RUST_VERSION}" \
        --profile minimal \
        --component rustfmt,clippy,llvm-tools \
    && chmod -R a+rwX "${RUSTUP_HOME}" "${CARGO_HOME}"

USER ubuntu
WORKDIR /home/ubuntu
