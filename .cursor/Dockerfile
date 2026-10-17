# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Cloud Agent base image for verilyze.
#
# Provides Docker-in-Docker (fuse-overlayfs + iptables-legacy) so
# `make super-linter` / verilyze-ship-pr can run the slim super-linter
# container. Also installs the pinned Rust toolchain so `.cursor/install.sh`
# can `cargo build` after checkout (a custom Dockerfile replaces Cursor's
# default base image), and a pinned Flutter / Dart SDK so DartRemediator
# (`pub add`) can be exercised against real binaries (HC-12).
#
# Build context is the repository root (`environment.json` build.context
# `..`) so Rust is derived from `rust-toolchain.toml`. Do not COPY the rest
# of the repository; Cursor checks out the requested revision. Exception:
# `docker-start.sh` is baked in so `start` can launch dockerd before checkout.

# rustup-init archive pin (OpenSSF Scorecard Pinned-Dependencies).
# Download+verify in a separate stage so the main image never curl|sh's an
# unpinned installer (Scorecard downloadThenRun). Checksums match
# https://static.rust-lang.org/rustup/archive/<ver>/<triple>/rustup-init.sha256
# (same scheme as rust-lang/docker-rust). Renovate bumps RUSTUP_VERSION and
# runs scripts/renovate-post-upgrade-rustup-init.sh to refresh both SHA-256
# ARGs from the archive .sha256 files in the same PR.
ARG RUSTUP_VERSION=1.29.1
ARG RUSTUP_INIT_SHA256_AMD64=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71
ARG RUSTUP_INIT_SHA256_ARM64=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433

# Flutter Linux stable pin (amd64). Upstream publishes no Linux arm64 Flutter
# archive; arm64 images install the matching Dart SDK instead (dart only).
# Renovate bumps FLUTTER_VERSION and runs
# scripts/renovate-post-upgrade-flutter-sdk.sh to refresh archive path / SHA /
# Dart pins from releases_linux.json (FLUTTER_ARCHIVE_PATH is the URL suffix).
ARG FLUTTER_VERSION=3.47.7
ARG FLUTTER_ARCHIVE_PATH=stable/linux/flutter_linux_3.47.7-stable.tar.xz
ARG FLUTTER_SHA256_AMD64=af7455f540df951184c7953fbe3cf884766e7541dacf8571f9f582db03dd6230
ARG DART_SDK_VERSION=3.13.5
ARG DART_SHA256_ARM64=19a731647c3ed55058ee46dde00330150e6a8729bb6121b4a31e86084c8a3e6d

# ubuntu:26.04 (resolute) @ 2026-09 (re-pin periodically via docker buildx imagetools).
# --- Stage: fetch and hash-pin rustup-init (do not execute here). ---
FROM ubuntu:26.04@sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7 AS rustup-fetch
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

# --- Stage: fetch and hash-pin Flutter (amd64) or Dart SDK (arm64). ---
# ubuntu:26.04 digest must match rustup-fetch FROM (Renovate dockerfile manager).
FROM ubuntu:26.04@sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7 AS flutter-sdk-fetch

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG FLUTTER_VERSION
ARG FLUTTER_ARCHIVE_PATH
ARG FLUTTER_SHA256_AMD64
ARG DART_SDK_VERSION
ARG DART_SHA256_ARM64

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && mkdir -p /sdk \
    && case "${arch}" in \
         amd64) \
           test -n "${FLUTTER_VERSION}"; \
           archive="$(basename "${FLUTTER_ARCHIVE_PATH}")"; \
           url="https://storage.googleapis.com/flutter_infra_release/releases/${FLUTTER_ARCHIVE_PATH}"; \
           curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 5 -sSfL \
             "${url}" -o "/tmp/${archive}"; \
           echo "${FLUTTER_SHA256_AMD64}  /tmp/${archive}" | sha256sum -c -; \
           tar -xJf "/tmp/${archive}" -C /sdk --strip-components=1; \
           rm -f "/tmp/${archive}"; \
           test -x /sdk/bin/flutter; \
           test -x /sdk/bin/dart; \
           ;; \
         arm64) \
           archive="dartsdk-linux-arm64-release.zip"; \
           url="https://storage.googleapis.com/dart-archive/channels/stable/release/${DART_SDK_VERSION}/sdk/${archive}"; \
           curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 5 -sSfL \
             "${url}" -o "/tmp/${archive}"; \
           echo "${DART_SHA256_ARM64}  /tmp/${archive}" | sha256sum -c -; \
           unzip -q "/tmp/${archive}" -d /tmp/dart-extract; \
           mv /tmp/dart-extract/dart-sdk/* /sdk/; \
           rm -rf "/tmp/${archive}" /tmp/dart-extract; \
           test -x /sdk/bin/dart; \
           ;; \
         *) echo "unsupported architecture: ${arch}" >&2; exit 1 ;; \
       esac

# --- Stage: Cloud Agent runtime image. ---
# ubuntu:26.04 digest must match rustup-fetch FROM (Renovate dockerfile manager).
FROM ubuntu:26.04@sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7

# Pipefail for RUN lines that use | (Hadolint DL4006).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    FLUTTER_HOME=/usr/local/flutter \
    PATH=/usr/local/flutter/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Base tools required by Cloud Agents and install.sh.
# acl: setfacl for docker.sock without world-writable mode.
# openssh-client: ssh-keygen for sign-setup.sh / make check-signatures.
# Ubuntu archive package pins drift; ignore DL3008 for this layer only.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    git \
    openssh-client \
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
    && rm -f /tmp/rust-toolchain.toml \
    && ln -sf "${CARGO_HOME}/bin/cargo" /usr/local/bin/cargo \
    && ln -sf "${CARGO_HOME}/bin/rustc" /usr/local/bin/rustc \
    && ln -sf "${CARGO_HOME}/bin/rustup" /usr/local/bin/rustup \
    && printf '%s\n' \
      'export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"' \
      'export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"' \
      'export PATH="${CARGO_HOME}/bin:${PATH}"' \
      > /etc/profile.d/rustup.sh \
    && chmod 0644 /etc/profile.d/rustup.sh

# Hash-pinned Flutter SDK (amd64) or Dart SDK (arm64) from flutter-sdk-fetch.
COPY --from=flutter-sdk-fetch /sdk /usr/local/flutter
RUN chmod -R a+rwX /usr/local/flutter \
    && ln -sf /usr/local/flutter/bin/dart /usr/local/bin/dart \
    && if test -x /usr/local/flutter/bin/flutter; then \
         ln -sf /usr/local/flutter/bin/flutter /usr/local/bin/flutter; \
       fi \
    && git config --system --add safe.directory /usr/local/flutter \
    && printf '%s\n' \
      'export FLUTTER_HOME="${FLUTTER_HOME:-/usr/local/flutter}"' \
      'export PATH="${FLUTTER_HOME}/bin:${PATH}"' \
      > /etc/profile.d/flutter.sh \
    && chmod 0644 /etc/profile.d/flutter.sh

# Boot-independent dockerd helper (warm-fork start runs before checkout).
COPY .cursor/docker-start.sh /usr/local/lib/vlz/docker-start.sh
RUN chmod 0755 /usr/local/lib/vlz/docker-start.sh

# Numeric UID matches ubuntu user created above (Hadolint DL3066).
USER 1000:1000
WORKDIR /home/ubuntu
