#!/usr/bin/env bash
#
# Idempotent Cloud Agent bootstrap for verilyze (vlz).
#
# Prepares a fresh VM to build, run, test, and lint the project:
#   - system packages needed by the Makefile gates (shellcheck, zstd, ...)
#   - gitleaks (used by the native super-linter checks)
#   - Python 3.14 (matches the CI toolchain in .github/workflows/ci.yml)
#   - the release `vlz` binary (Rust toolchain is pinned by rust-toolchain.toml)
#   - cargo-deny (dependency/license gate used by `make check-fast`)
#   - the Python test (.venv-test) and lint (.venv-lint) virtualenvs
#
# Safe to re-run: every step checks for existing state before doing work.

set -euo pipefail

# Pinned tool versions (single source of truth for this script).
GITLEAKS_VERSION="8.21.2"
PYTHON_SERIES="3.14"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

log() { printf '\n==> %s\n' "$*"; }

log "Installing base system packages"
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
  build-essential binutils curl ca-certificates \
  shellcheck zstd \
  software-properties-common

log "Ensuring Python ${PYTHON_SERIES} (CI toolchain) is available"
if ! command -v "python${PYTHON_SERIES}" >/dev/null 2>&1; then
  sudo add-apt-repository -y ppa:deadsnakes/ppa
  sudo apt-get update -qq
fi
sudo apt-get install -y --no-install-recommends \
  "python${PYTHON_SERIES}" "python${PYTHON_SERIES}-venv"

# Make bare `python3` resolve to the CI series (mirrors actions/setup-python).
# /usr/local/bin precedes /usr/bin on PATH, and system tools use absolute
# /usr/bin/python3 shebangs, so this only affects interactive/dev invocations.
sudo ln -sf "$(command -v "python${PYTHON_SERIES}")" /usr/local/bin/python3
hash -r || true

log "Restoring a functional man(1) for 'vlz help'"
# Minimized Ubuntu images divert /usr/bin/man to a stub that just prints an
# "unminimize" notice. 'vlz help' shells out to man on its embedded page, so
# restore the real binary by dropping the diversion when present.
if dpkg-divert --list /usr/bin/man 2>/dev/null | grep -q man.REAL; then
  sudo rm -f /usr/bin/man
  sudo dpkg-divert --remove --rename /usr/bin/man
fi

log "Ensuring gitleaks ${GITLEAKS_VERSION} is installed"
if ! command -v gitleaks >/dev/null 2>&1 ||
  [ "$(gitleaks version 2>/dev/null || true)" != "${GITLEAKS_VERSION}" ]; then
  tmp="$(mktemp -d)"
  curl -fsSL \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    -o "${tmp}/gitleaks.tar.gz"
  tar -xzf "${tmp}/gitleaks.tar.gz" -C "${tmp}" gitleaks
  sudo install -m 0755 "${tmp}/gitleaks" /usr/local/bin/gitleaks
  rm -rf "${tmp}"
fi

log "Building the release vlz binary"
cargo build --release -p vlz

log "Installing cargo-deny (dependency/license gate)"
make setup-cargo-deny

log "Installing the DCO sign-off git hook"
# Auto-append Signed-off-by on normal commits so the DCO gate passes. Cursor's
# hook dispatcher chains to the repository's original .git/hooks/commit-msg.
if [ -d "${REPO_ROOT}/.git/hooks" ]; then
  install -m 0755 "${REPO_ROOT}/.cursor/git-hooks/commit-msg.sh" \
    "${REPO_ROOT}/.git/hooks/commit-msg"
fi

log "Creating Python test and lint virtualenvs"
make venv-test-ready
make "${REPO_ROOT}/.venv-lint/bin/black"

log "Bootstrap complete"
"${REPO_ROOT}/target/release/vlz" --version
