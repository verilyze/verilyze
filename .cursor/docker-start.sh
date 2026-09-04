#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Idempotent Docker daemon start for Cursor Cloud Agents.
#
# systemd is unreliable in these VMs; start dockerd directly. Prefer the
# fuse-overlayfs storage driver from /etc/docker/daemon.json. If that fails
# to become ready, fall back once to vfs via a per-boot --storage-driver flag
# (do not rewrite daemon.json). Soft-fail is handled by environment.json so a
# dockerd outage does not block the whole agent session.

set -euo pipefail

LOG_DIR="${VLZ_DOCKER_LOG_DIR:-/tmp/cursor/docker}"
LOG_FILE="${LOG_DIR}/dockerd.log"
PID_FILE="${LOG_DIR}/dockerd.pid"
READY_TIMEOUT_SECS="${VLZ_DOCKER_READY_TIMEOUT_SECS:-60}"
SOCK_PATH="/var/run/docker.sock"

log() { printf '[docker-start] %s\n' "$*"; }

dockerd_running() {
  pgrep -x dockerd >/dev/null 2>&1
}

ensure_socket_access() {
  if [[ ! -S "${SOCK_PATH}" ]]; then
    return 0
  fi
  sudo chgrp docker "${SOCK_PATH}" 2>/dev/null || true
  sudo chmod 660 "${SOCK_PATH}" 2>/dev/null || true
  # Prefer ACL / group access over world-writable mode (no chmod 666).
  if command -v setfacl >/dev/null 2>&1; then
    sudo setfacl -m "u:${USER}:rw" "${SOCK_PATH}" 2>/dev/null || true
  fi
}

# Run docker; use sg docker when the session lacks socket read access.
docker_cmd() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
    return $?
  fi
  if command -v sg >/dev/null 2>&1; then
    local quoted=""
    local arg
    for arg in "$@"; do
      quoted+=" $(printf '%q' "${arg}")"
    done
    sg docker -c "docker${quoted}"
    return $?
  fi
  docker "$@"
}

docker_info_ok() {
  ensure_socket_access
  if docker info >/dev/null 2>&1; then
    return 0
  fi
  if command -v sg >/dev/null 2>&1; then
    sg docker -c "docker info" >/dev/null 2>&1
    return $?
  fi
  return 1
}

wait_ready() {
  local deadline=$((SECONDS + READY_TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    if docker_info_ok; then
      return 0
    fi
    sleep 1
  done
  return 1
}

print_driver_info() {
  docker_cmd info 2>/dev/null \
    | awk '/Server Version|Storage Driver/{print "[docker-start] " $0}' \
    || true
}

# Start dockerd. Extra args (e.g. --storage-driver=vfs) are appended.
# PID file is written inside the same root shell as the background dockerd
# so $! is the daemon, not an outer sudo wrapper.
start_dockerd() {
  mkdir -p "${LOG_DIR}"
  if dockerd_running; then
    local pid
    pid="$(pgrep -x dockerd | head -n1 || true)"
    log "dockerd already running${pid:+ (pid ${pid})}"
    if [[ -n "${pid}" ]]; then
      printf '%s\n' "${pid}" >"${PID_FILE}"
    fi
    return 0
  fi
  local -a dockerd_args=(
    "--host=unix://${SOCK_PATH}"
    "--iptables=false"
    "--ip6tables=false"
    "$@"
  )
  local cmd="dockerd"
  local arg
  for arg in "${dockerd_args[@]}"; do
    cmd+=" $(printf '%q' "${arg}")"
  done
  log "starting dockerd${*:+ $*}"
  sudo sh -c "${cmd} >>$(printf '%q' "${LOG_FILE}") 2>&1 & echo \$! >$(printf '%q' "${PID_FILE}")"
}

if ! command -v docker >/dev/null 2>&1; then
  log "error: docker CLI not found (base image missing Docker CE)"
  exit 1
fi

if ! command -v dockerd >/dev/null 2>&1; then
  log "error: dockerd not found (base image missing Docker CE)"
  exit 1
fi

# Fix socket ownership/ACL before deciding the daemon is unhealthy. Wrong
# group mode must not trigger a dockerd restart.
ensure_socket_access
if docker_info_ok; then
  log "docker already healthy"
  print_driver_info
  exit 0
fi

mkdir -p "${LOG_DIR}"
sudo touch "${LOG_FILE}"
sudo chmod 664 "${LOG_FILE}" 2>/dev/null || true
sudo chgrp docker "${LOG_FILE}" 2>/dev/null || true

# Daemon already up but still unreachable after ACL/group fix -- do not loop
# on pkill; surface the failure for soft-fail in environment.json.
if dockerd_running; then
  log "error: dockerd is running but docker info failed after socket access fix"
  if [[ -f "${LOG_FILE}" ]]; then
    log "last dockerd log lines:"
    tail -n 40 "${LOG_FILE}" || true
  fi
  exit 1
fi

start_dockerd
if wait_ready; then
  log "docker ready"
  print_driver_info
  exit 0
fi

log "configured storage driver did not become ready; falling back to vfs"
sudo pkill -x dockerd 2>/dev/null || true
sleep 1
# Per-boot override only -- leave /etc/docker/daemon.json as fuse-overlayfs.
sudo rm -rf /var/lib/docker
start_dockerd --storage-driver=vfs
if wait_ready; then
  log "docker ready (storage-driver=vfs fallback)"
  print_driver_info
  exit 0
fi

log "error: docker daemon failed to become ready within ${READY_TIMEOUT_SECS}s"
if [[ -f "${LOG_FILE}" ]]; then
  log "last dockerd log lines:"
  tail -n 40 "${LOG_FILE}" || true
fi
exit 1
