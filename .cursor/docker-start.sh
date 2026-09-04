#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Idempotent Docker daemon start for Cursor Cloud Agents.
#
# systemd is unreliable in these VMs; start dockerd directly. Prefer the
# fuse-overlayfs storage driver from /etc/docker/daemon.json. If that fails
# to become ready, fall back once to vfs (slower but works when nested
# overlay whiteouts are denied).

set -euo pipefail

LOG_DIR="${VLZ_DOCKER_LOG_DIR:-/tmp/cursor/docker}"
LOG_FILE="${LOG_DIR}/dockerd.log"
PID_FILE="${LOG_DIR}/dockerd.pid"
READY_TIMEOUT_SECS="${VLZ_DOCKER_READY_TIMEOUT_SECS:-60}"
SOCK_PATH="/var/run/docker.sock"

log() { printf '[docker-start] %s\n' "$*"; }

docker_info_ok() {
  docker info >/dev/null 2>&1
}

ensure_socket_access() {
  if [[ ! -S "${SOCK_PATH}" ]]; then
    return 0
  fi
  sudo chgrp docker "${SOCK_PATH}" 2>/dev/null || true
  sudo chmod 660 "${SOCK_PATH}" 2>/dev/null || true
  # Agent start sessions may lack the docker supplementary group.
  if ! docker_info_ok; then
    sudo chmod 666 "${SOCK_PATH}" 2>/dev/null || true
  fi
}

wait_ready() {
  local deadline=$((SECONDS + READY_TIMEOUT_SECS))
  while ((SECONDS < deadline)); do
    ensure_socket_access
    if docker_info_ok; then
      return 0
    fi
    sleep 1
  done
  return 1
}

print_driver_info() {
  docker info 2>/dev/null \
    | awk '/Server Version|Storage Driver/{print "[docker-start] " $0}' \
    || true
}

start_dockerd() {
  mkdir -p "${LOG_DIR}"
  if [[ -f "${PID_FILE}" ]]; then
    local old_pid
    old_pid="$(cat "${PID_FILE}" 2>/dev/null || true)"
    if [[ -n "${old_pid}" ]] && kill -0 "${old_pid}" 2>/dev/null; then
      log "dockerd already running (pid ${old_pid})"
      return 0
    fi
  fi
  if pgrep -x dockerd >/dev/null 2>&1; then
    log "stopping existing dockerd before restart"
    sudo pkill -x dockerd 2>/dev/null || true
    sleep 1
  fi
  log "starting dockerd"
  # Redirect as root so the log is always writable.
  sudo sh -c "dockerd --host=unix://${SOCK_PATH} --iptables=false --ip6tables=false >>'${LOG_FILE}' 2>&1" &
  echo $! >"${PID_FILE}"
}

write_storage_driver() {
  local driver="$1"
  sudo mkdir -p /etc/docker
  printf '%s\n' \
    '{' \
    "  \"storage-driver\": \"${driver}\"" \
    '}' | sudo tee /etc/docker/daemon.json >/dev/null
}

if ! command -v docker >/dev/null 2>&1; then
  log "error: docker CLI not found (base image missing Docker CE)"
  exit 1
fi

if ! command -v dockerd >/dev/null 2>&1; then
  log "error: dockerd not found (base image missing Docker CE)"
  exit 1
fi

if docker_info_ok; then
  log "docker already healthy"
  print_driver_info
  exit 0
fi

mkdir -p "${LOG_DIR}"
sudo touch "${LOG_FILE}"
sudo chmod 666 "${LOG_FILE}" 2>/dev/null || true

start_dockerd
if wait_ready; then
  log "docker ready"
  print_driver_info
  exit 0
fi

log "configured storage driver did not become ready; falling back to vfs"
sudo pkill -x dockerd 2>/dev/null || true
sleep 1
write_storage_driver vfs
sudo rm -rf /var/lib/docker
start_dockerd
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
