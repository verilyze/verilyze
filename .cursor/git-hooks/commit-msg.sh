#!/usr/bin/env bash
#
# commit-msg hook: append a Developer Certificate of Origin (DCO)
# Signed-off-by trailer for the configured git identity, mirroring
# `git commit -s`, when one is not already present.
#
# Installed into .git/hooks/commit-msg by .cursor/install.sh. Cursor's hook
# dispatcher chains to the repository's original .git/hooks, so this runs on
# normal commits (those that do not pass --no-verify). It uses whatever git
# identity is configured, so it signs off correctly for any contributor.

set -euo pipefail

msg_file="$1"

name="$(git config user.name 2>/dev/null || true)"
email="$(git config user.email 2>/dev/null || true)"
if [ -z "${name}" ] || [ -z "${email}" ]; then
  exit 0
fi

trailer="Signed-off-by: ${name} <${email}>"
if grep -qixF "${trailer}" "${msg_file}"; then
  exit 0
fi

git interpret-trailers --if-exists addIfDifferentNeighbor \
  --trailer "Signed-off-by=${name} <${email}>" --in-place "${msg_file}"
