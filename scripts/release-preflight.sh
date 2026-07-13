#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Local release preflight: CHANGELOG, version/tag alignment, OBS and packaging checks.
# Usage: release-preflight.sh

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "${script_dir}/.." && pwd)"
cd "${root}"

VERSION="$(
  python3 -c "import tomllib; print(tomllib.load(open('Cargo.toml','rb'))['workspace']['package']['version'])"
)"

echo "release-preflight: workspace version ${VERSION}"

if ! ./scripts/extract-changelog-for-release.sh "${VERSION}" >/dev/null; then
  echo "error: add a curated ## [${VERSION}] section to CHANGELOG.md" >&2
  exit 1
fi

./scripts/release-verify-tag-version.sh "v${VERSION}"

make check-obs-packaging
make check-packaging

./scripts/release-verify-upload-roundtrip.sh

cat <<EOF

release-preflight: OK for v${VERSION}

Next steps:
  1. Run make -j check before tagging (not part of this quick preflight)
  2. git tag -s v${VERSION} -m "Release v${VERSION}"
  3. git push origin v${VERSION}
  4. gh run watch --workflow=release.yml

(Maintainer or AI agent when explicitly asked to publish; see
.cursor/skills/release-prepare/SKILL.md.)
EOF
