#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run GitHub super-linter (slim image) against the repo root.
# Used by make super-linter / super-linter-full and GitHub Actions.
#
# Env (optional):
#   SUPER_LINTER_IMAGE   override pinned digest below
#   VALIDATE_ALL_CODEBASE  true | false (default false)
#   DEFAULT_BRANCH       default main
#   GITHUB_TOKEN         optional; passed through when set
#   SUPPRESS_POSSUM      optional; default true (super-linter possum banner)
#   SAVE_SUPER_LINTER_OUTPUT, SAVE_SUPER_LINTER_SUMMARY  optional artifact logs
# (set in DOCKER_ARGS): LINTER_RULES_PATH, YAML_CONFIG_FILE, FILTER_REGEX_EXCLUDE
#
# Default image is a pinned linux/amd64 digest (not :slim-latest) so bundled Biome
# and other linter versions do not drift on every CI pull. Renovate bumps SL_SHA
# via regex manager in renovate.json (weekly workflow .github/workflows/renovate.yml;
# GitHub App token via secrets RENOVATE_APP_ID / RENOVATE_APP_PRIVATE_KEY).
# Manual bump: use imagetools, then make super-linter-full:
#   docker buildx imagetools inspect ghcr.io/super-linter/super-linter:slim-latest \
#     --format '{{range .Manifest.Manifests}}{{if eq .Platform.OS "linux"}}{{if eq .Platform.Architecture "amd64"}}{{.Digest}}{{end}}{{end}}{{end}}'
#   update DEFAULT_SUPER_LINTER_IMAGE below, then run: make super-linter-full

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SL_SHA="sha256:0c13d6e36eb47ad35d4b7b3f4a36f10f3e1bb6bb96351d7f5e7d9c2a90ac9e0a"
DEFAULT_SUPER_LINTER_IMAGE="ghcr.io/super-linter/super-linter@${SL_SHA}"
IMAGE="${SUPER_LINTER_IMAGE:-$DEFAULT_SUPER_LINTER_IMAGE}"
ALL_CODEBASE="${VALIDATE_ALL_CODEBASE:-false}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

# Match CONTRIBUTING: skip build trees, venvs, completions (ShellCheck via make
# lint-shell + completions/.shellcheckrc), and site-packages.
FILTER_REGEX_EXCLUDE='(^|/)(target/|\.git/|completions/|\.venv[^/]*/|\.mypy_cache/|site-packages/|super-linter-output/)'

# Validator toggles: Rust/Python/shell/markdown/natural-language off when covered by
# make -j check (or not part of the project gate). isort is off because lint-python
# uses black/pylint/mypy/bandit only, not isort. Markdown linters are off to avoid a
# second policy layer until aligned with CONTRIBUTING.
# ESLint and Prettier (including JSON/JSONC/YAML Prettier) are off; Biome handles the
# file types listed in biome.json (JSON, JSONC, CSS, JS/TS/JSX/TSX, GraphQL) and avoids
# duplicate warnings vs ESLint/Prettier.
# Stylelint (VALIDATE_CSS) and CSS Prettier are off; Biome owns CSS when present (see
# biome.json).
# JSCPD stays off (see CONTRIBUTING.md, Super-linter). Gitleaks and Zizmor use
# super-linter defaults with LINTER_RULES_PATH=. so root configs apply.
DOCKER_ARGS=(
  --rm
  # Relative to GITHUB_WORKSPACE (/tmp/lint mount). `.` normalizes to repo root so
  # trivy.yaml, biome.json, .yamllint, etc. are found (not /tmp/lint/tmp/lint/...).
  -e LINTER_RULES_PATH=.
  -e YAML_CONFIG_FILE=.yamllint
  -e RUN_LOCAL=true
  -e SUPPRESS_POSSUM="${SUPPRESS_POSSUM:-true}"
  -e DEFAULT_BRANCH="$DEFAULT_BRANCH"
  -e IGNORE_GITIGNORED_FILES=true
  -e VALIDATE_ALL_CODEBASE="$ALL_CODEBASE"
  -e FILTER_REGEX_EXCLUDE="$FILTER_REGEX_EXCLUDE"
  -e BASH_EXEC_IGNORE_LIBRARIES=true
  -e SAVE_SUPER_LINTER_OUTPUT="${SAVE_SUPER_LINTER_OUTPUT:-false}"
  -e SAVE_SUPER_LINTER_SUMMARY="${SAVE_SUPER_LINTER_SUMMARY:-false}"
  -e VALIDATE_JSCPD=false
  -e VALIDATE_CSS=false
  -e VALIDATE_CSS_PRETTIER=false
  -e VALIDATE_GRAPHQL_PRETTIER=false
  -e VALIDATE_HTML_PRETTIER=false
  -e VALIDATE_JAVASCRIPT_ES=false
  -e VALIDATE_JAVASCRIPT_PRETTIER=false
  -e VALIDATE_JSON=false
  -e VALIDATE_JSON_PRETTIER=false
  -e VALIDATE_JSONC=false
  -e VALIDATE_JSONC_PRETTIER=false
  -e VALIDATE_JSX=false
  -e VALIDATE_JSX_PRETTIER=false
  -e VALIDATE_TSX=false
  -e VALIDATE_TYPESCRIPT_ES=false
  -e VALIDATE_TYPESCRIPT_PRETTIER=false
  -e VALIDATE_VUE=false
  -e VALIDATE_VUE_PRETTIER=false
  -e VALIDATE_YAML_PRETTIER=false
  -e VALIDATE_RUST_2015=false
  -e VALIDATE_RUST_2018=false
  -e VALIDATE_RUST_2021=false
  -e VALIDATE_RUST_2024=false
  -e VALIDATE_RUST_CLIPPY=false
  -e VALIDATE_PYTHON_BLACK=false
  -e VALIDATE_PYTHON_PYLINT=false
  -e VALIDATE_PYTHON_MYPY=false
  -e VALIDATE_PYTHON_RUFF=false
  -e VALIDATE_PYTHON_RUFF_FORMAT=false
  -e VALIDATE_PYTHON_FLAKE8=false
  -e VALIDATE_PYTHON_ISORT=false
  -e VALIDATE_MARKDOWN=false
  -e VALIDATE_MARKDOWN_PRETTIER=false
  -e VALIDATE_NATURAL_LANGUAGE=false
  -e VALIDATE_SHELL_SHFMT=false
  -e VALIDATE_BASH=false
)

if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  DOCKER_ARGS+=(-e GITHUB_TOKEN="$GITHUB_TOKEN")
fi

exec docker run "${DOCKER_ARGS[@]}" -v "$ROOT:/tmp/lint" "$IMAGE"
