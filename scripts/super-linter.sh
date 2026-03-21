#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Run GitHub super-linter (slim image) against the repo root.
# Used by make super-linter / super-linter-full and GitHub Actions.
#
# Env (optional):
#   SUPER_LINTER_IMAGE   default ghcr.io/super-linter/super-linter:slim-latest
#   VALIDATE_ALL_CODEBASE  true | false (default false)
#   DEFAULT_BRANCH       default main
#   GITHUB_TOKEN         optional; passed through when set
#   SAVE_SUPER_LINTER_OUTPUT, SAVE_SUPER_LINTER_SUMMARY  optional artifact logs

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${SUPER_LINTER_IMAGE:-ghcr.io/super-linter/super-linter:slim-latest}"
ALL_CODEBASE="${VALIDATE_ALL_CODEBASE:-false}"
DEFAULT_BRANCH="${DEFAULT_BRANCH:-main}"

# Match CONTRIBUTING: skip build trees, venvs, completions (ShellCheck via make
# lint-shell + completions/.shellcheckrc), and site-packages.
FILTER_REGEX_EXCLUDE='(^|/)(target/|\.git/|completions/|\.venv[^/]*/|\.mypy_cache/|site-packages/)'

# Validator toggles: Rust/Python/shell/markdown/natural-language off when covered by
# make check-fast (or not part of the project gate). isort is off because lint-python
# uses black/pylint/mypy/bandit only, not isort. Markdown linters are off to avoid a
# second policy layer until aligned with CONTRIBUTING.
# Zizmor/JSCPD/Gitleaks: pragmatically off in-container (see CONTRIBUTING super-linter).
DOCKER_ARGS=(
  --rm
  -e LINTER_RULES_PATH=/tmp/lint
  -e RUN_LOCAL=true
  -e DEFAULT_BRANCH="$DEFAULT_BRANCH"
  -e IGNORE_GITIGNORED_FILES=true
  -e VALIDATE_ALL_CODEBASE="$ALL_CODEBASE"
  -e FILTER_REGEX_EXCLUDE="$FILTER_REGEX_EXCLUDE"
  -e BASH_EXEC_IGNORE_LIBRARIES=true
  -e SAVE_SUPER_LINTER_OUTPUT="${SAVE_SUPER_LINTER_OUTPUT:-false}"
  -e SAVE_SUPER_LINTER_SUMMARY="${SAVE_SUPER_LINTER_SUMMARY:-false}"
  -e VALIDATE_GITHUB_ACTIONS_ZIZMOR=false
  -e VALIDATE_JSCPD=false
  -e VALIDATE_GITLEAKS=false
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
