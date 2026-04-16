# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Contract tests for resilient Python lint venv handling in CI."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_MAKEFILE = _ROOT / "Makefile"
_LINT_PYTHON = _ROOT / "scripts" / "lint-python.sh"


def test_ci_python_venv_cache_does_not_restore_cross_python_version() -> None:
    text = _CI.read_text(encoding="utf-8")
    assert "${{ runner.os }}-python-${{ steps.python.outputs.python-version }}-venvs-" in text
    assert "\n            ${{ runner.os }}-python-\n" not in text


def test_makefile_rebuilds_lint_venv_when_tools_cannot_run() -> None:
    text = _MAKEFILE.read_text(encoding="utf-8")
    assert "\"$(VENV_LINT)/bin/black\" --version >/dev/null 2>&1" in text
    assert "rm -rf $(VENV_LINT)" in text


def test_lint_python_script_validates_tool_runtime_not_only_executable_bit() -> None:
    text = _LINT_PYTHON.read_text(encoding="utf-8")
    assert "\"$venv_path\" --version >/dev/null 2>&1" in text
    assert "python lint tool not found in venv or PATH" in text
