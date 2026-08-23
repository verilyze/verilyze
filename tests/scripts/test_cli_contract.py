# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/cli_contract.py (CLI contract harness)."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from scripts.cli_contract import (
    UNQUALIFIED_NO_VULNS,
    CaseResult,
    DEFAULT_LANGUAGES,
    LOCKLESS_PM_ON_PATH,
    _shell_bin,
    cases_for_mode,
    isolated_env,
    load_registry,
    load_runtime_language_features,
    load_runtime_mem_language_features,
    main,
    materialize_fixture_tree,
    registry_covers_runtime_languages,
    runtime_language_features_from_toml,
    runtime_mem_language_features_from_toml,
    run_argv,
    run_case,
    run_completion_shell,
    substitute_args,
    validate_registry,
)
from tests.scripts.repo_root import repo_root

_ROOT = repo_root()
_MAKEFILE = _ROOT / "Makefile"


def test_cli_contract_python_helper_prints_interpreter() -> None:
    script = _ROOT / "scripts" / "cli-contract-python.sh"
    proc = subprocess.run(
        ["/bin/bash", str(script)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    path = Path(proc.stdout.strip())
    assert path.is_file()
    registry = load_registry(_ROOT)
    smoke = cases_for_mode(registry, "smoke")
    ids = {case["id"] for case in smoke}
    assert "version" in ids
    assert "help" in ids
    assert "languages" in ids
    assert "python-lock-offline" in ids
    assert "python-lockless" in ids
    assert "python-lockless-offline" in ids
    assert "rust-lock-offline" in ids
    assert "rust-lockless-offline" in ids
    assert "go-mod-offline" in ids
    assert "go-lockless-offline" in ids
    assert "javascript-lock-offline" in ids
    assert "java-gradle-lock-offline" in ids
    assert "ruby-lock-offline" in ids
    assert "generate-completions-bash" in ids


def test_lock_offline_cases_do_not_accept_exit_0_or_4() -> None:
    registry = load_registry(_ROOT)
    lock_offline = [
        case
        for case in registry["cases"]
        if case.get("category") == "lock_parse"
        and "--offline" in case.get("args", [])
        and "smoke" in (case.get("modes") or [])
    ]
    assert lock_offline
    for case in lock_offline:
        exits = case.get("expect_exit") or []
        assert 4 not in exits, case["id"]
        assert 0 not in exits, case["id"]
        assert "smoke" in (case.get("modes") or [])
        assert "--format" not in case.get("args", []), case["id"]


def test_lock_offline_pin_cases_use_cyclonedx_full_only() -> None:
    registry = load_registry(_ROOT)
    pins = [
        case
        for case in registry["cases"]
        if str(case.get("id", "")).endswith("-lock-offline-pin")
    ]
    expected = {
        "python-lock-offline-pin": "cli-contract-pkg",
        "rust-lock-offline-pin": "cli-contract-demo",
        "go-lock-offline-pin": "cli-contract-pkg",
        "javascript-lock-offline-pin": "cli-contract-pkg",
        "java-gradle-lock-offline-pin": "cli-contract",
        "ruby-lock-offline-pin": "cli_contract_demo",
    }
    assert {c["id"] for c in pins} == set(expected)
    for case in pins:
        assert case.get("modes") == ["full"], case["id"]
        assert "--format" in case.get("args", [])
        assert "cyclonedx" in case.get("args", [])
        needle = expected[case["id"]]
        assert needle in (case.get("stdout_contains") or [])
        exits = case.get("expect_exit") or []
        assert 0 not in exits, case["id"]
        assert 4 not in exits, case["id"]


def test_default_lockless_cases_expect_exit_4() -> None:
    registry = load_registry(_ROOT)
    default_lockless = [
        case
        for case in registry["cases"]
        if str(case.get("id", "")).endswith("-lockless")
        and "--offline" not in case.get("args", [])
    ]
    assert {c["id"] for c in default_lockless} >= {
        "python-lockless",
        "javascript-lockless",
        "java-pom-lockless",
        "ruby-lockless",
    }
    for case in default_lockless:
        assert case.get("expect_exit") == [4]


def test_runtime_language_features_from_toml_skips_cache_backends() -> None:
    text = """
[features]
runtime = ["redb", "python", "rust"]
"""
    assert runtime_language_features_from_toml(text) == ("python", "rust")
    mem_text = """
[features]
runtime-mem = ["mem", "python", "java"]
"""
    assert runtime_mem_language_features_from_toml(mem_text) == (
        "python",
        "java",
    )


def test_registry_covers_each_runtime_language() -> None:
    langs = load_runtime_language_features(_ROOT)
    mem_langs = load_runtime_mem_language_features(_ROOT)
    assert langs
    assert langs == mem_langs
    registry = load_registry(_ROOT)
    errors = registry_covers_runtime_languages(
        registry, langs, mem_langs=mem_langs
    )
    assert errors == []
    assert langs == DEFAULT_LANGUAGES
    assert LOCKLESS_PM_ON_PATH == frozenset({"rust", "go"})


def test_registry_covers_runtime_languages_reports_gaps() -> None:
    errors = registry_covers_runtime_languages(
        {"cases": []},
        ("python",),
    )
    assert any("python" in err for err in errors)
    assert registry_covers_runtime_languages({}, ("python",)) == [
        "registry cases must be a list"
    ]
    with pytest.raises(ValueError, match="runtime-mem"):
        runtime_mem_language_features_from_toml("[features]\n")
    pin_no_needle = {
        "cases": [
            {
                "id": "python-lock-offline",
                "language": "python",
                "category": "lock_parse",
                "modes": ["smoke"],
                "args": ["scan", "--offline"],
                "expect_exit": [6, 86],
            },
            {
                "id": "python-lockless",
                "language": "python",
                "args": ["scan"],
                "expect_exit": [4],
            },
            {
                "id": "python-lock-offline-pin",
                "language": "python",
                "modes": ["full"],
                "args": ["scan", "--offline", "--format", "cyclonedx"],
                "expect_exit": [6, 86],
            },
            {
                "id": "python-empty-lock",
                "language": "python",
                "args": ["scan"],
                "expect_exit": [0],
            },
        ]
    }
    extra = registry_covers_runtime_languages(pin_no_needle, ("python",))
    assert any("stdout_contains" in err for err in extra)
    assert any("empty-lock expect [4]" in err for err in extra)
    bad_lock = {
        "cases": [
            {
                "id": "python-lock-offline",
                "language": "python",
                "category": "lock_parse",
                "modes": ["smoke"],
                "args": ["scan", "--offline"],
                "expect_exit": [0],
            },
            {
                "id": "python-lockless",
                "language": "python",
                "args": ["scan"],
                "expect_exit": [6],
            },
        ]
    }
    bad_errs = registry_covers_runtime_languages(bad_lock, ("python",))
    assert any("lock-offline" in err for err in bad_errs)
    assert any("lock-less expect [4]" in err for err in bad_errs)
    rust_only = {
        "cases": [
            {
                "id": "rust-lock-offline",
                "language": "rust",
                "category": "lock_parse",
                "modes": ["smoke"],
                "args": ["scan", "--offline"],
                "expect_exit": [6, 86],
            },
            {
                "id": "rust-lockless-offline",
                "language": "rust",
                "modes": ["smoke"],
                "args": ["scan", "--offline"],
                "expect_exit": [0],
            },
        ]
    }
    rust_errs = registry_covers_runtime_languages(rust_only, ("rust",))
    assert any("lock-less-offline" in err for err in rust_errs)
    rust_missing = registry_covers_runtime_languages(
        {
            "cases": [
                {
                    "id": "rust-lock-offline",
                    "language": "rust",
                    "category": "lock_parse",
                    "modes": ["smoke"],
                    "args": ["scan", "--offline"],
                    "expect_exit": [6, 86],
                }
            ]
        },
        ("rust",),
    )
    assert any("cargo/go on PATH" in err for err in rust_missing)
    mem_mismatch = registry_covers_runtime_languages(
        {"cases": []},
        ("python",),
        mem_langs=("python", "ruby"),
    )
    assert any("runtime-mem" in err for err in mem_mismatch)
    missing_pin = {
        "cases": [
            {
                "id": "python-lock-offline",
                "language": "python",
                "category": "lock_parse",
                "modes": ["smoke", "full"],
                "args": ["scan", "--offline"],
                "expect_exit": [6],
            },
            {
                "id": "python-lockless",
                "language": "python",
                "args": ["scan"],
                "expect_exit": [4],
            },
        ]
    }
    pin_errs = registry_covers_runtime_languages(missing_pin, ("python",))
    assert any("86" in err or "lock-offline expect" in err for err in pin_errs)
    assert any("pin" in err for err in pin_errs)
    assert any("empty" in err for err in pin_errs)


def test_lockless_offline_go_and_rust_expect_cache_miss() -> None:
    registry = load_registry(_ROOT)
    by_id = {case["id"]: case for case in registry["cases"]}
    for case_id in ("go-lockless-offline", "rust-lockless-offline"):
        case = by_id[case_id]
        assert "--offline" in case["args"]
        exits = case.get("expect_exit") or []
        assert 4 not in exits
        assert 0 not in exits
        assert 6 in exits
        assert "smoke" in (case.get("modes") or [])
    rust_toml = (
        _ROOT
        / "tests"
        / "cli_contract"
        / "fixtures"
        / "rust"
        / "lockless"
        / "Cargo.toml.fixture"
    )
    assert "[dependencies]" in rust_toml.read_text(encoding="utf-8")


def test_registry_fixtures_exist() -> None:
    registry = load_registry(_ROOT)
    errors = validate_registry(_ROOT, registry)
    assert errors == []


def test_full_mode_includes_each_default_language() -> None:
    registry = load_registry(_ROOT)
    full = cases_for_mode(registry, "full")
    langs = {case.get("language") for case in full if case.get("language")}
    assert langs >= {
        "python",
        "rust",
        "go",
        "javascript",
        "java",
        "ruby",
    }


def test_cases_for_mode_rejects_unknown() -> None:
    with pytest.raises(ValueError, match="unknown mode"):
        cases_for_mode({"cases": []}, "weekly")


def test_substitute_args_replaces_fixture() -> None:
    args = substitute_args(
        ["scan", "{fixture}", "--offline"],
        Path("/tmp/fx"),
    )
    assert args == ["scan", "/tmp/fx", "--offline"]


def test_materialize_fixture_tree_strips_fixture_suffix(
    tmp_path: Path,
) -> None:
    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt.fixture").write_text("pkg==1\n", encoding="utf-8")
    (src / "notes.txt").write_text("keep\n", encoding="utf-8")
    (src / "requirements.txt.license").write_text("SPDX\n", encoding="utf-8")
    dest = tmp_path / "dest"
    materialize_fixture_tree(src, dest)
    assert (dest / "requirements.txt").read_text(
        encoding="utf-8"
    ) == "pkg==1\n"
    assert (dest / "notes.txt").read_text(encoding="utf-8") == "keep\n"
    assert not (dest / "requirements.txt.license").exists()


def test_materialize_fixture_tree_recurses_subdirs(tmp_path: Path) -> None:
    src = tmp_path / "src"
    nested = src / "python"
    nested.mkdir(parents=True)
    (nested / "pylock.toml.fixture").write_text("x\n", encoding="utf-8")
    (nested / "pylock.toml.license").write_text("SPDX\n", encoding="utf-8")
    dest = tmp_path / "dest"
    materialize_fixture_tree(src, dest)
    assert (dest / "python" / "pylock.toml").read_text(
        encoding="utf-8"
    ) == "x\n"
    assert not (dest / "python" / "pylock.toml.license").exists()


def test_corner_registry_cases_exist() -> None:
    registry = load_registry(_ROOT)
    by_id = {case["id"]: case for case in registry["cases"]}
    mixed = by_id["mixed-good-and-lockless"]
    assert mixed["expect_exit"] == [4]
    assert "cli-contract-pkg" in mixed.get("stdout_contains", [])
    assert mixed["fixture"] == "mixed/good-and-lockless"
    python_lock = by_id["python-lock-offline"]
    assert "--format" not in python_lock.get("args", [])
    assert "cli-contract-pkg" not in python_lock.get("stdout_contains", [])
    python_lockless = by_id["python-lockless"]
    assert any(
        "could not be fully analyzed" in str(n)
        for n in python_lockless.get("stderr_contains", [])
    )
    for case_id in (
        "python-empty-lock",
        "javascript-empty-lock",
        "java-empty-gradle-lock",
        "ruby-empty-lock",
    ):
        case = by_id[case_id]
        assert case.get("expect_exit") == [4]
        assert "--offline" not in case.get("args", [])
        assert UNQUALIFIED_NO_VULNS in (case.get("stdout_forbids") or [])


def test_isolated_env_path_contains_only_bin_dir(tmp_path: Path) -> None:
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    xdg = tmp_path / "xdg"
    env = isolated_env(binary, xdg)
    path_entries = env["PATH"].split(os.pathsep)
    assert len(path_entries) == 1
    assert Path(path_entries[0]).joinpath("vlz").is_file()
    assert env["XDG_CACHE_HOME"] == str(xdg)
    assert "VLZ_IGNORE_DB" in env


def test_run_argv_records_category(tmp_path: Path) -> None:
    script = tmp_path / "vlz"
    script.write_text(
        "#!/bin/sh\necho vlz 0.0.0\nexit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    case = {
        "id": "version",
        "category": "startup",
        "args": ["--version"],
        "expect_exit": [0],
        "stdout_contains": ["vlz"],
    }
    result = run_argv(script, case, tmp_path / "xdg")
    assert result.ok
    assert result.category == "startup"
    assert result.exit_code == 0


def test_run_argv_forbids_unqualified_no_vulns(tmp_path: Path) -> None:
    script = tmp_path / "vlz"
    script.write_text(
        f"#!/bin/sh\necho '{UNQUALIFIED_NO_VULNS}'\nexit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    case = {
        "id": "lockless",
        "category": "exit_code",
        "args": ["scan", "."],
        "expect_exit": [4],
        "stdout_forbids": [UNQUALIFIED_NO_VULNS],
    }
    result = run_argv(script, case, tmp_path / "xdg")
    assert not result.ok
    assert UNQUALIFIED_NO_VULNS in result.detail


def test_main_missing_binary_exits_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    missing = tmp_path / "no-such-vlz"
    code = main(["--binary", str(missing), "--mode", "smoke"])
    assert code == 2
    err = capsys.readouterr().err
    assert "binary not found" in err


def test_main_runs_registry_with_fake_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "vlz"
    script.write_text(
        "#!/bin/sh\n"
        "echo vlz 9.9.9\n"
        "echo python\n"
        "echo rust\n"
        "echo go\n"
        "echo javascript\n"
        "echo java\n"
        "echo ruby\n"
        "echo languages\n"
        "exit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)

    def fake_load(_root: Path) -> dict[str, object]:
        return {
            "cases": [
                {
                    "id": "version",
                    "category": "startup",
                    "modes": ["smoke"],
                    "args": ["--version"],
                    "expect_exit": [0],
                    "stdout_contains": ["vlz"],
                }
            ]
        }

    monkeypatch.setattr("scripts.cli_contract.load_registry", fake_load)
    code = main(
        ["--binary", str(script), "--mode", "smoke", "--root", str(_ROOT)]
    )
    assert code == 0


def test_case_result_failure_message() -> None:
    result = CaseResult(
        case_id="x",
        category="startup",
        ok=False,
        exit_code=1,
        detail="bad",
    )
    text = result.summary()
    assert "startup" in text
    assert "x" in text
    assert "bad" in text


def test_makefile_cli_contract_not_in_check() -> None:
    text = _MAKEFILE.read_text(encoding="utf-8")
    assert "\ncli-contract:" in text or text.startswith("cli-contract:")
    assert "cli-contract:" in text
    fast = text[text.index("check-fast-parallel:") : text.index("check-slow:")]
    parallel = text[text.index("check-parallel:") :]
    assert "cli-contract" not in fast
    assert "cli-contract" not in parallel.split("install:")[0]


def test_shell_bin_unknown() -> None:
    assert _shell_bin("definitely-not-a-shell-xyz") is None


def test_repo_root_from_default_and_override(tmp_path: Path) -> None:
    from scripts.cli_contract import repo_root_from

    assert repo_root_from(tmp_path) == tmp_path
    inferred = repo_root_from()
    assert (inferred / "scripts" / "cli_contract.py").is_file()


def test_bash_not_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "completions").mkdir()
    (tmp_path / "completions" / "vlz.bash").write_text("#\n", encoding="utf-8")
    monkeypatch.setattr("scripts.cli_contract._shell_bin", lambda _name: None)
    result = run_completion_shell(
        tmp_path,
        tmp_path / "vlz",
        {"id": "bash-skip", "shell": "bash"},
    )
    assert result.ok
    assert "bash not installed" in result.detail


def test_bash_completion_oserror(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "completions").mkdir()
    (tmp_path / "completions" / "vlz.bash").write_text(
        "_vlz() { COMPREPLY=(scan); }\n",
        encoding="utf-8",
    )

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("no exec")

    monkeypatch.setattr(
        "scripts.cli_contract._shell_bin", lambda _n: "/bin/true"
    )
    monkeypatch.setattr("scripts.cli_contract.subprocess.run", boom)
    result = run_completion_shell(
        tmp_path,
        tmp_path / "vlz",
        {"id": "bash-os", "shell": "bash"},
    )
    assert not result.ok
    assert "no exec" in result.detail


def test_zsh_and_fish_stub_shells(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completions = tmp_path / "completions"
    completions.mkdir()
    (completions / "_vlz").write_text("#\n", encoding="utf-8")
    (completions / "vlz.fish").write_text("#\n", encoding="utf-8")
    stub = tmp_path / "stub-shell"
    stub.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setattr(
        "scripts.cli_contract._shell_bin", lambda _n: str(stub)
    )
    zsh = run_completion_shell(
        tmp_path, tmp_path / "vlz", {"id": "zsh-stub", "shell": "zsh"}
    )
    fish = run_completion_shell(
        tmp_path, tmp_path / "vlz", {"id": "fish-stub", "shell": "fish"}
    )
    assert zsh.ok, zsh.detail
    assert fish.ok, fish.detail


def test_main_reports_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = tmp_path / "vlz"
    script.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    script.chmod(0o755)

    def fake_load(_root: Path) -> dict[str, object]:
        return {
            "cases": [
                {
                    "id": "version",
                    "category": "startup",
                    "modes": ["smoke"],
                    "args": ["--version"],
                    "expect_exit": [0],
                }
            ]
        }

    monkeypatch.setattr("scripts.cli_contract.load_registry", fake_load)
    code = main(
        ["--binary", str(script), "--mode", "smoke", "--root", str(_ROOT)]
    )
    assert code == 1
    assert "failed" in capsys.readouterr().err


def test_main_mode_value_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "vlz"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)

    def fake_load(_root: Path) -> dict[str, object]:
        return {
            "cases": [{"id": "x", "modes": ["smoke"], "args": ["--version"]}]
        }

    def boom(_reg: dict[str, object], _mode: str) -> list[dict[str, object]]:
        raise ValueError("unknown mode: x")

    monkeypatch.setattr("scripts.cli_contract.load_registry", fake_load)
    monkeypatch.setattr("scripts.cli_contract.cases_for_mode", boom)
    code = main(["--binary", str(script), "--root", str(_ROOT)])
    assert code == 2


def test_zsh_oserror(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "completions").mkdir()
    (tmp_path / "completions" / "_vlz").write_text("#\n", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("zsh boom")

    monkeypatch.setattr(
        "scripts.cli_contract._shell_bin", lambda _n: "/bin/true"
    )
    monkeypatch.setattr("scripts.cli_contract.subprocess.run", boom)
    result = run_completion_shell(
        tmp_path, tmp_path / "vlz", {"id": "zsh-os", "shell": "zsh"}
    )
    assert not result.ok
    assert "zsh boom" in result.detail


def test_fish_oserror(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "completions").mkdir()
    (tmp_path / "completions" / "vlz.fish").write_text("#\n", encoding="utf-8")

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("fish boom")

    monkeypatch.setattr(
        "scripts.cli_contract._shell_bin", lambda _n: "/bin/true"
    )
    monkeypatch.setattr("scripts.cli_contract.subprocess.run", boom)
    result = run_completion_shell(
        tmp_path, tmp_path / "vlz", {"id": "fish-os", "shell": "fish"}
    )
    assert not result.ok
    assert "fish boom" in result.detail


def test_main_infers_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "vlz"
    script.write_text(
        "#!/bin/sh\necho vlz\nexit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)

    def fake_load(_root: Path) -> dict[str, object]:
        return {
            "cases": [
                {
                    "id": "version",
                    "modes": ["smoke"],
                    "args": ["--version"],
                    "expect_exit": [0],
                    "stdout_contains": ["vlz"],
                }
            ]
        }

    monkeypatch.setattr("scripts.cli_contract.load_registry", fake_load)
    code = main(["--binary", str(script), "--mode", "smoke"])
    assert code == 0


def test_registry_json_is_object() -> None:
    path = _ROOT / "tests" / "cli_contract" / "registry.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(data["cases"], list)
    assert data["cases"]


def test_validate_registry_reports_missing_fixture(tmp_path: Path) -> None:
    registry = {
        "cases": [
            {
                "id": "missing",
                "args": ["scan", "{fixture}"],
                "fixture": "nope",
            }
        ]
    }
    errors = validate_registry(tmp_path, registry)
    assert errors
    assert "missing" in errors[0]


def test_validate_registry_reports_empty_args() -> None:
    registry = {"cases": [{"id": "bad", "args": []}]}
    errors = validate_registry(_ROOT, registry)
    assert any("args" in err for err in errors)


def test_substitute_args_requires_fixture() -> None:
    with pytest.raises(ValueError, match="fixture placeholder"):
        substitute_args(["scan", "{fixture}"], None)


def test_cases_for_mode_requires_list() -> None:
    with pytest.raises(ValueError, match="list"):
        cases_for_mode({"cases": {}}, "smoke")


def test_run_case_missing_fixture(tmp_path: Path) -> None:
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    result = run_case(
        _ROOT,
        binary,
        {
            "id": "gone",
            "category": "lock_parse",
            "fixture": "does-not-exist",
            "args": ["scan", "{fixture}"],
        },
    )
    assert not result.ok
    assert "missing fixture" in result.detail


def test_completion_shell_unknown() -> None:
    result = run_completion_shell(
        _ROOT,
        _ROOT / "Makefile",
        {"id": "x", "shell": "ksh"},
    )
    assert not result.ok
    assert "unknown shell" in result.detail


def test_completion_shell_skips_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("scripts.cli_contract.sys.platform", "win32")
    result = run_completion_shell(
        _ROOT,
        _ROOT / "Makefile",
        {"id": "bash-win", "shell": "bash"},
    )
    assert result.ok
    assert "skipped on Windows" in result.detail


def test_main_invalid_registry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)

    def fake_load(_root: Path) -> dict[str, object]:
        return {"cases": [{"id": "bad", "args": []}]}

    monkeypatch.setattr("scripts.cli_contract.load_registry", fake_load)
    code = main(["--binary", str(binary), "--root", str(_ROOT)])
    assert code == 2
    assert "args" in capsys.readouterr().err


def test_run_argv_oserror(tmp_path: Path) -> None:
    missing = tmp_path / "not-executable-dir"
    missing.mkdir()
    result = run_argv(
        missing,
        {"id": "boom", "category": "startup", "args": ["--version"]},
        tmp_path / "xdg",
    )
    assert not result.ok
    assert result.exit_code is None


def test_run_case_completion_kind(tmp_path: Path) -> None:
    completions = tmp_path / "completions"
    completions.mkdir()
    (completions / "vlz.bash").write_text(
        "_vlz() { COMPREPLY=(scan); }\n",
        encoding="utf-8",
    )
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    result = run_case(
        tmp_path,
        binary,
        {
            "id": "bash-kind",
            "kind": "completion_shell",
            "shell": "bash",
            "args": ["generate-completions", "bash"],
        },
    )
    assert result.ok, result.detail

    script = tmp_path / "vlz"
    script.write_text(
        "#!/bin/sh\necho out\necho err >&2\nexit 0\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    result = run_argv(
        script,
        {
            "id": "io",
            "category": "startup",
            "args": ["--help"],
            "expect_exit": [0],
            "stderr_contains": ["err"],
            "combined_contains": ["out"],
        },
        tmp_path / "xdg",
    )
    assert result.ok


def test_isolated_env_replaces_existing_copy(tmp_path: Path) -> None:
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    binary.chmod(0o755)
    xdg = tmp_path / "xdg"
    isolated_env(binary, xdg)
    isolated_env(binary, xdg)
    assert (xdg / "bin" / "vlz").is_file()


@pytest.mark.parametrize(
    ("stdout_contains", "expected_ok"),
    [(["scan"], True), (["missing"], False)],
)
def test_bash_completion_with_stub(
    tmp_path: Path, stdout_contains: list[str], expected_ok: bool
) -> None:
    completions = tmp_path / "completions"
    completions.mkdir()
    (completions / "vlz.bash").write_text(
        # Require $2/$3 like clap_complete under set -u (complete -F protocol).
        '_vlz() { : "$2" "$3"; COMPREPLY=(scan languages); }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    result = run_completion_shell(
        tmp_path,
        binary,
        {
            "id": "bash-stub",
            "shell": "bash",
            "stdout_contains": stdout_contains,
        },
    )
    assert result.ok is expected_ok, result.detail
    if not expected_ok:
        assert "completion missing" in result.detail


def test_bash_completion_allows_empty_reply(tmp_path: Path) -> None:
    completions = tmp_path / "completions"
    completions.mkdir()
    (completions / "vlz.bash").write_text(
        '_vlz() { : "$2" "$3"; COMPREPLY=(); }\n',
        encoding="utf-8",
    )
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    result = run_completion_shell(
        tmp_path,
        binary,
        {"id": "bash-empty-reply", "shell": "bash"},
    )
    assert result.ok, result.detail


def test_zsh_completion_missing_script(tmp_path: Path) -> None:
    result = run_completion_shell(
        tmp_path,
        tmp_path / "vlz",
        {"id": "zsh-miss", "shell": "zsh"},
    )
    assert not result.ok
    assert "missing completions/_vlz" in result.detail


def test_fish_completion_missing_script(tmp_path: Path) -> None:
    result = run_completion_shell(
        tmp_path,
        tmp_path / "vlz",
        {"id": "fish-miss", "shell": "fish"},
    )
    assert not result.ok
    assert "missing completions/vlz.fish" in result.detail


def test_zsh_completion_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "completions").mkdir()
    (tmp_path / "completions" / "_vlz").write_text("#\n", encoding="utf-8")
    monkeypatch.setattr("scripts.cli_contract._shell_bin", lambda _name: None)
    result = run_completion_shell(
        tmp_path,
        tmp_path / "vlz",
        {"id": "zsh-skip", "shell": "zsh"},
    )
    assert result.ok
    assert "zsh not installed" in result.detail


def test_fish_completion_not_installed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "completions").mkdir()
    (tmp_path / "completions" / "vlz.fish").write_text("#\n", encoding="utf-8")
    monkeypatch.setattr("scripts.cli_contract._shell_bin", lambda _name: None)
    result = run_completion_shell(
        tmp_path,
        tmp_path / "vlz",
        {"id": "fish-skip", "shell": "fish"},
    )
    assert result.ok
    assert "fish not installed" in result.detail


def test_run_argv_missing_needles(tmp_path: Path) -> None:
    script = tmp_path / "vlz"
    script.write_text("#!/bin/sh\necho hi\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    result = run_argv(
        script,
        {
            "id": "miss",
            "category": "startup",
            "args": ["--version"],
            "expect_exit": [0],
            "stdout_contains": ["nope"],
            "stderr_contains": ["nope"],
            "combined_contains": ["nope"],
        },
        tmp_path / "xdg",
    )
    assert not result.ok
    assert "stdout missing" in result.detail


def test_bash_completion_no_function(tmp_path: Path) -> None:
    completions = tmp_path / "completions"
    completions.mkdir()
    (completions / "vlz.bash").write_text("# empty\n", encoding="utf-8")
    binary = tmp_path / "vlz"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o755)
    result = run_completion_shell(
        tmp_path,
        binary,
        {"id": "bash-empty", "shell": "bash"},
    )
    assert not result.ok
