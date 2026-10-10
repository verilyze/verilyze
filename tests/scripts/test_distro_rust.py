# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/distro_rust.py."""

import json
import subprocess
from pathlib import Path

import pytest

from scripts.distro_rust import (
    DEFAULT_DISTRO_RUST_REL,
    DistroTarget,
    build_matrix,
    check_distro_rust,
    check_live,
    docker_probe_runner,
    extract_rust_version,
    load_distro_targets,
    main,
    parse_distro_targets,
    probe_target,
)
from scripts.obs_repositories import (
    DEFAULT_PACKAGE_META_REL,
    DEFAULT_PROJECT_META_REL,
)

_PROJECT_META = """\
<project name="home:example:proj">
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Tumbleweed" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
  <repository name="Fedora_44">
    <path project="Fedora:Rawhide" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
  <repository name="Fedora_43">
    <path project="Fedora:43" repository="standard"/>
    <arch>x86_64</arch>
  </repository>
</project>
"""

_PACKAGE_META = """\
<package name="verilyze" project="home:example:proj">
  <build>
    <disable repository="Fedora_43"/>
  </build>
</package>
"""

_DATA = """\
[targets.openSUSE_Tumbleweed]
distro = "openSUSE Tumbleweed"
rust_available = "1.98"
verified_at = "2026-10-10"
probe_image = "registry.example/tumbleweed:latest"
probe_command = "echo 1.98.1-1.1"
build_deps_command = "zypper -n install rust cargo"

[targets.Fedora_44]
distro = "Fedora Rawhide"
rust_available = "1.99"
verified_at = "2026-10-10"
probe_image = "registry.example/fedora:rawhide"
probe_command = "echo 1.99.0"
build_deps_command = "dnf -y install rust cargo"

[targets.Fedora_43]
distro = "Fedora 43"
verified_at = "2026-10-10"
probe_image = "registry.example/fedora:43"
probe_command = "echo 1.97.0"
build_deps_command = "dnf -y install rust cargo"
disabled_reason = "rust older than MSRV"
"""


def _write_repo(
    root: Path,
    *,
    msrv: str = "1.98",
    data: str = _DATA,
) -> None:
    (root / "Cargo.toml").write_text(
        f'[workspace.package]\nrust-version = "{msrv}"\n', encoding="utf-8"
    )
    for rel, text in (
        (DEFAULT_PROJECT_META_REL, _PROJECT_META),
        (DEFAULT_PACKAGE_META_REL, _PACKAGE_META),
        (DEFAULT_DISTRO_RUST_REL, data),
    ):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def test_parse_distro_targets_reads_fields() -> None:
    targets = parse_distro_targets(_DATA)
    tw = targets["openSUSE_Tumbleweed"]
    assert tw == DistroTarget(
        repository="openSUSE_Tumbleweed",
        distro="openSUSE Tumbleweed",
        rust_available=(1, 98),
        verified_at="2026-10-10",
        probe_image="registry.example/tumbleweed:latest",
        probe_command="echo 1.98.1-1.1",
        build_deps_command="zypper -n install rust cargo",
        disabled_reason=None,
    )
    assert targets["Fedora_43"].rust_available is None
    assert targets["Fedora_43"].disabled_reason == "rust older than MSRV"


def test_parse_distro_targets_requires_targets_table() -> None:
    with pytest.raises(ValueError, match="targets"):
        parse_distro_targets("title = 'x'\n")


def test_parse_distro_targets_requires_probe_fields() -> None:
    with pytest.raises(ValueError, match="probe_image"):
        parse_distro_targets(
            '[targets.X]\ndistro = "X"\nverified_at = "2026-01-01"\n'
        )


def test_load_distro_targets_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="distro-rust"):
        load_distro_targets(tmp_path)


def test_parse_distro_targets_requires_build_deps_command() -> None:
    with pytest.raises(ValueError, match="build_deps_command"):
        parse_distro_targets(
            '[targets.X]\ndistro = "X"\nverified_at = "2026-01-01"\n'
            'probe_image = "i"\nprobe_command = "c"\n'
        )


def test_build_matrix_lists_enabled_targets_only(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    assert build_matrix(tmp_path) == [
        {
            "repository": "Fedora_44",
            "distro": "Fedora Rawhide",
            "image": "registry.example/fedora:rawhide",
            "deps_command": "dnf -y install rust cargo",
        },
        {
            "repository": "openSUSE_Tumbleweed",
            "distro": "openSUSE Tumbleweed",
            "image": "registry.example/tumbleweed:latest",
            "deps_command": "zypper -n install rust cargo",
        },
    ]


def test_main_matrix_json_prints_enabled_targets(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_repo(tmp_path)
    assert main(["--repo-root", str(tmp_path), "--matrix-json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [row["repository"] for row in payload["include"]] == [
        "Fedora_44",
        "openSUSE_Tumbleweed",
    ]


def test_check_passes_when_msrv_within_enabled_targets(tmp_path: Path) -> None:
    _write_repo(tmp_path, msrv="1.98")
    assert check_distro_rust(tmp_path) == []


def test_check_fails_when_msrv_exceeds_enabled_target(tmp_path: Path) -> None:
    _write_repo(tmp_path, msrv="1.99")
    errors = check_distro_rust(tmp_path)
    assert len(errors) == 1
    assert "openSUSE_Tumbleweed" in errors[0]
    assert "1.99" in errors[0]
    assert "1.98" in errors[0]


def test_check_ignores_disabled_target_below_msrv(tmp_path: Path) -> None:
    _write_repo(tmp_path, msrv="1.98")
    assert check_distro_rust(tmp_path) == []


def test_check_reports_enabled_target_without_data(tmp_path: Path) -> None:
    data = _DATA.split("[targets.Fedora_44]")[0]
    _write_repo(tmp_path, data=data)
    errors = check_distro_rust(tmp_path)
    assert any("Fedora_44" in err and "distro-rust.toml" in err for err in errors)


def test_check_reports_enabled_target_without_rust_available(
    tmp_path: Path,
) -> None:
    data = _DATA.replace('rust_available = "1.99"\n', "")
    _write_repo(tmp_path, data=data)
    errors = check_distro_rust(tmp_path)
    assert any("Fedora_44" in err and "rust_available" in err for err in errors)


def test_check_reports_unknown_repository_in_data(tmp_path: Path) -> None:
    data = _DATA + (
        '\n[targets.Ghost]\ndistro = "Ghost"\nverified_at = "2026-01-01"\n'
        'probe_image = "x"\nprobe_command = "y"\nbuild_deps_command = "z"\n'
    )
    _write_repo(tmp_path, data=data)
    errors = check_distro_rust(tmp_path)
    assert any("Ghost" in err and "project _meta" in err for err in errors)


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("1.98.1-1.1\n", (1, 98)),
        ("\n\nVersion : 1.99.0\n", (1, 99)),
        ("rust 1.100.2", (1, 100)),
        ("", None),
        ("no version here", None),
    ],
)
def test_extract_rust_version(
    output: str, expected: tuple[int, int] | None
) -> None:
    assert extract_rust_version(output) == expected


def _target(command: str = "echo 1.98.1") -> DistroTarget:
    return DistroTarget(
        repository="openSUSE_Tumbleweed",
        distro="openSUSE Tumbleweed",
        rust_available=(1, 98),
        verified_at="2026-10-10",
        probe_image="registry.example/tumbleweed:latest",
        probe_command=command,
        build_deps_command="zypper -n install rust cargo",
        disabled_reason=None,
    )


def test_probe_target_returns_version_from_runner() -> None:
    seen: list[DistroTarget] = []

    def runner(target: DistroTarget) -> str:
        seen.append(target)
        return "Version : 1.98.1-1.1\n"

    assert probe_target(_target(), runner) == (1, 98)
    assert seen == [_target()]


def test_probe_target_rejects_unparseable_output() -> None:
    with pytest.raises(ValueError, match="openSUSE_Tumbleweed"):
        probe_target(_target(), lambda _t: "package not found")


def test_check_live_passes_when_probe_meets_msrv(tmp_path: Path) -> None:
    _write_repo(tmp_path, msrv="1.98")
    versions = {
        "registry.example/tumbleweed:latest": "1.98.1\n",
        "registry.example/fedora:rawhide": "1.99.0\n",
    }
    errors = check_live(tmp_path, lambda t: versions[t.probe_image])
    assert errors == []


def test_check_live_fails_when_probe_below_msrv(tmp_path: Path) -> None:
    _write_repo(tmp_path, msrv="1.99")
    errors = check_live(tmp_path, lambda _t: "1.98.1\n")
    assert any("openSUSE_Tumbleweed" in err and "1.98" in err for err in errors)


def test_check_live_reports_probe_failure(tmp_path: Path) -> None:
    _write_repo(tmp_path)

    def runner(_t: DistroTarget) -> str:
        msg = "docker unavailable"
        raise RuntimeError(msg)

    errors = check_live(tmp_path, runner)
    assert any("docker unavailable" in err for err in errors)


def test_docker_probe_runner_invokes_docker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        cmd: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="1.98.1\n", stderr="")

    monkeypatch.setattr("scripts.distro_rust.subprocess.run", fake_run)
    out = docker_probe_runner(_target("echo 1.98.1"))
    assert out == "1.98.1\n"
    assert calls == [
        [
            "docker",
            "run",
            "--rm",
            "registry.example/tumbleweed:latest",
            "sh",
            "-c",
            "echo 1.98.1",
        ]
    ]


def test_docker_probe_runner_raises_on_nonzero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        cmd: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, 3, stdout="", stderr="boom")

    monkeypatch.setattr("scripts.distro_rust.subprocess.run", fake_run)
    with pytest.raises(RuntimeError, match="boom"):
        docker_probe_runner(_target())


def test_main_offline_ok(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_repo(tmp_path)
    assert main(["--repo-root", str(tmp_path)]) == 0
    assert "MSRV 1.98" in capsys.readouterr().out


def test_main_offline_fails_and_prints_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_repo(tmp_path, msrv="1.99")
    assert main(["--repo-root", str(tmp_path)]) == 1
    assert "openSUSE_Tumbleweed" in capsys.readouterr().err


def test_main_live_uses_probe_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_repo(tmp_path)
    monkeypatch.setattr(
        "scripts.distro_rust.docker_probe_runner", lambda _t: "1.99.0\n"
    )
    assert main(["--repo-root", str(tmp_path), "--live"]) == 0
    assert "live" in capsys.readouterr().out


def test_main_reports_missing_data_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "Cargo.toml").write_text(
        '[workspace.package]\nrust-version = "1.98"\n', encoding="utf-8"
    )
    assert main(["--repo-root", str(tmp_path)]) == 1
    assert "distro-rust" in capsys.readouterr().err


def test_repository_data_satisfies_gate() -> None:
    root = Path(__file__).resolve().parent.parent.parent
    assert check_distro_rust(root) == []


def test_parse_distro_targets_rejects_non_table_entry() -> None:
    with pytest.raises(ValueError, match="must be a table"):
        parse_distro_targets('[targets]\nX = "not-a-table"\n')


def test_build_matrix_skips_enabled_target_without_data(
    tmp_path: Path,
) -> None:
    data = _DATA.split("[targets.Fedora_44]")[0]
    _write_repo(tmp_path, data=data)
    assert [row["repository"] for row in build_matrix(tmp_path)] == [
        "openSUSE_Tumbleweed"
    ]


def test_check_live_skips_enabled_target_without_data(tmp_path: Path) -> None:
    data = _DATA.split("[targets.Fedora_44]")[0]
    _write_repo(tmp_path, data=data)
    assert check_live(tmp_path, lambda _t: "1.98.1\n") == []


def test_main_matrix_json_reports_missing_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--repo-root", str(tmp_path), "--matrix-json"]) == 1
    assert "distro-rust" in capsys.readouterr().err
