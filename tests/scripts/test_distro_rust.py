# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/distro_rust.py."""

import json
import subprocess
from pathlib import Path

import pytest

import urllib.error

from scripts.distro_rust import (
    DEFAULT_DISTRO_RUST_REL,
    OBS_PUBLIC_BUILD_API,
    PROBE_KIND_CONTAINER,
    PROBE_KIND_OBS,
    CanaryTarget,
    DistroTarget,
    build_canary_matrix,
    build_matrix,
    check_distro_rust,
    check_live,
    default_http_fetcher,
    docker_probe_runner,
    extract_rust_version,
    highest_versioned_rust_package,
    load_canary_targets,
    load_distro_targets,
    main,
    obs_binarylist_has_msrv_packages,
    obs_probe_target,
    parse_binarylist_filenames,
    parse_canary_targets,
    parse_directory_entry_names,
    parse_distro_targets,
    parse_versioned_rust_package_name,
    probe_target,
    versioned_rust_package_name,
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
probe_kind = "obs"
obs_project = "openSUSE:Factory"
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

[canaries.Alpine]
distro = "Alpine Linux"
probe_image = "docker.io/library/alpine:latest"
build_deps_command = "apk add --no-cache rust cargo gcc make git openssl-dev"

[canaries.Arch]
distro = "Arch Linux"
probe_image = "docker.io/library/archlinux:latest"
build_deps_command = "pacman -Sy --noconfirm rust cargo gcc make git openssl"
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
        probe_kind=PROBE_KIND_OBS,
        obs_project="openSUSE:Factory",
        obs_repository=None,
        probe_image="registry.example/tumbleweed:latest",
        probe_command="echo 1.98.1-1.1",
        build_deps_command="zypper -n install rust cargo",
        disabled_reason=None,
    )
    assert targets["Fedora_44"].probe_kind == PROBE_KIND_CONTAINER
    assert targets["Fedora_43"].rust_available is None
    assert targets["Fedora_43"].disabled_reason == "rust older than MSRV"


def test_parse_canary_targets_reads_non_obs_rows() -> None:
    canaries = parse_canary_targets(_DATA)
    assert canaries["Alpine"] == CanaryTarget(
        name="Alpine",
        distro="Alpine Linux",
        probe_image="docker.io/library/alpine:latest",
        build_deps_command=(
            "apk add --no-cache rust cargo gcc make git openssl-dev"
        ),
    )
    assert "Arch" in canaries


def test_canaries_do_not_fail_project_meta_cross_check(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    assert check_distro_rust(tmp_path) == []


def test_build_canary_matrix_includes_disabled_obs_and_canaries(
    tmp_path: Path,
) -> None:
    _write_repo(tmp_path)
    rows = build_canary_matrix(tmp_path)
    names = {row["name"] for row in rows}
    assert names == {"Fedora_43", "Alpine", "Arch"}
    alpine = next(row for row in rows if row["name"] == "Alpine")
    assert alpine["image"] == "docker.io/library/alpine:latest"


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


def _target(
    command: str = "echo 1.98.1",
    *,
    probe_kind: str = PROBE_KIND_CONTAINER,
    obs_project: str | None = None,
    rust_available: tuple[int, int] | None = (1, 98),
) -> DistroTarget:
    return DistroTarget(
        repository="openSUSE_Tumbleweed",
        distro="openSUSE Tumbleweed",
        rust_available=rust_available,
        verified_at="2026-10-10",
        probe_kind=probe_kind,
        obs_project=obs_project,
        obs_repository=None,
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
    data = _DATA.replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    )
    _write_repo(tmp_path, msrv="1.98", data=data)
    versions = {
        "registry.example/tumbleweed:latest": "1.98.1\n",
        "registry.example/fedora:rawhide": "1.99.0\n",
    }
    errors, notes = check_live(tmp_path, lambda t: versions[t.probe_image])
    assert errors == []
    assert notes == []


def test_check_live_fails_when_probe_below_msrv(tmp_path: Path) -> None:
    data = _DATA.replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    )
    _write_repo(tmp_path, msrv="1.99", data=data)
    errors, _notes = check_live(tmp_path, lambda _t: "1.98.1\n")
    assert any("openSUSE_Tumbleweed" in err and "1.98" in err for err in errors)


def test_check_live_reports_probe_failure(tmp_path: Path) -> None:
    data = _DATA.replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    )
    _write_repo(tmp_path, data=data)

    def runner(_t: DistroTarget) -> str:
        msg = "docker unavailable"
        raise RuntimeError(msg)

    errors, _notes = check_live(tmp_path, runner)
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
    data = _DATA.split("[targets.Fedora_44]")[0].replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    )
    _write_repo(tmp_path, data=data)
    assert check_live(tmp_path, lambda _t: "1.98.1\n") == ([], [])


def test_main_matrix_json_reports_missing_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--repo-root", str(tmp_path), "--matrix-json"]) == 1
    assert "distro-rust" in capsys.readouterr().err


def test_versioned_rust_package_name_formats_suse_style() -> None:
    assert versioned_rust_package_name((1, 98)) == "rust1.98"


def test_parse_versioned_rust_package_name() -> None:
    assert parse_versioned_rust_package_name("rust1.98") == (1, 98)
    assert parse_versioned_rust_package_name("rust1.98:test") is None
    assert parse_versioned_rust_package_name("rust") is None


def test_parse_binarylist_filenames() -> None:
    xml = """\
<binarylist>
  <binary filename="rust1.98-1.98.1-1.1.x86_64.rpm"/>
  <binary filename="cargo1.98-1.98.1-1.1.x86_64.rpm"/>
  <binary filename="_statistics"/>
</binarylist>
"""
    names = parse_binarylist_filenames(xml)
    assert "rust1.98-1.98.1-1.1.x86_64.rpm" in names
    assert "cargo1.98-1.98.1-1.1.x86_64.rpm" in names
    assert "_statistics" not in names


def test_parse_binarylist_filenames_rejects_empty_and_bad_xml() -> None:
    with pytest.raises(ValueError, match="empty binarylist"):
        parse_binarylist_filenames("<binarylist/>")
    with pytest.raises(ValueError, match="not well-formed"):
        parse_binarylist_filenames("<binarylist>")


def test_obs_binarylist_has_msrv_packages() -> None:
    names = frozenset(
        {
            "rust1.98-1.98.1-1.1.x86_64.rpm",
            "cargo1.98-1.98.1-1.1.x86_64.rpm",
        }
    )
    assert obs_binarylist_has_msrv_packages(names, (1, 98))
    assert not obs_binarylist_has_msrv_packages(
        frozenset({"rust1.98-1.98.1-1.1.x86_64.rpm"}), (1, 98)
    )


def test_highest_versioned_rust_package() -> None:
    entries = ("rust1.97", "rust1.98", "rust", "rust1.98:test", "cargo")
    assert highest_versioned_rust_package(entries) == (1, 98)


def test_obs_probe_target_checks_msrv_packages_and_highest(
    tmp_path: Path,
) -> None:
    _write_repo(tmp_path, msrv="1.98")
    responses = {
        f"{OBS_PUBLIC_BUILD_API}/openSUSE:Factory/standard/x86_64": """\
<directory>
  <entry name="rust1.97"/>
  <entry name="rust1.98"/>
  <entry name="rust"/>
</directory>
""",
        (
            f"{OBS_PUBLIC_BUILD_API}/openSUSE:Factory/standard/x86_64/rust1.98"
        ): """\
<binarylist>
  <binary filename="rust1.98-1.98.1-1.1.x86_64.rpm"/>
  <binary filename="cargo1.98-1.98.1-1.1.x86_64.rpm"/>
</binarylist>
""",
    }

    def fetch(url: str) -> str:
        try:
            return responses[url]
        except KeyError as exc:
            raise RuntimeError(f"unexpected URL {url}") from exc

    target = _target(
        probe_kind=PROBE_KIND_OBS, obs_project="openSUSE:Factory"
    )
    probed = obs_probe_target(
        tmp_path, target, msrv=(1, 98), fetcher=fetch
    )
    assert probed == (1, 98)


def test_obs_probe_target_fails_when_msrv_packages_missing(
    tmp_path: Path,
) -> None:
    _write_repo(tmp_path)
    responses = {
        f"{OBS_PUBLIC_BUILD_API}/openSUSE:Factory/standard/x86_64": """\
<directory>
  <entry name="rust1.97"/>
</directory>
""",
        (
            f"{OBS_PUBLIC_BUILD_API}/openSUSE:Factory/standard/x86_64/rust1.98"
        ): "<binarylist/>",
    }

    def fetch(url: str) -> str:
        body = responses.get(url)
        if body is None:
            raise RuntimeError(f"HTTP 404 for {url}")
        return body

    with pytest.raises(ValueError, match="rust1.98"):
        obs_probe_target(
            tmp_path,
            _target(probe_kind=PROBE_KIND_OBS, obs_project="openSUSE:Factory"),
            msrv=(1, 98),
            fetcher=fetch,
        )


def test_obs_probe_target_fails_when_arches_disagree(tmp_path: Path) -> None:
    meta = """\
<project name="home:example:proj">
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Tumbleweed" repository="standard"/>
    <arch>x86_64</arch>
    <arch>aarch64</arch>
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
    _write_repo(tmp_path)
    (tmp_path / DEFAULT_PROJECT_META_REL).write_text(meta, encoding="utf-8")

    def fetch(url: str) -> str:
        if url.endswith("/x86_64"):
            return (
                '<directory><entry name="rust1.98"/>'
                '<entry name="rust1.99"/></directory>'
            )
        if url.endswith("/aarch64"):
            return '<directory><entry name="rust1.98"/></directory>'
        if url.endswith("rust1.98"):
            return """\
<binarylist>
  <binary filename="rust1.98-1.98.1-1.1.rpm"/>
  <binary filename="cargo1.98-1.98.1-1.1.rpm"/>
</binarylist>
"""
        raise RuntimeError(f"unexpected {url}")

    with pytest.raises(ValueError, match="architectures disagree"):
        obs_probe_target(
            tmp_path,
            _target(probe_kind=PROBE_KIND_OBS, obs_project="openSUSE:Factory"),
            msrv=(1, 98),
            fetcher=fetch,
        )


def test_check_live_fails_when_probe_below_rust_available(
    tmp_path: Path,
) -> None:
    # Tumbleweed claims 1.98 but live container reports 1.97.
    data = _DATA.replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    ).replace(
        'probe_command = "echo 1.98.1-1.1"\n',
        'probe_command = "echo 1.97.0"\n',
    )
    _write_repo(tmp_path, msrv="1.98", data=data)
    errors, _notes = check_live(tmp_path, lambda _t: "1.97.0\n")
    assert any(
        "rust_available" in err and "openSUSE_Tumbleweed" in err
        for err in errors
    )


def test_check_live_returns_raise_notes_when_live_ahead(
    tmp_path: Path,
) -> None:
    data = _DATA.replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    )
    _write_repo(tmp_path, data=data)
    errors, notes = check_live(tmp_path, lambda _t: "1.99.0\n")
    assert errors == []
    assert any("rust_available" in note and "1.99" in note for note in notes)


def test_main_live_uses_obs_fetcher_for_obs_targets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _write_repo(tmp_path)

    def fake_obs(
        repo_root: Path,
        target: DistroTarget,
        *,
        msrv: tuple[int, int],
        fetcher: object,
    ) -> tuple[int, int]:
        assert target.probe_kind == PROBE_KIND_OBS
        assert msrv == (1, 98)
        return (1, 98)

    monkeypatch.setattr("scripts.distro_rust.obs_probe_target", fake_obs)
    monkeypatch.setattr(
        "scripts.distro_rust.docker_probe_runner",
        lambda t: "1.99.0\n",
    )
    assert main(["--repo-root", str(tmp_path), "--live"]) == 0
    out = capsys.readouterr().out
    assert "live" in out


def test_load_canary_targets_from_repo(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    canaries = load_canary_targets(tmp_path)
    assert set(canaries) == {"Alpine", "Arch"}


def test_parse_distro_targets_rejects_unknown_probe_kind() -> None:
    with pytest.raises(ValueError, match="probe_kind"):
        parse_distro_targets(
            '[targets.X]\ndistro = "X"\nverified_at = "2026-01-01"\n'
            'probe_kind = "nope"\nprobe_image = "i"\nprobe_command = "c"\n'
            'build_deps_command = "d"\n'
        )


def test_main_canary_matrix_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _write_repo(tmp_path)
    assert main(["--repo-root", str(tmp_path), "--canary-matrix-json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert {row["name"] for row in payload["include"]} == {
        "Fedora_43",
        "Alpine",
        "Arch",
    }


def test_parse_canary_targets_empty_when_absent() -> None:
    assert parse_canary_targets(_DATA.split("[canaries.Alpine]")[0]) == {}


def test_parse_canary_targets_rejects_bad_shape() -> None:
    with pytest.raises(ValueError, match="canaries"):
        parse_canary_targets("canaries = 'nope'\n")
    with pytest.raises(ValueError, match="must be a table"):
        parse_canary_targets("[canaries]\nX = 'nope'\n")


def test_load_canary_targets_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="distro-rust"):
        load_canary_targets(tmp_path)


def test_optional_obs_project_rejects_empty() -> None:
    with pytest.raises(ValueError, match="obs_project"):
        parse_distro_targets(
            '[targets.X]\ndistro = "X"\nverified_at = "2026-01-01"\n'
            'obs_project = ""\nprobe_image = "i"\nprobe_command = "c"\n'
            'build_deps_command = "d"\n'
        )


def test_parse_binarylist_rejects_wrong_root() -> None:
    with pytest.raises(ValueError, match="binarylist"):
        parse_binarylist_filenames("<directory/>")


def test_parse_directory_entry_names() -> None:
    names = parse_directory_entry_names(
        '<directory><entry name="rust1.98"/><entry name=""/></directory>'
    )
    assert names == ("rust1.98",)


def test_parse_directory_entry_names_errors() -> None:
    with pytest.raises(ValueError, match="not well-formed"):
        parse_directory_entry_names("<directory>")
    with pytest.raises(ValueError, match="OBS build API error"):
        parse_directory_entry_names(
            '<status code="404"><summary>missing</summary></status>'
        )
    with pytest.raises(ValueError, match="directory"):
        parse_directory_entry_names("<binarylist/>")


def test_default_http_fetcher_maps_http_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeHTTPError(urllib.error.HTTPError):
        def __init__(self) -> None:
            super().__init__(
                "https://example.test", 404, "nope", hdrs=None, fp=None
            )

        def read(self) -> bytes:
            return b"gone"

    def boom(_request: object, timeout: float = 0) -> object:
        raise FakeHTTPError()

    monkeypatch.setattr("scripts.distro_rust.urllib.request.urlopen", boom)
    with pytest.raises(RuntimeError, match="HTTP 404"):
        default_http_fetcher("https://example.test/x")


def test_default_http_fetcher_maps_url_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(_request: object, timeout: float = 0) -> object:
        raise urllib.error.URLError("offline")

    monkeypatch.setattr("scripts.distro_rust.urllib.request.urlopen", boom)
    with pytest.raises(RuntimeError, match="HTTP error"):
        default_http_fetcher("https://example.test/x")


def test_obs_probe_target_missing_path(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    target = DistroTarget(
        repository="Ghost",
        distro="Ghost",
        rust_available=(1, 98),
        verified_at="2026-10-10",
        probe_kind=PROBE_KIND_OBS,
        obs_project="openSUSE:Factory",
        obs_repository=None,
        probe_image="i",
        probe_command="c",
        build_deps_command="d",
        disabled_reason=None,
    )
    with pytest.raises(ValueError, match="missing from project _meta"):
        obs_probe_target(
            tmp_path, target, msrv=(1, 98), fetcher=lambda _u: ""
        )


def test_obs_probe_target_no_versioned_packages(tmp_path: Path) -> None:
    _write_repo(tmp_path)

    def fetch(url: str) -> str:
        if url.endswith("/x86_64"):
            return '<directory><entry name="cargo"/></directory>'
        raise RuntimeError(url)

    with pytest.raises(ValueError, match="no rustX.Y"):
        obs_probe_target(
            tmp_path,
            _target(probe_kind=PROBE_KIND_OBS, obs_project="openSUSE:Factory"),
            msrv=(1, 98),
            fetcher=fetch,
        )


def test_obs_probe_target_lacks_cargo_rpm(tmp_path: Path) -> None:
    _write_repo(tmp_path)

    def fetch(url: str) -> str:
        if url.endswith("/x86_64"):
            return '<directory><entry name="rust1.98"/></directory>'
        if url.endswith("rust1.98"):
            return (
                "<binarylist>"
                '<binary filename="rust1.98-1.98.1-1.1.x86_64.rpm"/>'
                "</binarylist>"
            )
        raise RuntimeError(url)

    with pytest.raises(ValueError, match="lacks rust1.98 and cargo1.98"):
        obs_probe_target(
            tmp_path,
            _target(probe_kind=PROBE_KIND_OBS, obs_project="openSUSE:Factory"),
            msrv=(1, 98),
            fetcher=fetch,
        )


def test_main_canary_matrix_json_missing_data(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--repo-root", str(tmp_path), "--canary-matrix-json"]) == 1
    assert "distro-rust" in capsys.readouterr().err


def test_main_live_prints_raise_notes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data = _DATA.replace(
        'probe_kind = "obs"\nobs_project = "openSUSE:Factory"\n', ""
    )
    _write_repo(tmp_path, data=data)
    monkeypatch.setattr(
        "scripts.distro_rust.docker_probe_runner",
        lambda _t: "1.99.0\n",
    )
    assert main(["--repo-root", str(tmp_path), "--live"]) == 0
    out = capsys.readouterr().out
    assert "NOTE:" in out
    assert "can raise rust_available" in out
