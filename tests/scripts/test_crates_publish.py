# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for scripts/crates_publish.py."""

import subprocess
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from scripts.crates_publish import (
    PUBLISH_RATE_LIMIT_FALLBACK_SECS,
    PUBLISH_RATE_LIMIT_MAX_WAIT_SECS,
    PUBLISH_RATE_LIMIT_SKEW_SECS,
    _wait_secs_until_retry_at,
    PUBLISHED_CRATE_NAMES,
    check_crates_publish,
    crate_already_on_registry,
    crate_registry_search_query,
    default_feature_set,
    discover_crate_manifests,
    is_publish_duplicate_error,
    is_publish_rate_limit_error,
    leaf_crates,
    list_vlz_package_binaries,
    main,
    parse_internal_dependencies,
    parse_publish_retry_after_secs,
    publish_crate_with_retry,
    publish_order,
    publish_release_crates,
    run_cargo_package,
    rust_version_from_toolchain_channel,
    validate_crate_descriptions,
    validate_manifest_publish_flags,
    validate_registry_metadata,
    validate_vlz_assets,
    validate_vlz_install_binaries,
    validate_workspace_dep_versions,
)


@pytest.fixture
def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_published_crate_manifests_exist(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    assert set(manifests) == set(PUBLISHED_CRATE_NAMES)


def test_publish_order_is_bottom_up(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    ordered = publish_order(manifests)
    index = {name: pos for pos, name in enumerate(ordered)}
    for name, path in manifests.items():
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        deps = data.get("dependencies", {})
        if not isinstance(deps, dict):
            continue
        for dep_name, spec in deps.items():
            if dep_name not in manifests:
                continue
            assert (
                index[dep_name] < index[name]
            ), f"{dep_name} must precede {name}"


def test_workspace_internal_dep_versions_match_workspace(
    repo_root: Path,
) -> None:
    assert validate_workspace_dep_versions(repo_root) == []


def test_production_crates_are_publishable(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    assert validate_manifest_publish_flags(manifests) == []


def test_published_crates_inherit_registry_metadata(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    assert validate_registry_metadata(repo_root, manifests) == []


def test_published_crate_descriptions_name_verilyze(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    assert validate_crate_descriptions(manifests) == []


def test_vlz_assets_are_in_sync(repo_root: Path) -> None:
    assert validate_vlz_assets(repo_root) == []


def test_vlz_default_install_exposes_only_vlz_binary(repo_root: Path) -> None:
    assert validate_vlz_install_binaries(repo_root) == []


def test_default_features_exclude_manpage_gen(repo_root: Path) -> None:
    manifest = repo_root / "crates" / "core" / "vlz" / "Cargo.toml"
    defaults = default_feature_set(manifest)
    assert "manpage-gen" not in defaults
    assert list_vlz_package_binaries("vlz", repo_root) == {"vlz"}


def test_publish_order_starts_with_leaf_crates(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    ordered = publish_order(manifests)
    leaves = set(leaf_crates(manifests))
    assert ordered[0] in leaves
    assert ordered[-1] == "vlz"


def test_leaf_crates_have_no_internal_dependencies(repo_root: Path) -> None:
    manifests = discover_crate_manifests(repo_root)
    for name in leaf_crates(manifests):
        assert parse_internal_dependencies(manifests[name]) == set()


def test_crate_registry_search_query_includes_version() -> None:
    assert crate_registry_search_query("vlz-db", "0.9.1") == "vlz-db =0.9.1"


def test_validate_registry_metadata_reports_missing_inheritance(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "Cargo.toml"
    workspace.write_text(
        "[workspace.package]\n"
        'keywords = ["cve"]\n'
        'categories = ["development-tools"]\n'
        'readme = "README.md"\n'
        'rust-version = "1.98"\n',
        encoding="utf-8",
    )
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.98.0"\n',
        encoding="utf-8",
    )
    crate = tmp_path / "crates" / "core" / "vlz-db"
    crate.mkdir(parents=True)
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "vlz-db"\ndescription = "db for verilyze"\n',
        encoding="utf-8",
    )
    errors = validate_registry_metadata(
        tmp_path, {"vlz-db": crate / "Cargo.toml"}
    )
    assert any("keywords" in err for err in errors)
    assert any("categories" in err for err in errors)
    assert any("readme" in err for err in errors)
    assert any("rust-version" in err for err in errors)


def test_rust_version_from_toolchain_channel() -> None:
    assert rust_version_from_toolchain_channel("1.98.0") == "1.98"
    assert rust_version_from_toolchain_channel("nightly") == "nightly"


def test_validate_registry_metadata_rejects_rust_version_mismatch(
    tmp_path: Path,
) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "[workspace.package]\n"
        'keywords = ["cve"]\n'
        'categories = ["development-tools"]\n'
        'readme = "README.md"\n'
        'rust-version = "1.85"\n',
        encoding="utf-8",
    )
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.98.0"\n',
        encoding="utf-8",
    )
    errors = validate_registry_metadata(tmp_path, {})
    assert any("expected '1.98'" in err for err in errors)


def test_validate_crate_descriptions_requires_verilyze(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(
        '[package]\nname = "vlz-db"\ndescription = "DatabaseBackend trait"\n',
        encoding="utf-8",
    )
    errors = validate_crate_descriptions({"vlz-db": manifest})
    assert errors
    assert "verilyze" in errors[0]


def test_validate_crate_descriptions_rejects_en_dash(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(
        '[package]\nname = "vlz-report"\n'
        'description = "Reporting trait for verilyze – renders JSON"\n',
        encoding="utf-8",
    )
    errors = validate_crate_descriptions({"vlz-report": manifest})
    assert errors
    assert "dash" in errors[0]


def test_validate_crate_descriptions_rejects_missing_description(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text('[package]\nname = "vlz-db"\n', encoding="utf-8")
    errors = validate_crate_descriptions({"vlz-db": manifest})
    assert errors == ["vlz-db: missing package.description"]


def test_validate_registry_metadata_reports_missing_package_table(
    tmp_path: Path,
) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "[workspace.package]\n"
        'keywords = ["cve"]\n'
        'categories = ["development-tools"]\n'
        'readme = "README.md"\n'
        'rust-version = "1.98"\n',
        encoding="utf-8",
    )
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.98.0"\n',
        encoding="utf-8",
    )
    crate = tmp_path / "Cargo-crate.toml"
    crate.write_text('package = "not-a-table"\n', encoding="utf-8")
    errors = validate_registry_metadata(tmp_path, {"vlz-db": crate})
    assert any("missing [package] table" in err for err in errors)


def test_validate_registry_metadata_reports_missing_workspace_field(
    tmp_path: Path,
) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "[workspace.package]\n"
        'categories = ["development-tools"]\n'
        'readme = "README.md"\n'
        'rust-version = "1.98"\n',
        encoding="utf-8",
    )
    (tmp_path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "1.98.0"\n',
        encoding="utf-8",
    )
    errors = validate_registry_metadata(tmp_path, {})
    assert any("workspace.package.keywords" in err for err in errors)


def test_validate_registry_metadata_handles_missing_toolchain(
    tmp_path: Path,
) -> None:
    (tmp_path / "Cargo.toml").write_text(
        "[workspace.package]\n"
        'keywords = ["cve"]\n'
        'categories = ["development-tools"]\n'
        'readme = "README.md"\n'
        'rust-version = "1.98"\n',
        encoding="utf-8",
    )
    assert validate_registry_metadata(tmp_path, {}) == []


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            "error: crate version `0.9.1` is already uploaded on crates.io index",
            True,
        ),
        ("version 0.9.1 already exists on crates.io", True),
        ("error: failed to verify compressed package", False),
    ],
)
def test_is_publish_duplicate_error(output: str, expected: bool) -> None:
    assert is_publish_duplicate_error(output) is expected


MODERN_429_ERROR = (
    "the remote server responded with an error (status 429 Too Many "
    "Requests): You have published too many updates to existing crates in a "
    "short period of time. Please try again after Mon, 30 Mar 2026 21:36:35 "
    "GMT and see https://crates.io/docs/rate-limits for more details."
)


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (MODERN_429_ERROR, True),
        ("error: failed to get a 200 OK response, got 429\nbody:\n", True),
        ("error: failed to verify compressed package", False),
        ("too many dependencies in this manifest", False),
        ("error: failed to get a 200 OK response, got 4290", False),
    ],
)
def test_is_publish_rate_limit_error(output: str, expected: bool) -> None:
    assert is_publish_rate_limit_error(output) is expected


def test_parse_publish_retry_after_secs_future_date() -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    retry_at = datetime(2026, 3, 30, 21, 36, 35, tzinfo=UTC)
    expected = int((retry_at - now).total_seconds()) + PUBLISH_RATE_LIMIT_SKEW_SECS
    assert (
        parse_publish_retry_after_secs(
            "Please try again after Mon, 30 Mar 2026 21:36:35 GMT",
            now=now,
        )
        == expected
    )


def test_parse_publish_retry_after_secs_accepts_utc_suffix() -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    assert (
        parse_publish_retry_after_secs(
            "Please try again after Mon, 30 Mar 2026 21:36:35 UTC",
            now=now,
        )
        == 400
    )


def test_parse_publish_retry_after_secs_or_email_variant() -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    message = (
        "Please try again after Mon, 30 Mar 2026 21:36:35 GMT or email "
        "help@crates.io to have your limit increased."
    )
    assert parse_publish_retry_after_secs(message, now=now) == 400


def test_parse_publish_retry_after_secs_from_retry_after_header() -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    output = (
        "error: failed to get a 200 OK response, got 429\n"
        "headers:\n"
        "\tHTTP/1.1 429\n"
        "\tRetry-After: Mon, 30 Mar 2026 21:36:35 GMT\n"
        "body:\n"
    )
    assert parse_publish_retry_after_secs(output, now=now) == 400


def test_parse_publish_retry_after_secs_header_seconds() -> None:
    assert (
        parse_publish_retry_after_secs(
            "headers:\n\tRetry-After: 120\n",
            now=datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC),
        )
        == 120 + PUBLISH_RATE_LIMIT_SKEW_SECS
    )


def test_parse_publish_retry_after_secs_header_zero_seconds() -> None:
    assert (
        parse_publish_retry_after_secs(
            "headers:\n\tRetry-After: 0\n",
            now=datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC),
        )
        == PUBLISH_RATE_LIMIT_SKEW_SECS
    )


def test_parse_publish_retry_after_secs_invalid_header_date() -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    assert (
        parse_publish_retry_after_secs(
            "headers:\n\tRetry-After: not-a-date\n",
            now=now,
        )
        is None
    )


def test_wait_secs_until_retry_at_naive_datetimes() -> None:
    retry_at = datetime(2026, 3, 30, 21, 36, 35)
    now = datetime(2026, 3, 30, 21, 30, 0)
    assert _wait_secs_until_retry_at(retry_at, now=now) == 400


def test_parse_publish_retry_after_secs_past_date() -> None:
    now = datetime(2026, 3, 30, 22, 0, 0, tzinfo=UTC)
    assert (
        parse_publish_retry_after_secs(
            "Please try again after Mon, 30 Mar 2026 21:36:35 GMT",
            now=now,
        )
        == PUBLISH_RATE_LIMIT_SKEW_SECS
    )


def test_parse_publish_retry_after_secs_unparseable() -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    assert parse_publish_retry_after_secs("no retry hint here", now=now) is None


def test_publish_continues_after_duplicate_publish_error(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ordered = ["vlz-db", "vlz-manifest-finder"]

    def fake_already(crate: str, version: str, root: Path) -> bool:
        return False

    def fake_publish(
        crate: str, root: Path
    ) -> subprocess.CompletedProcess[str]:
        if crate == "vlz-db":
            return subprocess.CompletedProcess(
                args=["cargo", "publish"],
                returncode=1,
                stdout="",
                stderr=(
                    "error: crate version `0.9.1` is already uploaded on crates.io index"
                ),
            )
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "scripts.crates_publish.publish_order",
        lambda _manifests: ordered,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.crate_already_on_registry",
        fake_already,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )

    errors = publish_release_crates(repo_root, version="0.9.1")
    assert errors == []
    out = capsys.readouterr().out
    assert "skip vlz-db 0.9.1 (already published; registry index lag)" in out
    assert "publishing vlz-manifest-finder 0.9.1" in out


def test_publish_stops_on_real_publish_error(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ordered = ["vlz-db"]

    monkeypatch.setattr(
        "scripts.crates_publish.publish_order",
        lambda _manifests: ordered,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.crate_already_on_registry",
        lambda _crate, _version, _root: False,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        lambda _crate, _root: subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=1,
            stdout="",
            stderr="error: failed to verify compressed package",
        ),
    )

    errors = publish_release_crates(repo_root, version="0.9.1")
    assert len(errors) == 1
    assert "failed to verify compressed package" in errors[0]


def test_publish_skips_when_registry_search_finds_version(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ordered = ["vlz-db", "vlz-manifest-finder"]
    published: list[str] = []

    def fake_already(crate: str, version: str, root: Path) -> bool:
        return crate == "vlz-db"

    def fake_publish(
        crate: str, root: Path
    ) -> subprocess.CompletedProcess[str]:
        published.append(crate)
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "scripts.crates_publish.publish_order",
        lambda _manifests: ordered,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.crate_already_on_registry",
        fake_already,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )

    errors = publish_release_crates(repo_root, version="0.9.1")
    assert errors == []
    assert published == ["vlz-manifest-finder"]
    out = capsys.readouterr().out
    assert "skip vlz-db 0.9.1 (already published)" in out


def test_validate_manifest_publish_flags_detects_publish_false(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text(
        '[package]\nname = "vlz-db"\npublish = false\n',
        encoding="utf-8",
    )
    errors = validate_manifest_publish_flags({"vlz-db": manifest})
    assert errors == ["vlz-db: publish = false blocks crates.io"]


def test_validate_vlz_assets_reports_missing_and_stale(
    tmp_path: Path,
) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "man").mkdir()
    (tmp_path / "scripts" / "config-comments.toml").write_text(
        "src\n", encoding="utf-8"
    )
    (tmp_path / "man" / "vlz.1").write_text("man\n", encoding="utf-8")
    errors = validate_vlz_assets(tmp_path)
    assert any("missing vlz asset" in err for err in errors)

    assets = tmp_path / "crates" / "core" / "vlz" / "assets"
    assets.mkdir(parents=True)
    (assets / "config-comments.toml").write_text("stale\n", encoding="utf-8")
    (assets / "vlz.1").write_text("man\n", encoding="utf-8")
    errors = validate_vlz_assets(tmp_path)
    assert any("out of sync" in err for err in errors)


def test_default_feature_set_handles_missing_and_non_list(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "a.toml"
    missing.write_text("[package]\nname = 'x'\n", encoding="utf-8")
    assert default_feature_set(missing) == set()

    bad = tmp_path / "b.toml"
    bad.write_text(
        "[package]\nname = 'x'\n[features]\ndefault = 'runtime'\n",
        encoding="utf-8",
    )
    assert default_feature_set(bad) == set()

    empty_features = tmp_path / "c.toml"
    empty_features.write_text(
        "[package]\nname = 'x'\nfeatures = 'nope'\n",
        encoding="utf-8",
    )
    assert default_feature_set(empty_features) == set()


def test_list_vlz_package_binaries_non_vlz_is_empty(repo_root: Path) -> None:
    assert list_vlz_package_binaries("vlz-db", repo_root) == set()


def test_validate_vlz_install_binaries_extra_and_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "scripts.crates_publish.list_vlz_package_binaries",
        lambda _name, _root: {"vlz", "extra"},
    )
    errors = validate_vlz_install_binaries(tmp_path)
    assert errors == ["vlz package exposes extra binaries: extra"]

    monkeypatch.setattr(
        "scripts.crates_publish.list_vlz_package_binaries",
        lambda _name, _root: set(),
    )
    errors = validate_vlz_install_binaries(tmp_path)
    assert errors == ["vlz package is missing the vlz binary target"]


def test_run_cargo_package_respects_allow_dirty_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[list[str]] = []

    def fake_run(
        cmd: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr("scripts.crates_publish.subprocess.run", fake_run)
    monkeypatch.setenv("VLZ_ALLOW_DIRTY_PACKAGE", "0")
    run_cargo_package("vlz-db", tmp_path)
    assert "--allow-dirty" not in calls[0]

    monkeypatch.setenv("VLZ_ALLOW_DIRTY_PACKAGE", "1")
    run_cargo_package("vlz-db", tmp_path)
    assert "--allow-dirty" in calls[1]


def test_crate_already_on_registry_handles_search_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_registry_search",
        lambda *_a, **_k: subprocess.CompletedProcess(
            ["cargo"], 1, "", "error"
        ),
    )
    assert crate_already_on_registry("vlz", "0.9.1", tmp_path) is False

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_registry_search",
        lambda *_a, **_k: subprocess.CompletedProcess(
            ["cargo"], 0, 'vlz = "0.9.1"\n', ""
        ),
    )
    assert crate_already_on_registry("vlz", "0.9.1", tmp_path) is True


def test_check_crates_publish_manifest_only_and_package_failure(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert check_crates_publish(repo_root, package_leaves=False) == []

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_package",
        lambda crate, _root: subprocess.CompletedProcess(
            ["cargo"], 1, "", f"boom {crate}"
        ),
    )
    errors = check_crates_publish(repo_root, package_leaves=True)
    assert errors
    assert "cargo package" in errors[0]


def test_main_list_order_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--list-order"]) == 0
    out = capsys.readouterr().out
    assert "vlz-db" in out
    assert out.strip().splitlines()[-1] == "vlz"
    assert main([]) == 2
    assert "crates.io publish helpers" in capsys.readouterr().out


def test_main_check_manifest_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "scripts.crates_publish.check_crates_publish",
        lambda _root, package_leaves=True: [],
    )
    assert main(["--check", "--manifest-only"]) == 0


def test_main_check_reports_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "scripts.crates_publish.check_crates_publish",
        lambda _root, package_leaves=True: ["bad"],
    )
    assert main(["--check"]) == 1
    assert "error: bad" in capsys.readouterr().err


def test_main_publish_success_and_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "scripts.crates_publish.publish_release_crates",
        lambda _root: [],
    )
    assert main(["--publish"]) == 0
    assert "cargo-publish-release: OK" in capsys.readouterr().out

    monkeypatch.setattr(
        "scripts.crates_publish.publish_release_crates",
        lambda _root: ["fail"],
    )
    assert main(["--publish"]) == 1
    assert "error: fail" in capsys.readouterr().err


def test_read_workspace_version_and_dep_version_mismatch(
    tmp_path: Path,
) -> None:
    from scripts.crates_publish import (
        read_workspace_version,
        validate_workspace_dep_versions,
        workspace_internal_dep_versions,
    )

    cargo = tmp_path / "Cargo.toml"
    cargo.write_text(
        "[workspace.package]\n"
        'version = "0.9.1"\n'
        "[workspace.dependencies]\n"
        'vlz-db = { path = "crates/core/vlz-db", version = "0.8.0" }\n'
        'serde = "1.0"\n',
        encoding="utf-8",
    )
    assert read_workspace_version(cargo) == "0.9.1"
    versions = workspace_internal_dep_versions(cargo)
    assert versions["vlz-db"] == "0.8.0"
    errors = validate_workspace_dep_versions(tmp_path)
    assert any("vlz-db" in err for err in errors)


def test_discover_crate_manifests_rejects_missing(
    tmp_path: Path,
) -> None:
    (tmp_path / "crates").mkdir()
    with pytest.raises(ValueError, match="missing Cargo.toml"):
        discover_crate_manifests(tmp_path)


def test_publish_order_detects_unknown_dep_and_cycle(
    tmp_path: Path,
) -> None:
    a = tmp_path / "a.toml"
    a.write_text(
        "[package]\nname = 'vlz-db'\n"
        "[dependencies]\nvlz-report = { workspace = true }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="unknown crate"):
        publish_order({"vlz-db": a})

    b = tmp_path / "b.toml"
    c = tmp_path / "c.toml"
    b.write_text(
        "[package]\nname = 'vlz-db'\n"
        "[dependencies]\nvlz-manifest-finder = { workspace = true }\n",
        encoding="utf-8",
    )
    c.write_text(
        "[package]\nname = 'vlz-manifest-finder'\n"
        "[dependencies]\nvlz-db = { workspace = true }\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="cycle"):
        publish_order({"vlz-db": b, "vlz-manifest-finder": c})


def test_inherits_and_read_workspace_package_non_dict(
    tmp_path: Path,
) -> None:
    from scripts.crates_publish import (
        inherits_workspace_field,
        read_workspace_package_table,
    )

    assert inherits_workspace_field(
        {"keywords": {"workspace": True}}, "keywords"
    )
    assert not inherits_workspace_field({"keywords": "x"}, "keywords")
    cargo = tmp_path / "Cargo.toml"
    cargo.write_text("[workspace]\npackage = 'nope'\n", encoding="utf-8")
    assert read_workspace_package_table(cargo) == {}


def test_validate_workspace_rust_version_skips_without_channel(
    tmp_path: Path,
) -> None:
    from scripts.crates_publish import validate_workspace_rust_version

    (tmp_path / "rust-toolchain.toml").write_text(
        "[toolchain]\ncomponents = ['rustfmt']\n",
        encoding="utf-8",
    )
    assert (
        validate_workspace_rust_version(tmp_path, {"rust-version": "1.98"})
        == []
    )


def test_run_cargo_registry_search_and_publish_invoked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from scripts.crates_publish import (
        run_cargo_publish,
        run_cargo_registry_search,
    )

    seen: list[list[str]] = []

    def fake_run(
        cmd: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "ok", "")

    monkeypatch.setattr("scripts.crates_publish.subprocess.run", fake_run)
    run_cargo_registry_search("vlz", "0.9.1", tmp_path)
    run_cargo_publish("vlz", tmp_path)
    assert any("search" in cmd for cmd in seen)
    assert any("publish" in cmd for cmd in seen)


def test_publish_crate_with_retry_retries_after_rate_limit(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    sleeps: list[float] = []
    attempts = {"count": 0}

    def fake_publish(
        _crate: str, _root: Path
    ) -> subprocess.CompletedProcess[str]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return subprocess.CompletedProcess(
                args=["cargo", "publish"],
                returncode=1,
                stdout="",
                stderr=MODERN_429_ERROR,
            )
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )

    result = publish_crate_with_retry(
        "vlz-db",
        repo_root,
        sleep_fn=lambda secs: sleeps.append(secs),
        now_fn=lambda: now,
    )
    assert result.returncode == 0
    assert attempts["count"] == 2
    assert sleeps == [400.0]
    out = capsys.readouterr().out
    assert "rate limited publishing vlz-db" in out
    assert "retry 1/5 in 400s" in out


def test_publish_crate_with_retry_exhausts_retries(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        lambda _crate, _root: subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=1,
            stdout="",
            stderr=MODERN_429_ERROR,
        ),
    )

    result = publish_crate_with_retry(
        "vlz-db",
        repo_root,
        max_retries=2,
        sleep_fn=lambda _secs: None,
        now_fn=lambda: now,
    )
    assert result.returncode == 1
    assert "status 429" in result.stderr


def test_publish_crate_with_retry_non_rate_limit_no_retry(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts = {"count": 0}

    def fake_publish(
        _crate: str, _root: Path
    ) -> subprocess.CompletedProcess[str]:
        attempts["count"] += 1
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=1,
            stdout="",
            stderr="error: failed to verify compressed package",
        )

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )

    result = publish_crate_with_retry("vlz-db", repo_root)
    assert result.returncode == 1
    assert attempts["count"] == 1


def test_publish_crate_with_retry_wait_above_cap_fails_without_sleep(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    now = datetime(2026, 3, 30, 20, 0, 0, tzinfo=UTC)
    sleeps: list[float] = []

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        lambda _crate, _root: subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=1,
            stdout="",
            stderr=MODERN_429_ERROR,
        ),
    )

    result = publish_crate_with_retry(
        "vlz-db",
        repo_root,
        sleep_fn=lambda secs: sleeps.append(secs),
        now_fn=lambda: now,
    )
    assert result.returncode == 1
    assert sleeps == []
    assert PUBLISH_RATE_LIMIT_MAX_WAIT_SECS < 5795
    out = capsys.readouterr().out
    assert "exceeds 3600s cap" in out
    assert "re-run the release job" in out


def test_publish_crate_with_retry_unparseable_uses_fallback(
    repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sleeps: list[float] = []
    attempts = {"count": 0}

    def fake_publish(
        _crate: str, _root: Path
    ) -> subprocess.CompletedProcess[str]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return subprocess.CompletedProcess(
                args=["cargo", "publish"],
                returncode=1,
                stdout="",
                stderr="error: failed to get a 200 OK response, got 429",
            )
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )

    result = publish_crate_with_retry(
        "vlz-db",
        repo_root,
        sleep_fn=lambda secs: sleeps.append(secs),
        now_fn=lambda: datetime.now(UTC),
    )
    assert result.returncode == 0
    assert sleeps == [float(PUBLISH_RATE_LIMIT_FALLBACK_SECS)]


def test_publish_release_crates_uses_rate_limit_retry(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ordered = ["vlz-db"]
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    sleeps: list[float] = []
    attempts = {"count": 0}

    def fake_publish(
        _crate: str, _root: Path
    ) -> subprocess.CompletedProcess[str]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return subprocess.CompletedProcess(
                args=["cargo", "publish"],
                returncode=1,
                stdout="",
                stderr=MODERN_429_ERROR,
            )
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=0,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        "scripts.crates_publish.publish_order",
        lambda _manifests: ordered,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.crate_already_on_registry",
        lambda _crate, _version, _root: False,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )
    monkeypatch.setattr("scripts.crates_publish._utc_now", lambda: now)
    monkeypatch.setattr(
        "scripts.crates_publish.time.sleep",
        lambda secs: sleeps.append(secs),
    )

    errors = publish_release_crates(repo_root, version="0.9.1")
    assert errors == []
    assert attempts["count"] == 2
    assert sleeps == [400.0]


def test_publish_release_crates_skips_duplicate_after_rate_limit_retry(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ordered = ["vlz-db"]
    now = datetime(2026, 3, 30, 21, 30, 0, tzinfo=UTC)
    attempts = {"count": 0}

    def fake_publish(
        _crate: str, _root: Path
    ) -> subprocess.CompletedProcess[str]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            return subprocess.CompletedProcess(
                args=["cargo", "publish"],
                returncode=1,
                stdout="",
                stderr=MODERN_429_ERROR,
            )
        return subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=1,
            stdout="",
            stderr=(
                "error: crate version `0.9.1` is already uploaded on crates.io index"
            ),
        )

    monkeypatch.setattr(
        "scripts.crates_publish.publish_order",
        lambda _manifests: ordered,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.crate_already_on_registry",
        lambda _crate, _version, _root: False,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        fake_publish,
    )
    monkeypatch.setattr("scripts.crates_publish._utc_now", lambda: now)
    monkeypatch.setattr("scripts.crates_publish.time.sleep", lambda _secs: None)

    errors = publish_release_crates(repo_root, version="0.9.1")
    assert errors == []
    assert attempts["count"] == 2
    out = capsys.readouterr().out
    assert "skip vlz-db 0.9.1 (already published; registry index lag)" in out


def test_publish_release_crates_fails_when_wait_exceeds_cap(
    repo_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    ordered = ["vlz-db"]
    now = datetime(2026, 3, 30, 20, 0, 0, tzinfo=UTC)

    monkeypatch.setattr(
        "scripts.crates_publish.publish_order",
        lambda _manifests: ordered,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.crate_already_on_registry",
        lambda _crate, _version, _root: False,
    )
    monkeypatch.setattr(
        "scripts.crates_publish.run_cargo_publish",
        lambda _crate, _root: subprocess.CompletedProcess(
            args=["cargo", "publish"],
            returncode=1,
            stdout="",
            stderr=MODERN_429_ERROR,
        ),
    )
    monkeypatch.setattr("scripts.crates_publish._utc_now", lambda: now)

    errors = publish_release_crates(repo_root, version="0.9.1")
    assert len(errors) == 1
    assert "status 429" in errors[0]
    out = capsys.readouterr().out
    assert "exceeds 3600s cap" in out
