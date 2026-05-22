# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Contract tests for OBS packaging consistency wiring."""

import re

from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def test_makefile_exposes_check_obs_packaging_target() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert ".PHONY: check-obs-packaging" in text
    assert "check-obs-packaging:" in text


def test_makefile_check_depends_on_obs_packaging_validation() -> None:
    text = (_repo_root() / "Makefile").read_text(encoding="utf-8")
    assert "check-obs-packaging" in text


def test_obs_project_env_has_required_coordinate_keys() -> None:
    env_file = _repo_root() / "packaging" / "obs" / "obs-project.env"
    text = env_file.read_text(encoding="utf-8")
    assert "OBS_PROJECT=" in text
    assert "OBS_PACKAGE=" in text


def test_obs_packaging_check_script_invokes_signing_check() -> None:
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "check-obs-signing.sh" in text


def test_obs_packaging_check_does_not_require_ripgrep() -> None:
    """GitHub Actions ubuntu-latest images do not install ripgrep by default."""
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "rg " not in text


def test_obs_spec_uses_literal_version_for_set_version_service() -> None:
    """Ensure OBS set_version can rewrite the spec Version field."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "%{!?version:%global version" not in spec_text
    assert re.search(r"^Version:\s+\d+\.\d+\.\d+$", spec_text, re.MULTILINE)


def test_obs_scm_strips_git_tag_v_prefix() -> None:
    """SemVer tags use leading v; rewrite keeps tarball/Source0 sane for RPM."""
    service_text = (
        _repo_root() / "packaging" / "obs" / "_service"
    ).read_text(encoding="utf-8")
    assert '<param name="versionrewrite-pattern">v(.*)</param>' in service_text
    assert '<param name="versionrewrite-replacement">\\1</param>' in service_text


def test_obs_service_declares_cargo_vendor() -> None:
    """OBS _service must declare cargo_vendor for offline builds (NFR-021)."""
    service_text = (
        _repo_root() / "packaging" / "obs" / "_service"
    ).read_text(encoding="utf-8")
    assert 'name="cargo_vendor"' in service_text
    assert '<param name="srcdir">verilyze</param>' in service_text
    assert '<param name="compression">zst</param>' in service_text
    assert '<param name="respect-lockfile">true</param>' in service_text


def test_obs_spec_uses_offline_cargo_with_vendor_sources() -> None:
    """RPM spec must consume vendor archive and build offline."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "Source1:        vendor.tar.zst" in spec_text
    assert "Source2:" not in spec_text
    assert "cargo_config" not in spec_text
    assert "BuildRequires:  zstd" in spec_text
    assert "cargo build --release --locked --offline" in spec_text
    assert "tar --zstd -xf %{SOURCE1}" in spec_text


def test_debian_rules_uses_offline_cargo_with_vendor_sources() -> None:
    """Debian rules must extract vendor archive and build offline."""
    rules_text = (
        _repo_root()
        / "packaging"
        / "obs"
        / "debian"
        / "debian"
        / "rules"
    ).read_text(encoding="utf-8")
    assert "vendor.tar.zst" in rules_text
    assert "cargo_config" not in rules_text
    assert "cargo build --release --locked --offline" in rules_text


def test_debian_control_build_depends_includes_zstd() -> None:
    """Debian control must list zstd so vendor.tar.zst can be extracted."""
    control_text = (
        _repo_root()
        / "packaging"
        / "obs"
        / "debian"
        / "debian"
        / "control"
    ).read_text(encoding="utf-8")
    assert "zstd" in control_text


def test_obs_set_version_handles_optional_leading_v_in_basenames() -> None:
    """Upstream tags use v; OBS default set_version filename regex rejects those."""
    service_text = (
        _repo_root() / "packaging" / "obs" / "_service"
    ).read_text(encoding="utf-8")
    assert '<param name="basename">verilyze</param>' in service_text
    assert (
        '<param name="regex">^verilyze-v?(.*)\\.(?:tar\\.xz|obscpio|tar\\.gz|tar\\.zst)$</param>'
        in service_text
    )


def test_obs_packaging_check_asserts_cargo_vendor_and_offline() -> None:
    """check-obs-packaging.sh must assert cargo_vendor and --offline."""
    text = (_repo_root() / "scripts" / "check-obs-packaging.sh").read_text(
        encoding="utf-8"
    )
    assert "cargo_vendor" in text
    assert "--offline" in text


def test_obs_spec_lists_completion_parent_dirs_for_filelist_check() -> None:
    """openSUSE OBS brp filelist expects parent dirs owned when not from deps."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    for line in (
        "%dir %{_datadir}/zsh",
        "%dir %{_datadir}/zsh/site-functions",
        "%dir %{_datadir}/fish",
        "%dir %{_datadir}/fish/vendor_completions.d",
    ):
        assert line in spec_text


def test_obs_spec_declares_non_empty_check_section() -> None:
    """OBS RPM spec should include a meaningful %check section for rpmlint."""
    spec_text = (
        _repo_root() / "packaging" / "obs" / "rpm" / "verilyze.spec"
    ).read_text(encoding="utf-8")
    assert "\n%check\n" in spec_text
    assert 'set -- $(./target/release/%{crate_name} --version)' in spec_text
    assert 'actual_version="$2"' in spec_text
    assert 'expected_version="%{version}"' in spec_text
    assert '[ "$actual_version" = "$expected_version" ]' in spec_text
    assert "./target/release/%{crate_name} --help >/dev/null" in spec_text
