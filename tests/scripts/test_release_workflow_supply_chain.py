# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for release signing and provenance workflow coverage."""

import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_RELEASE = _ROOT / ".github" / "workflows" / "release.yml"
_VERIFY_SCRIPT = _ROOT / "scripts" / "release-verify-bundle.sh"
_RESTORE_SCRIPT = _ROOT / "scripts" / "release-restore-download-layout.sh"


def test_release_backfill_workflow_removed() -> None:
    backfill = _ROOT / ".github" / "workflows" / "release-backfill-metadata.yml"
    assert not backfill.exists()


def test_release_workflow_uses_shared_artifact_manifest_script() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "./scripts/release-list-artifacts.sh" in text


def test_release_workflow_generates_blob_provenance_for_release_assets() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "cosign attest-blob --yes" in text
    assert "--type slsaprovenance" in text


def test_release_workflow_uses_draft_then_publish_for_immutable_release() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "draft: true" in text
    assert "Verify signatures, attestations, and checksums (local)" in text
    assert "Re-verify draft release assets from GitHub" in text
    assert "gh release download" in text
    assert "Publish release (make immutable)" in text
    assert 'gh release edit "${TAG}" --draft=false' in text


def test_release_workflow_invokes_verify_bundle_script() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "./scripts/release-verify-bundle.sh" in text
    assert "./scripts/release-restore-download-layout.sh" in text
    assert "EXPECTED_BUILDER_REGEX" in text


def test_release_verify_bundle_script_invokes_cosign_verify() -> None:
    text = _VERIFY_SCRIPT.read_text(encoding="utf-8")
    assert "cosign verify-blob" in text
    assert "cosign verify-blob-attestation" in text


def test_release_restore_download_layout_script_exists() -> None:
    assert _RESTORE_SCRIPT.is_file()


def test_release_restore_download_layout_uses_rpm_x86_64_path(tmp_path: Path) -> None:
    download_dir = tmp_path / "draft-verify"
    download_dir.mkdir()
    (download_dir / "vlz").write_bytes(b"vlz-binary")
    (download_dir / "vlz_0.1.0_amd64.deb").write_bytes(b"deb-pkg")
    (download_dir / "vlz-0.1.0-1.x86_64.rpm").write_bytes(b"rpm-pkg")

    proc = subprocess.run(
        [str(_RESTORE_SCRIPT), str(download_dir)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert (download_dir / "rpm-package" / "x86_64" / "vlz-0.1.0-1.x86_64.rpm").is_file()


def test_release_workflow_build_rpm_installs_python3() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    rpm_start = text.index("build-rpm:")
    rpm_end = text.index("build-docker:", rpm_start)
    rpm_job = text[rpm_start:rpm_end]
    assert "make rpm" in rpm_job
    assert "python3" in rpm_job


def test_release_workflow_has_scorecard_packaging_pattern() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "docker push" in text or "docker/build-push-action" in text


def test_release_workflow_gates_create_release_on_obs_builds() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "wait-obs-builds:" in text
    assert "./scripts/obs-wait-for-builds.sh" in text
    create_start = text.index("create-release:")
    create_needs_end = text.index("\n    runs-on:", create_start)
    create_needs = text[create_start:create_needs_end]
    assert "wait-obs-builds" in create_needs


def test_release_workflow_supports_dispatch_without_github_release() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "RELEASE_CHECKOUT_REF:" in text
    assert "release-read-workspace-version.sh" in text
    create_start = text.index("create-release:")
    create_block_end = text.index("\n\n", create_start + 1)
    create_block = text[create_start:create_block_end]
    assert "if: github.event_name == 'push'" in create_block


def test_release_workflow_skips_ckv_gha_7_for_dispatch_only() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "checkov:skip=CKV_GHA_7:" in text
    assert "workflow_dispatch:" in text
    assert "inputs:" in text


def test_release_read_workspace_version_script_matches_cargo_toml() -> None:
    script = _ROOT / "scripts" / "release-read-workspace-version.sh"
    cargo = _ROOT / "Cargo.toml"
    assert script.is_file()
    proc = subprocess.run(
        [str(script), str(cargo)],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    version_line = next(
        line for line in cargo.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith("version = ")
    )
    cargo_version = version_line.split("=", 1)[1].strip().strip('"')
    assert proc.stdout.strip() == cargo_version


def test_check_obs_signing_runs_in_preflight_not_in_publish_obs() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    preflight_end = text.index("build-binary:")
    publish_start = text.index("publish-obs:")
    assert "./scripts/check-obs-signing.sh" in text[:preflight_end]
    assert "Verify OBS signing metadata" in text[:preflight_end]
    publish_job = text[publish_start:]
    assert "./scripts/check-obs-signing.sh" not in publish_job
