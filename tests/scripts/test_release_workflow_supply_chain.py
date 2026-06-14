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


def test_check_obs_signing_runs_in_preflight_not_in_publish_obs() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    preflight_end = text.index("build-binary:")
    publish_start = text.index("publish-obs:")
    assert "./scripts/check-obs-signing.sh" in text[:preflight_end]
    assert "Verify OBS signing metadata" in text[:preflight_end]
    publish_job = text[publish_start:]
    assert "./scripts/check-obs-signing.sh" not in publish_job
