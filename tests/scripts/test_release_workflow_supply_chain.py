# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for release signing and provenance workflow coverage."""

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


def test_check_obs_signing_runs_in_preflight_not_in_trigger_obs() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    preflight_end = text.index("build-binary:")
    trigger_start = text.index("trigger-obs:")
    assert "./scripts/check-obs-signing.sh" in text[:preflight_end]
    assert "Verify OBS signing metadata" in text[:preflight_end]
    trigger_job = text[trigger_start:]
    assert "./scripts/check-obs-signing.sh" not in trigger_job
