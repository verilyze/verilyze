# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for release signing and provenance workflow coverage."""

from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent.parent
_RELEASE = _ROOT / ".github" / "workflows" / "release.yml"
_BACKFILL = _ROOT / ".github" / "workflows" / "release-backfill-metadata.yml"


def test_release_workflow_uses_shared_artifact_manifest_script() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "./scripts/release-list-artifacts.sh" in text


def test_release_workflow_generates_blob_provenance_for_release_assets() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "cosign attest-blob --yes" in text
    assert "--type slsaprovenance" in text


def test_release_workflow_verifies_metadata_presence() -> None:
    text = _RELEASE.read_text(encoding="utf-8")
    assert "Validate signed artifacts and provenance outputs" in text
    assert ".sigstore.json" in text
    assert ".intoto.jsonl" in text


def test_backfill_workflow_exists_for_historical_releases() -> None:
    text = _BACKFILL.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "TAGS: v0.1.0,v0.2.1" in text
    assert "Fallback for historical releases with legacy asset names" in text
    assert "gh release download" in text
    assert "gh release upload" in text
