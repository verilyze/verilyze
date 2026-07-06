# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests for deterministic workspace SBOM normalization (SEC-019)."""

import json

from scripts.normalize_sbom import (
    SBOM_METADATA_TIMESTAMP,
    SBOM_SPDX_DOC_ID,
    normalize_cyclonedx,
    normalize_spdx,
    normalize_sbom_files,
)
from tests.scripts.repo_root import repo_root


def test_normalize_cyclonedx_replaces_metadata_timestamp() -> None:
    data = {
        "metadata": {"timestamp": "3996-07-06T06:02:06Z", "tools": []},
        "components": [],
    }
    out = normalize_cyclonedx(data)
    assert out["metadata"]["timestamp"] == SBOM_METADATA_TIMESTAMP


def test_normalize_spdx_replaces_doc_id_and_created() -> None:
    data = {
        "spdxId": "urn:spdx.dev:doc-1783317726",
        "creationInfo": {"created": "3996-07-06T06:02:06Z"},
        "element": [],
        "relationship": [],
    }
    out = normalize_spdx(data)
    assert out["spdxId"] == SBOM_SPDX_DOC_ID
    assert out["creationInfo"]["created"] == SBOM_METADATA_TIMESTAMP


def test_normalize_spdx_replaces_relationship_annotation_dates() -> None:
    data = {
        "spdxId": "urn:spdx.dev:doc-volatile",
        "creationInfo": {"created": "3996-07-06T06:02:06Z"},
        "element": [],
        "relationship": [
            {
                "annotations": [
                    {"annotationDate": "3996-07-06T06:02:06Z", "comment": "x"}
                ]
            }
        ],
    }
    out = normalize_spdx(data)
    ann = out["relationship"][0]["annotations"][0]
    assert ann["annotationDate"] == SBOM_METADATA_TIMESTAMP


def test_normalize_sbom_files_updates_committed_artifacts(tmp_path) -> None:
    cdx_path = tmp_path / "verilyze.cdx.json"
    spdx_path = tmp_path / "verilyze.spdx.json"
    cdx_path.write_text(
        json.dumps(
            {
                "metadata": {"timestamp": "3996-07-06T05:41:12Z"},
                "components": [],
            }
        ),
        encoding="utf-8",
    )
    spdx_path.write_text(
        json.dumps(
            {
                "spdxId": "urn:spdx.dev:doc-1783316472",
                "creationInfo": {"created": "3996-07-06T05:41:12Z"},
                "element": [],
                "relationship": [],
            }
        ),
        encoding="utf-8",
    )
    normalize_sbom_files(cdx_path, spdx_path)
    cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
    spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
    assert cdx["metadata"]["timestamp"] == SBOM_METADATA_TIMESTAMP
    assert spdx["spdxId"] == SBOM_SPDX_DOC_ID
    assert spdx["creationInfo"]["created"] == SBOM_METADATA_TIMESTAMP


def test_committed_workspace_sbom_uses_normalized_metadata() -> None:
    """Guard: committed sbom/v1/ must not contain volatile timestamps."""
    cdx = json.loads(
        (repo_root() / "sbom/v1/verilyze.cdx.json").read_text(encoding="utf-8")
    )
    spdx = json.loads(
        (repo_root() / "sbom/v1/verilyze.spdx.json").read_text(encoding="utf-8")
    )
    assert cdx["metadata"]["timestamp"] == SBOM_METADATA_TIMESTAMP
    assert spdx["spdxId"] == SBOM_SPDX_DOC_ID
    assert spdx["creationInfo"]["created"] == SBOM_METADATA_TIMESTAMP
