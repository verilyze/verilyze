# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Normalize volatile SBOM fields for deterministic check-sbom (SEC-019)."""

import json
import sys
from pathlib import Path
from typing import Any

# Fixed metadata so committed workspace SBOMs are reproducible across runs.
SBOM_METADATA_TIMESTAMP = "1970-01-01T00:00:00Z"
SBOM_SPDX_DOC_ID = "urn:spdx.dev:doc-verilyze-workspace"


def normalize_cyclonedx(data: dict[str, Any]) -> dict[str, Any]:
    """Replace CycloneDX metadata.timestamp with a fixed value."""
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        metadata["timestamp"] = SBOM_METADATA_TIMESTAMP
    return data


def normalize_spdx(data: dict[str, Any]) -> dict[str, Any]:
    """Replace SPDX document timestamps and document spdxId."""
    data["spdxId"] = SBOM_SPDX_DOC_ID
    creation = data.get("creationInfo")
    if isinstance(creation, dict):
        creation["created"] = SBOM_METADATA_TIMESTAMP
    for rel in data.get("relationship", []):
        if not isinstance(rel, dict):
            continue
        for ann in rel.get("annotations", []):
            if isinstance(ann, dict):
                ann["annotationDate"] = SBOM_METADATA_TIMESTAMP
    return data


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def normalize_sbom_files(cyclonedx_path: Path, spdx_path: Path) -> None:
    """Normalize both workspace SBOM artifacts in place."""
    cdx = json.loads(cyclonedx_path.read_text(encoding="utf-8"))
    _write_json(cyclonedx_path, normalize_cyclonedx(cdx))
    spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
    _write_json(spdx_path, normalize_spdx(spdx))


def main(argv: list[str] | None = None) -> int:
    """CLI entry: normalize CycloneDX and SPDX SBOM files in place."""
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2:
        print(
            "usage: normalize_sbom.py <cyclonedx.json> <spdx.json>",
            file=sys.stderr,
        )
        return 2
    normalize_sbom_files(Path(args[0]), Path(args[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
