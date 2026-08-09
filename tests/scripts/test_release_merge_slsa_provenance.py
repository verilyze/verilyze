# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Release SLSA archive provenance merge helper (SEC-021)."""

import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root


class TestReleaseMergeSlsaProvenance:
    def test_merge_copies_slsa_bundles_beside_archives(self, tmp_path: Path) -> None:
        root = tmp_path / "artifacts"
        version = "1.2.3"
        platforms = (
            ("vlz-linux-x86_64", "vlz-1.2.3-linux-x86_64.tar.gz"),
            ("vlz-macos-aarch64", "vlz-1.2.3-macos-aarch64.tar.gz"),
            ("vlz-windows-x86_64", "vlz-1.2.3-windows-x86_64.zip"),
        )
        for name, archive in platforms:
            dest_dir = root / name
            dest_dir.mkdir(parents=True)
            (dest_dir / archive).write_bytes(b"archive")
            nested = root / "nested"
            nested.mkdir(exist_ok=True)
            (nested / f"slsa-{name}.intoto.jsonl").write_text(
                '{"payloadType":"application/vnd.in-toto+json"}',
                encoding="utf-8",
            )
        script = repo_root() / "scripts" / "release-merge-slsa-binary-provenance.sh"
        subprocess.run(
            [str(script), str(root), version],
            check=True,
            cwd=repo_root(),
        )
        for name, archive in platforms:
            bundle = root / name / f"{archive}.intoto.jsonl"
            assert bundle.is_file()
            assert "in-toto" in bundle.read_text(encoding="utf-8")
