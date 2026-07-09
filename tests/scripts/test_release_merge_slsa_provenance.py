# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Release SLSA binary provenance merge helper (SEC-021)."""

import subprocess
from pathlib import Path

from tests.scripts.repo_root import repo_root


class TestReleaseMergeSlsaProvenance:
    def test_merge_copies_slsa_bundles(self, tmp_path: Path) -> None:
        root = tmp_path / "artifacts"
        for name, binary in (
            ("vlz-linux-x86_64", "vlz"),
            ("vlz-macos-aarch64", "vlz"),
            ("vlz-windows-x86_64", "vlz.exe"),
        ):
            dest_dir = root / name
            dest_dir.mkdir(parents=True)
            (dest_dir / binary).write_bytes(b"bin")
            nested = root / "nested"
            nested.mkdir(exist_ok=True)
            (nested / f"slsa-{name}.intoto.jsonl").write_text(
                '{"payloadType":"application/vnd.in-toto+json"}',
                encoding="utf-8",
            )
        script = repo_root() / "scripts" / "release-merge-slsa-binary-provenance.sh"
        subprocess.run([str(script), str(root)], check=True, cwd=repo_root())
        for name, binary in (
            ("vlz-linux-x86_64", "vlz"),
            ("vlz-macos-aarch64", "vlz"),
            ("vlz-windows-x86_64", "vlz.exe"),
        ):
            bundle = root / name / f"{binary}.intoto.jsonl"
            assert bundle.is_file()
            assert "in-toto" in bundle.read_text(encoding="utf-8")
