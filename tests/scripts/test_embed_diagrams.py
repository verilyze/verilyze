# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/embed-diagrams.py (NFR-021)."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Load embed-diagrams module (filename has hyphen, not valid Python identifier)
_embed_diagrams_path = Path(__file__).resolve().parent.parent.parent / "scripts" / "embed-diagrams.py"
_spec = importlib.util.spec_from_file_location("embed_diagrams", _embed_diagrams_path)
embed_diagrams = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(embed_diagrams)  # type: ignore[union-attr]


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_parent_of_scripts(self) -> None:
        root = embed_diagrams.get_repo_root()
        assert (root / "scripts" / "embed-diagrams.py").exists()
        assert root.name != "scripts"


class TestProcessMarkdown:
    """Tests for process_markdown."""

    def test_replaces_include_marker_with_mermaid_block(self, tmp_path: Path) -> None:
        mmd = tmp_path / "architecture" / "test.mmd"
        mmd.parent.mkdir(parents=True)
        mmd.write_text("graph TD\n  A --> B\n", encoding="utf-8")
        content = (
            "Some text\n"
            "<!-- INCLUDE architecture/test.mmd -->\n"
            "More text\n"
        )
        processed, errors = embed_diagrams.process_markdown(content, tmp_path)
        assert "```mermaid" in processed
        assert "graph TD" in processed
        assert "A --> B" in processed
        assert errors == []

    def test_missing_mmd_file_appends_error(self, tmp_path: Path) -> None:
        content = "<!-- INCLUDE architecture/nonexistent.mmd -->\n"
        processed, errors = embed_diagrams.process_markdown(content, tmp_path)
        assert "<!-- INCLUDE architecture/nonexistent.mmd -->" in processed
        assert errors == ["Missing file: architecture/nonexistent.mmd"]

    def test_no_marker_returns_unchanged(self, tmp_path: Path) -> None:
        content = "Plain markdown\nNo marker here\n"
        processed, errors = embed_diagrams.process_markdown(content, tmp_path)
        assert processed == content
        assert errors == []

    def test_marker_with_extra_whitespace(self, tmp_path: Path) -> None:
        mmd = tmp_path / "architecture" / "ws.mmd"
        mmd.parent.mkdir(parents=True)
        mmd.write_text("flowchart\n", encoding="utf-8")
        content = "  <!-- INCLUDE architecture/ws.mmd -->  \n"
        processed, errors = embed_diagrams.process_markdown(content, tmp_path)
        assert "```mermaid" in processed
        assert "flowchart" in processed
        assert errors == []

    def test_multiple_markers(self, tmp_path: Path) -> None:
        mmd1 = tmp_path / "architecture" / "a.mmd"
        mmd2 = tmp_path / "architecture" / "b.mmd"
        mmd1.parent.mkdir(parents=True)
        mmd1.write_text("A\n", encoding="utf-8")
        mmd2.write_text("B\n", encoding="utf-8")
        content = (
            "<!-- INCLUDE architecture/a.mmd -->\n"
            "<!-- INCLUDE architecture/b.mmd -->\n"
        )
        processed, errors = embed_diagrams.process_markdown(content, tmp_path)
        assert "```mermaid" in processed
        assert "A" in processed
        assert "B" in processed
        assert errors == []


class TestMain:
    """Tests for main entry point."""

    def test_file_not_found_returns_2(self) -> None:
        with patch("sys.argv", ["embed-diagrams.py", "nonexistent.md"]):
            with patch.object(
                embed_diagrams,
                "get_repo_root",
                return_value=Path("/tmp"),
            ):
                exit_code = embed_diagrams.main()
        assert exit_code == 2

    def test_check_mode_out_of_sync_returns_1(self, tmp_path: Path) -> None:
        md_file = tmp_path / "doc.md"
        md_file.write_text("<!-- INCLUDE architecture/x.mmd -->\n", encoding="utf-8")
        mmd_file = tmp_path / "architecture" / "x.mmd"
        mmd_file.parent.mkdir()
        mmd_file.write_text("graph\n", encoding="utf-8")
        with patch("sys.argv", ["embed-diagrams.py", "--check", "doc.md"]):
            with patch.object(
                embed_diagrams,
                "get_repo_root",
                return_value=tmp_path,
            ):
                exit_code = embed_diagrams.main()
        assert exit_code == 1

    def test_check_mode_in_sync_returns_0(self, tmp_path: Path) -> None:
        mmd_file = tmp_path / "architecture" / "y.mmd"
        mmd_file.parent.mkdir()
        mmd_content = "graph\n"
        mmd_file.write_text(mmd_content, encoding="utf-8")
        embedded = "```mermaid\n" + mmd_content.rstrip() + "\n```\n"
        md_file = tmp_path / "doc.md"
        md_file.write_text(embedded, encoding="utf-8")
        with patch("sys.argv", ["embed-diagrams.py", "--check", "doc.md"]):
            with patch.object(
                embed_diagrams,
                "get_repo_root",
                return_value=tmp_path,
            ):
                exit_code = embed_diagrams.main()
        assert exit_code == 0

    def test_default_mode_writes_updated_content(self, tmp_path: Path) -> None:
        mmd_file = tmp_path / "architecture" / "z.mmd"
        mmd_file.parent.mkdir()
        mmd_file.write_text("pie\n", encoding="utf-8")
        md_file = tmp_path / "doc.md"
        md_file.write_text("<!-- INCLUDE architecture/z.mmd -->\n", encoding="utf-8")
        with patch("sys.argv", ["embed-diagrams.py", "doc.md"]):
            with patch.object(
                embed_diagrams,
                "get_repo_root",
                return_value=tmp_path,
            ):
                exit_code = embed_diagrams.main()
        assert exit_code == 0
        assert "```mermaid" in md_file.read_text()

    def test_missing_mmd_in_check_returns_2(self, tmp_path: Path) -> None:
        md_file = tmp_path / "doc.md"
        md_file.write_text("<!-- INCLUDE architecture/missing.mmd -->\n", encoding="utf-8")
        (tmp_path / "architecture").mkdir(exist_ok=True)
        with patch("sys.argv", ["embed-diagrams.py", "--check", "doc.md"]):
            with patch.object(
                embed_diagrams,
                "get_repo_root",
                return_value=tmp_path,
            ):
                exit_code = embed_diagrams.main()
        assert exit_code == 2

    def test_absolute_path_resolved_correctly(self, tmp_path: Path) -> None:
        mmd_file = tmp_path / "architecture" / "abs.mmd"
        mmd_file.parent.mkdir()
        mmd_content = "graph\n"
        mmd_file.write_text(mmd_content, encoding="utf-8")
        embedded = "```mermaid\n" + mmd_content.rstrip() + "\n```\n"
        md_file = tmp_path / "abs.md"
        md_file.write_text(embedded, encoding="utf-8")
        with patch("sys.argv", ["embed-diagrams.py", "--check", str(md_file)]):
            with patch.object(
                embed_diagrams,
                "get_repo_root",
                return_value=tmp_path,
            ):
                exit_code = embed_diagrams.main()
        assert exit_code == 0

    def test_absolute_path_file_not_found_returns_2(self) -> None:
        with patch("sys.argv", ["embed-diagrams.py", "/nonexistent/path.md"]):
            exit_code = embed_diagrams.main()
        assert exit_code == 2

# REUSE-IgnoreEnd
