# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/check_header_duplicates.py (DOC-013)."""

from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.check_header_duplicates import (
    extract_copyright_identifiers,
    get_files_with_duplicates,
    get_repo_root,
    main,
    parse_mailmap,
)


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_parent_of_scripts(self) -> None:
        root = get_repo_root()
        assert (root / "scripts" / "check_header_duplicates.py").exists()
        assert root.name != "scripts"


class TestParseMailmap:
    """Tests for parse_mailmap."""

    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        mailmap = tmp_path / ".mailmap"
        mailmap.write_text("")
        assert parse_mailmap(tmp_path) == {}

    def test_missing_file_returns_empty_dict(self, tmp_path: Path) -> None:
        assert parse_mailmap(tmp_path) == {}

    def test_single_mapping(self, tmp_path: Path) -> None:
        mailmap = tmp_path / ".mailmap"
        mailmap.write_text(
            "Canonical Name <canonical@x.com> Alias <alias@x.com>\n"
        )
        result = parse_mailmap(tmp_path)
        assert result == {"Alias <alias@x.com>": "Canonical Name <canonical@x.com>"}

    def test_canonical_identity_maps_to_self(self, tmp_path: Path) -> None:
        mailmap = tmp_path / ".mailmap"
        mailmap.write_text(
            "Canonical Name <canonical@x.com> Alias <alias@x.com>\n"
        )
        result = parse_mailmap(tmp_path)
        assert "Canonical Name <canonical@x.com>" not in result
        assert result.get("Canonical Name <canonical@x.com>") is None

    def test_skips_empty_and_comment_lines(self, tmp_path: Path) -> None:
        mailmap = tmp_path / ".mailmap"
        mailmap.write_text(
            "\n"
            "# comment line\n"
            "  \n"
            "Real <real@x.com> Other <other@x.com>\n"
        )
        result = parse_mailmap(tmp_path)
        assert result == {"Other <other@x.com>": "Real <real@x.com>"}


class TestExtractCopyrightIdentifiers:
    """Tests for extract_copyright_identifiers."""

    def test_two_copyright_lines(self) -> None:
        header = (
            "# SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "# SPDX-FileCopyrightText: 2023 Bob <b@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n"
        )
        result = extract_copyright_identifiers(header)
        assert set(result) == {"Alice <a@x>", "Bob <b@x>"} and len(result) == 2

    def test_year_range_in_copyright(self) -> None:
        header = "# SPDX-FileCopyrightText: 2022-2024 Carol <c@x>\n"
        result = extract_copyright_identifiers(header)
        assert result == ["Carol <c@x>"]

    def test_no_copyright_returns_empty(self) -> None:
        header = "# SPDX-License-Identifier: GPL-3.0-or-later\n"
        result = extract_copyright_identifiers(header)
        assert result == []

    def test_year_only_no_identifier_returns_empty(self) -> None:
        header = "# SPDX-FileCopyrightText: 2024\n"
        result = extract_copyright_identifiers(header)
        assert result == []


class TestGetFilesWithDuplicates:
    """Tests for get_files_with_duplicates."""

    def test_two_different_people_same_name_no_mailmap(
        self, tmp_path: Path
    ) -> None:
        """John Smith <a@x> and John Smith <b@x> are distinct without .mailmap."""
        f = tmp_path / "foo.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 John Smith <a@x>\n"
            "# SPDX-FileCopyrightText: 2023 John Smith <b@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["foo.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert duplicates == []

    def test_same_person_two_emails_mapped_in_mailmap(
        self, tmp_path: Path
    ) -> None:
        """Both emails map to same canonical: duplicate."""
        mailmap = tmp_path / ".mailmap"
        mailmap.write_text(
            "Jane Doe <jane@work.com> Jane Doe <jane@personal.com>\n"
        )
        f = tmp_path / "bar.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 Jane Doe <jane@work.com>\n"
            "# SPDX-FileCopyrightText: 2023 Jane Doe <jane@personal.com>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["bar.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert len(duplicates) == 1
        assert duplicates[0][0] == "bar.py"
        assert set(duplicates[0][1]) == {
            "Jane Doe <jane@work.com>",
            "Jane Doe <jane@personal.com>",
        }

    def test_identical_identifiers_exact_duplicate(self, tmp_path: Path) -> None:
        """Exact duplicate line: duplicate."""
        f = tmp_path / "baz.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "# SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["baz.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert len(duplicates) == 1
        assert duplicates[0][0] == "baz.py"
        assert duplicates[0][1] == ["Alice <a@x>", "Alice <a@x>"]

    def test_mailmap_absent_no_false_positives(self, tmp_path: Path) -> None:
        """Same name, different emails, no .mailmap: no duplicate."""
        f = tmp_path / "quux.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 John Smith <john@acme.com>\n"
            "# SPDX-FileCopyrightText: 2023 John Smith <john@gmail.com>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        assert not (tmp_path / ".mailmap").exists()
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["quux.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert duplicates == []

    def test_no_headers_no_duplicate(self, tmp_path: Path) -> None:
        """File without SPDX headers: skip (no duplicates)."""
        f = tmp_path / "no_header.py"
        f.write_text("print('hello')\n")
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["no_header.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert duplicates == []

    def test_nonexistent_file_skipped(self, tmp_path: Path) -> None:
        """When collect returns a path that does not exist, skip it."""
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["nonexistent.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert duplicates == []

    def test_copyright_with_year_only_skipped(self, tmp_path: Path) -> None:
        """File with SPDX-FileCopyrightText but no identifier yields empty idents."""
        f = tmp_path / "year_only.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["year_only.py"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert duplicates == []

    def test_uses_dot_license_file_when_present(self, tmp_path: Path) -> None:
        """Force-dot-license files (e.g. .mmd): read from file.license."""
        mmd = tmp_path / "diagram.mmd"
        mmd.write_text("graph TD\n  A-->B\n")
        license_file = tmp_path / "diagram.mmd.license"
        license_file.write_text(
            "SPDX-FileCopyrightText: 2024 A <a@x>\n"
            "SPDX-FileCopyrightText: 2023 A <a@x>\n"
            "SPDX-License-Identifier: GPL-3.0-or-later\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["diagram.mmd"] if root == tmp_path else [],
            )
            duplicates = get_files_with_duplicates(tmp_path)
        assert len(duplicates) == 1
        assert duplicates[0][0] == "diagram.mmd"

    def test_get_header_content_handles_read_error(self, tmp_path: Path) -> None:
        """When read_text raises OSError, treat as empty content."""
        f = tmp_path / "bad.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["bad.py"] if root == tmp_path else [],
            )
            with patch.object(Path, "read_text", side_effect=OSError):
                duplicates = get_files_with_duplicates(tmp_path)
        assert duplicates == []


class TestCollectCoveredFiles:
    """Tests for collect_covered_files."""

    def test_returns_files_from_collect(self, tmp_path: Path) -> None:
        """collect_covered_files uses load_config and collect_files."""
        from scripts.check_header_duplicates import collect_covered_files

        with patch(
            "scripts.check_header_duplicates.load_config",
        ) as mock_load:
            with patch(
                "scripts.check_header_duplicates.collect_files",
                return_value=["a.py", "b.py"],
            ) as mock_collect:
                result = collect_covered_files(tmp_path)
        mock_load.assert_called_once_with(tmp_path)
        mock_collect.assert_called_once()
        assert result == ["a.py", "b.py"]


class TestMain:
    """Tests for main entry point."""

    def test_exit_0_when_no_duplicates(self, tmp_path: Path) -> None:
        f = tmp_path / "ok.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.get_repo_root",
                lambda: tmp_path,
            )
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["ok.py"] if root == tmp_path else [],
            )
            assert main() == 0

    def test_exit_1_when_duplicates_found(self, tmp_path: Path) -> None:
        mailmap = tmp_path / ".mailmap"
        mailmap.write_text("A <a@x> B <b@x>\n")
        f = tmp_path / "dup.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 A <a@x>\n"
            "# SPDX-FileCopyrightText: 2023 B <b@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n"
        )
        with pytest.MonkeyPatch.context() as m:
            m.chdir(tmp_path)
            m.setattr(
                "scripts.check_header_duplicates.get_repo_root",
                lambda: tmp_path,
            )
            m.setattr(
                "scripts.check_header_duplicates.collect_covered_files",
                lambda root: ["dup.py"] if root == tmp_path else [],
            )
            assert main() == 1


class TestMainModule:
    """Tests for __main__ execution."""

    def test_main_module_exit_code(self) -> None:
        """Running as __main__ invokes main() and exits with its return code."""
        import runpy

        repo_root = Path(__file__).resolve().parent.parent.parent
        script = repo_root / "scripts" / "check_header_duplicates.py"
        try:
            runpy.run_path(str(script), run_name="__main__")
        except SystemExit as e:
            assert e.code == 0
            return
        pytest.fail("Expected SystemExit from sys.exit(main())")

# REUSE-IgnoreEnd
