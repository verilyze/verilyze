# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/update_headers.py (NFR-021)."""

import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts import update_headers
from scripts.update_headers import (
    _extract_file_identifiers,
    _extract_identifier,
    _parse_git_log_numstat,
    annotate_file,
    collect_files,
    get_nontrivial_authors,
    get_repo_root,
    get_reuse_cmd,
    headers_match,
    load_config,
    process_one_file,
    resolve_authors,
    run,
)


class TestExtractIdentifier:
    """Tests for _extract_identifier."""

    def test_single_year(self) -> None:
        assert _extract_identifier("2024 Alice <alice@x>") == "Alice <alice@x>"

    def test_year_range(self) -> None:
        assert _extract_identifier("2022-2024 Bob <bob@x>") == "Bob <bob@x>"

    def test_year_only_returns_empty(self) -> None:
        assert _extract_identifier("2024") == ""

    def test_empty_string(self) -> None:
        assert _extract_identifier("") == ""


class TestParseGitLogNumstat:
    """Tests for _parse_git_log_numstat."""

    def test_author_above_threshold(self) -> None:
        # Author A: 20 lines (>=15)
        log = "Alice <alice@x>\n2024\n20\t5\tfoo.py"
        result = _parse_git_log_numstat(log, 15)
        assert result == ["2024 Alice <alice@x>"]

    def test_author_below_threshold_excluded(self) -> None:
        # Author B: 5 lines (<15)
        log = "Bob <bob@x>\n2024\n5\t2\tbar.py"
        result = _parse_git_log_numstat(log, 15)
        assert result == []

    def test_author_multiple_years(self) -> None:
        # Author C: 30 lines across 2023-2024
        log = (
            "Carol <carol@x>\n2023\n10\t0\tfoo.py\n"
            "Carol <carol@x>\n2024\n20\t0\tfoo.py"
        )
        result = _parse_git_log_numstat(log, 15)
        assert result == ["2023-2024 Carol <carol@x>"]

    def test_multiple_authors(self) -> None:
        log = (
            "Alice <a@x>\n2024\n25\t0\tx.py\n"
            "Bob <b@x>\n2024\n30\t0\ty.py"
        )
        result = _parse_git_log_numstat(log, 15)
        assert set(result) == {"2024 Alice <a@x>", "2024 Bob <b@x>"}

    def test_empty_log(self) -> None:
        assert _parse_git_log_numstat("", 15) == []


class TestExtractFileIdentifiers:
    """Tests for _extract_file_identifiers."""

    def test_two_copyright_lines(self) -> None:
        header = (
            "SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "SPDX-FileCopyrightText: 2023 Bob <b@x>\n"
            "SPDX-License-Identifier: GPL-3.0-or-later"
        )
        result = _extract_file_identifiers(header)
        assert result == {"Alice <a@x>", "Bob <b@x>"}

    def test_year_range_in_copyright(self) -> None:
        header = "SPDX-FileCopyrightText: 2022-2024 Carol <c@x>"
        result = _extract_file_identifiers(header)
        assert result == {"Carol <c@x>"}

    def test_no_copyright_returns_empty(self) -> None:
        header = "SPDX-License-Identifier: GPL-3.0-or-later"
        result = _extract_file_identifiers(header)
        assert result == set()


class TestLoadConfig:
    """Tests for load_config."""

    def test_missing_pyproject_returns_defaults(self, tmp_path: Path) -> None:
        result = load_config(tmp_path)
        assert result["default_license"] == "GPL-3.0-or-later"
        assert result["default_copyright"] == "The verilyze contributors"
        assert result["nontrivial_lines"] == 15
        assert "py" in result["extensions"]

    def test_pyproject_overrides(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            """
[tool.vlz-headers]
default_copyright = "Custom Contributor"
default_license = "MIT"
nontrivial_lines = 20
extensions = ["py", "rs"]
literal_names = ["Makefile", "Dockerfile"]
exclude_paths = ["vendor"]
""",
            encoding="utf-8",
        )
        result = load_config(tmp_path)
        assert result["default_copyright"] == "Custom Contributor"
        assert result["default_license"] == "MIT"
        assert result["nontrivial_lines"] == 20
        assert result["extensions"] == ("py", "rs")
        assert result["literal_names"] == ("Makefile", "Dockerfile")
        assert result["exclude_paths"] == ("vendor",)

    def test_invalid_toml_returns_defaults(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("invalid toml {{{", encoding="utf-8")
        result = load_config(tmp_path)
        assert result["default_license"] == "GPL-3.0-or-later"


class TestHeadersMatch:
    """Tests for headers_match."""

    def test_matching_headers(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text(
            "#!/usr/bin/env python3\n"
            "# SPDX-FileCopyrightText: 2024 Alice <alice@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n",
            encoding="utf-8",
        )
        config: update_headers.HeadersConfig = {
            "default_copyright": "The verilyze contributors",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        assert headers_match(
            tmp_path, "test.py", ["2024 Alice <alice@x>"], config
        ) is True

    def test_missing_license_returns_false(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text(
            "SPDX-FileCopyrightText: 2024 Alice <alice@x>\n\npass\n",
            encoding="utf-8",
        )
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        assert headers_match(
            tmp_path, "test.py", ["2024 Alice <alice@x>"], config
        ) is False

    def test_missing_copyright_returns_false(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text(
            "SPDX-License-Identifier: GPL-3.0-or-later\n\npass\n",
            encoding="utf-8",
        )
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        assert (
            headers_match(tmp_path, "test.py", ["2024 Alice <a@x>"], config)
            is False
        )

    def test_nonexistent_file_returns_false(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        assert (
            headers_match(tmp_path, "nonexistent.py", [], config) is False
        )

    def test_uses_dot_license_file_when_present(self, tmp_path: Path) -> None:
        f = tmp_path / "test.mmd"
        f.write_text("content\n", encoding="utf-8")
        lic = tmp_path / "test.mmd.license"
        lic.write_text(
            "SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "SPDX-License-Identifier: GPL-3.0-or-later\n",
            encoding="utf-8",
        )
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("mmd",),
            "literal_names": (),
            "exclude_paths": (),
        }
        assert headers_match(
            tmp_path, "test.mmd", ["2024 Alice <a@x>"], config
        ) is True


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_parent_of_scripts(self) -> None:
        root = get_repo_root()
        assert (root / "scripts" / "update_headers.py").exists()
        assert root.name != "scripts"


class TestGetNontrivialAuthors:
    """Tests for get_nontrivial_authors."""

    def test_returns_authors_from_git_log(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tfoo.py")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = get_nontrivial_authors(
                tmp_path, "foo.py", None, config
            )
        assert result == ["2024 Alice <a@x>"]

    def test_returns_empty_on_git_failure(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=1, stdout="")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = get_nontrivial_authors(
                tmp_path, "foo.py", None, config
            )
        assert result == []

    def test_writes_cache_after_git_log(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        cache_dir = tmp_path / ".cache"
        rev_result = MagicMock(returncode=0, stdout="abc123")
        log_result = MagicMock(
            returncode=0,
            stdout="Alice <a@x>\n2024\n20\t0\tfoo.py",
        )
        with patch(
            "scripts.update_headers.run",
            side_effect=[rev_result, log_result],
        ):
            result = get_nontrivial_authors(
                tmp_path, "foo.py", cache_dir, config
            )
        assert result == ["2024 Alice <a@x>"]
        digest = hashlib.sha256(b"abc123:foo.py").hexdigest()
        assert (cache_dir / digest).exists()

    def test_uses_cache_when_available(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        rev_result = MagicMock(returncode=0, stdout="abc123")
        digest = hashlib.sha256(b"abc123:foo.py").hexdigest()
        (cache_dir / digest).write_text("2023 Cached <cached@x>\n")
        with patch("scripts.update_headers.run", return_value=rev_result):
            result = get_nontrivial_authors(
                tmp_path, "foo.py", cache_dir, config
            )
        assert result == ["2023 Cached <cached@x>"]

    def test_git_log_includes_use_mailmap(self, tmp_path: Path) -> None:
        """get_nontrivial_authors passes --use-mailmap to git log (DOC-013)."""
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        log_result = MagicMock(
            returncode=0,
            stdout="Canonical <canonical@x>\n2024\n20\t0\tfoo.py",
        )

        with patch("scripts.update_headers.run", return_value=log_result) as mock:
            get_nontrivial_authors(tmp_path, "foo.py", None, config)
            mock.assert_called_once()
            cmd = mock.call_args[0][0]
            assert cmd[0] == "git"
            assert cmd[1] == "log"
            assert "--use-mailmap" in cmd


class TestGetReuseCmd:
    """Tests for get_reuse_cmd."""

    def test_returns_ensure_reuse_path(self) -> None:
        root = get_repo_root()
        cmd = get_reuse_cmd(root)
        assert cmd.name == "ensure-reuse.sh"
        assert cmd.parent.name == "scripts"


class TestResolveAuthors:
    """Tests for resolve_authors."""

    def test_returns_raw_authors_when_non_empty(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        result = resolve_authors(tmp_path, "x.py", ["2024 A <a@x>"], config)
        assert result == ["2024 A <a@x>"]

    def test_first_commit_when_raw_empty(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=0, stdout="2023 First <first@x>")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = resolve_authors(tmp_path, "x.py", [], config)
        assert result == ["2023 First <first@x>"]

    def test_most_recent_commit_when_first_fails(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        first_fail = MagicMock(returncode=1, stdout="")
        second_ok = MagicMock(returncode=0, stdout="2024 Recent <recent@x>")
        with patch(
            "scripts.update_headers.run",
            side_effect=[first_fail, second_ok],
        ):
            result = resolve_authors(tmp_path, "x.py", [], config)
        assert result == ["2024 Recent <recent@x>"]

    def test_resolve_authors_git_log_includes_use_mailmap(
        self, tmp_path: Path
    ) -> None:
        """resolve_authors passes --use-mailmap to git log (DOC-013)."""
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=0, stdout="2023 First <first@x>")
        with patch(
            "scripts.update_headers.run", return_value=mock_result
        ) as mock:
            resolve_authors(tmp_path, "x.py", [], config)
            mock.assert_called()
            for call in mock.call_args_list:
                cmd = call[0][0]
                if cmd[0] == "git" and cmd[1] == "log":
                    assert "--use-mailmap" in cmd
                    break
            else:
                pytest.fail("No git log call found in resolve_authors")

    def test_fallback_to_default_copyright_when_no_git(
        self, tmp_path: Path
    ) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "The verilyze contributors",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=1, stdout="")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = resolve_authors(tmp_path, "x.py", [], config)
        assert len(result) == 1
        assert "The verilyze contributors" in result[0]


class TestCollectFiles:
    """Tests for collect_files."""

    def test_returns_covered_files(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py", "rs"),
            "literal_names": ("Makefile",),
            "exclude_paths": ("vendor",),
        }
        mock_result = MagicMock(
            returncode=0,
            stdout="foo.py\0bar.rs\0Makefile\0vendor/x.py\0",
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = collect_files(tmp_path, config)
        assert "foo.py" in result
        assert "bar.rs" in result
        assert "Makefile" in result
        assert "vendor/x.py" not in result

    def test_excludes_cargo_lock(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("lock",),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(
            returncode=0,
            stdout="Cargo.lock\0",
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = collect_files(tmp_path, config)
        assert result == []

    def test_returns_empty_on_git_failure(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=1, stdout="")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = collect_files(tmp_path, config)
        assert result == []


class TestRun:
    """Tests for run helper."""

    def test_run_with_capture_false(self) -> None:
        result = run(["true"], capture=False)
        assert result.returncode == 0


class TestAnnotateFile:
    """Tests for annotate_file."""

    def test_returns_true_when_reuse_succeeds(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("print(1)\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=0, stdout="", stderr="")
        with patch("scripts.update_headers.run", return_value=mock_result):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                ok = annotate_file(
                    tmp_path, "test.py", ["2024 A <a@x>"], config
                )
        assert ok is True

    def test_returns_false_when_both_annotate_attempts_fail(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "test.mmd"
        f.write_text("graph\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        fail_result = MagicMock(returncode=1, stdout="", stderr="reuse failed")
        with patch("scripts.update_headers.run", return_value=fail_result):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                ok = annotate_file(
                    tmp_path, "test.mmd", ["2024 A <a@x>"], config
                )
        assert ok is False


class TestProcessOneFile:
    """Tests for process_one_file."""

    def test_returns_none_when_headers_match(self, tmp_path: Path) -> None:
        f = tmp_path / "match.py"
        f.write_text(
            "# SPDX-FileCopyrightText: 2024 Alice <a@x>\n"
            "# SPDX-License-Identifier: GPL-3.0-or-later\n\n"
            "pass\n",
            encoding="utf-8",
        )
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_result = MagicMock(returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tmatch.py")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = process_one_file(
                tmp_path, "match.py", None, config
            )
        assert result is None

    def test_returns_annotated_when_reuse_succeeds(self, tmp_path: Path) -> None:
        f = tmp_path / "new.py"
        f.write_text("print(1)\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_run = MagicMock(return_value=MagicMock(returncode=0, stdout="", stderr=""))
        with patch("scripts.update_headers.run", mock_run):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                result = process_one_file(
                    tmp_path, "new.py", None, config
                )
        assert result == "Annotated: new.py"


class TestMainPrintConfig:
    """Tests for main --print-config."""

    def test_print_config_returns_zero(self) -> None:
        with patch("sys.argv", ["update_headers.py", "--print-config"]):
            exit_code = update_headers.main()
        assert exit_code == 0

    def test_returns_one_when_ensure_reuse_not_found(self) -> None:
        with patch("sys.argv", ["update_headers.py"]):
            with patch(
                "scripts.update_headers.get_repo_root",
                return_value=Path("/nonexistent/repo"),
            ):
                with patch("os.chdir"):
                    exit_code = update_headers.main()
        assert exit_code == 1

    def test_main_full_run_updated_count(self, tmp_path: Path) -> None:
        """Run main with mocked deps to cover ThreadPoolExecutor and print."""
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "ensure-reuse.sh").write_text("#!/bin/sh\nexit 0\n")
        (tmp_path / "LICENSES").mkdir()
        with patch("sys.argv", ["update_headers.py"]):
            with patch(
                "scripts.update_headers.get_repo_root",
                return_value=tmp_path,
            ):
                with patch("os.chdir"):
                    with patch(
                        "scripts.update_headers.collect_files",
                        return_value=[],
                    ):
                        exit_code = update_headers.main()
        assert exit_code == 0

    def test_main_downloads_license_when_missing(self, tmp_path: Path) -> None:
        """Run main when LICENSES dir does not exist; covers download path."""
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "ensure-reuse.sh").write_text("#!/bin/sh\nexit 0\n")
        assert not (tmp_path / "LICENSES").exists()
        with patch("sys.argv", ["update_headers.py"]):
            with patch(
                "scripts.update_headers.get_repo_root",
                return_value=tmp_path,
            ):
                with patch("os.chdir"):
                    with patch(
                        "scripts.update_headers.collect_files",
                        return_value=[],
                    ):
                        with patch("scripts.update_headers.run") as mock_run:
                            mock_run.return_value = MagicMock(
                                returncode=0, stdout="", stderr=""
                            )
                            exit_code = update_headers.main()
        assert exit_code == 0
        assert mock_run.call_count >= 1

    def test_main_prints_updated_files(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Run main with one file that gets annotated; covers print(result) path."""
        (tmp_path / "scripts").mkdir()
        (tmp_path / "scripts" / "ensure-reuse.sh").write_text("#!/bin/sh\nexit 0\n")
        (tmp_path / "LICENSES").mkdir()
        with patch("sys.argv", ["update_headers.py"]):
            with patch(
                "scripts.update_headers.get_repo_root",
                return_value=tmp_path,
            ):
                with patch("os.chdir"):
                    with patch(
                        "scripts.update_headers.collect_files",
                        return_value=["new.py"],
                    ):
                        with patch(
                            "scripts.update_headers.process_one_file",
                            return_value="Annotated: new.py",
                        ):
                            exit_code = update_headers.main()
        assert exit_code == 0
        out, _ = capsys.readouterr()
        assert "Annotated: new.py" in out


class TestCoveredFilesExcludePaths:
    """Tests for collect_files exclude_paths behavior."""

    def test_excludes_path_starting_with_exclude_prefix(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": ("vendor",),
        }
        mock_result = MagicMock(
            returncode=0,
            stdout="vendor/sub/module.py\0",
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = collect_files(tmp_path, config)
        assert "vendor/sub/module.py" not in result


class TestHeadersMatchReadError:
    """Tests for headers_match error paths."""

    def test_returns_false_on_read_error(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.py"
        f.write_text("content\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        with patch.object(Path, "read_text", side_effect=OSError("read failed")):
            assert (
                headers_match(tmp_path, "bad.py", ["2024 A <a@x>"], config)
                is False
            )


class TestAnnotateFileForceDotLicense:
    """Tests for annotate_file --force-dot-license fallback."""

    def test_skips_author_with_empty_identifier(self, tmp_path: Path) -> None:
        f = tmp_path / "test.py"
        f.write_text("code\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        mock_ok = MagicMock(returncode=0, stdout="", stderr="")
        with patch("scripts.update_headers.run", return_value=mock_ok):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                ok = annotate_file(
                    tmp_path, "test.py", ["2024", "2023 Alice <a@x>"], config
                )
        assert ok is True

    def test_returns_true_when_force_dot_license_succeeds(self, tmp_path: Path) -> None:
        f = tmp_path / "test.mmd"
        f.write_text("graph\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        first_fail = MagicMock(returncode=1, stdout="", stderr="")
        second_ok = MagicMock(returncode=0, stdout="", stderr="")
        with patch(
            "scripts.update_headers.run",
            side_effect=[first_fail, second_ok],
        ):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                ok = annotate_file(
                    tmp_path, "test.mmd", ["2024 A <a@x>"], config
                )
        assert ok is True


class TestProcessOneFileEdgeCases:
    """Tests for process_one_file edge cases."""

    def test_returns_none_when_file_nonexistent(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        result = process_one_file(
            tmp_path, "nonexistent.py", None, config
        )
        assert result is None

    def test_returns_none_when_annotate_fails(self, tmp_path: Path) -> None:
        f = tmp_path / "noheader.py"
        f.write_text("print(1)\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
        }
        with patch("scripts.update_headers.run", return_value=MagicMock(returncode=1)):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                result = process_one_file(tmp_path, "noheader.py", None, config)
        assert result is None


class TestParseGitLogNumstatEdgeCases:
    """Tests for _parse_git_log_numstat edge cases."""

    def test_non_digit_add_uses_zero(self) -> None:
        log = "Alice <a@x>\n2024\nabc\t5\tfoo.py"
        result = _parse_git_log_numstat(log, 15)
        assert result == []

    def test_author_with_year_unknown_firstyear(self) -> None:
        log = "Alice <a@x>\n2024\n20\t0\tfoo.py"
        result = _parse_git_log_numstat(log, 15)
        assert result == ["2024 Alice <a@x>"]


class TestExtractFileIdentifiersNoMatch:
    """Tests for _extract_file_identifiers."""

    def test_copyright_line_with_year_only_no_identifier(self) -> None:
        header = "SPDX-FileCopyrightText: 2024\nSPDX-License-Identifier: MIT"
        result = _extract_file_identifiers(header)
        assert result == set()


class TestGetNontrivialAuthorsCacheErrors:
    """Tests for get_nontrivial_authors cache error handling."""

    def test_continues_on_cache_read_error(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        rev_result = MagicMock(returncode=0, stdout="abc123")
        digest = hashlib.sha256(b"abc123:foo.py").hexdigest()
        (cache_dir / digest).write_text("x")
        with patch("scripts.update_headers.run", side_effect=[rev_result, MagicMock(returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tfoo.py")]):
            with patch.object(Path, "read_text", side_effect=OSError):
                result = get_nontrivial_authors(
                    tmp_path, "foo.py", cache_dir, config
                )
        assert result == ["2024 Alice <a@x>"]

    def test_continues_on_cache_write_error(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
        }
        cache_dir = tmp_path / ".cache"
        rev_result = MagicMock(returncode=0, stdout="abc123")
        log_result = MagicMock(returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tfoo.py")
        with patch(
            "scripts.update_headers.run",
            side_effect=[rev_result, log_result],
        ):
            with patch.object(Path, "write_text", side_effect=OSError):
                result = get_nontrivial_authors(
                    tmp_path, "foo.py", cache_dir, config
                )
        assert result == ["2024 Alice <a@x>"]

# REUSE-IgnoreEnd
