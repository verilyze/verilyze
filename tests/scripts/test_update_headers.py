# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/update_headers.py (NFR-021)."""

import hashlib
from functools import lru_cache
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts import update_headers
from scripts.update_headers import (
    email_matches_bot_markers,
    _extract_file_identifiers,
    _extract_identifier,
    _filter_non_bot_copyright_entries,
    _parse_git_log_numstat,
    _path_matches_reuse_glob,
    annotate_file,
    collect_files,
    load_reuse_annotation_globs,
    get_nontrivial_authors,
    get_repo_root,
    get_reuse_cmd,
    headers_match,
    load_config,
    process_one_file,
    resolve_authors,
    run,
)


@lru_cache(maxsize=1)
def project_bot_email_markers() -> tuple[str, ...]:
    """Markers from repo root pyproject [tool.vlz-headers]."""
    return load_config(get_repo_root())["bot_email_markers"]


def _primary_bot_marker() -> str:
    """First configured marker for synthetic bot emails in tests."""
    markers = project_bot_email_markers()
    assert markers, "pyproject bot_email_markers must be non-empty"
    return markers[0]


def _write_minimal_pyproject_with_bot_markers(
    path: Path,
    markers: tuple[str, ...] | None = None,
) -> None:
    """Minimal [tool.vlz-headers] for tmp_path repos (mirrors root markers)."""
    use = markers if markers is not None else project_bot_email_markers()
    lines = ["[tool.vlz-headers]", "bot_email_markers = ["]
    lines.extend(
        f'  "{m}"' + ("," if i < len(use) - 1 else "")
        for i, m in enumerate(use)
    )
    lines.append("]")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


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


class TestEmailMatchesBotMarkers:
    """Tests for email_matches_bot_markers and bot filtering helpers."""

    def test_substring_case_insensitive(self) -> None:
        marker = _primary_bot_marker()
        assert (
            email_matches_bot_markers(
                f"49699333+dependabot{marker}@users.noreply.github.com",
                project_bot_email_markers(),
            )
            is True
        )
        assert (
            email_matches_bot_markers(
                "49699333+DEPENDABOT"
                + marker.upper()
                + "@users.noreply.github.com",
                project_bot_email_markers(),
            )
            is True
        )
        assert (
            email_matches_bot_markers("alice@x", project_bot_email_markers())
            is False
        )

    def test_empty_markers_never_matches(self) -> None:
        assert (
            email_matches_bot_markers(
                f"x{_primary_bot_marker()}@y",
                (),
            )
            is False
        )

    def test_filter_non_bot_entries(self) -> None:
        m = _primary_bot_marker()
        raw = ["2024 A <a@x>", f"2024 B <b{m}@y>"]
        assert _filter_non_bot_copyright_entries(
            raw,
            project_bot_email_markers(),
        ) == ["2024 A <a@x>"]


class TestParseGitLogNumstat:
    """Tests for _parse_git_log_numstat."""

    def test_author_above_threshold(self) -> None:
        # Author A: 20 lines (>=15)
        log = "Alice <alice@x>\n2024\n20\t5\tfoo.py"
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert result == ["2024 Alice <alice@x>"]

    def test_author_below_threshold_excluded(self) -> None:
        # Author B: 5 lines (<15)
        log = "Bob <bob@x>\n2024\n5\t2\tbar.py"
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert result == []

    def test_author_multiple_years(self) -> None:
        # Author C: 30 lines across 2023-2024
        log = (
            "Carol <carol@x>\n2023\n10\t0\tfoo.py\n"
            "Carol <carol@x>\n2024\n20\t0\tfoo.py"
        )
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert result == ["2023-2024 Carol <carol@x>"]

    def test_multiple_authors(self) -> None:
        log = (
            "Alice <a@x>\n2024\n25\t0\tx.py\n"
            "Bob <b@x>\n2024\n30\t0\ty.py"
        )
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert set(result) == {"2024 Alice <a@x>", "2024 Bob <b@x>"}

    def test_empty_log(self) -> None:
        assert _parse_git_log_numstat("", 15, project_bot_email_markers()) == []

    def test_bot_above_threshold_excluded(self) -> None:
        m = _primary_bot_marker()
        log = (
            f"Dependabot <49699333+dependabot{m}"
            "@users.noreply.github.com>\n"
            "2024\n20\t0\tfoo.py"
        )
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert result == []

    def test_human_and_bot_over_threshold_only_human(self) -> None:
        m = _primary_bot_marker()
        log = (
            f"Dependabot <d{m}@x>\n2024\n20\t0\ta.py\n"
            "Alice <alice@x>\n2024\n20\t0\tb.py"
        )
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert result == ["2024 Alice <alice@x>"]

    def test_custom_marker_excludes_matching_email(self) -> None:
        log = "Svc <svc@corp.internal>\n2024\n20\t0\tf.py"
        assert _parse_git_log_numstat(log, 15, ("internal",)) == []

    def test_empty_markers_includes_bot_contributor(self) -> None:
        m = _primary_bot_marker()
        log = f"Bot <b{m}@x>\n2024\n20\t0\tf.py"
        result = _parse_git_log_numstat(log, 15, ())
        assert result == [f"2024 Bot <b{m}@x>"]


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
        assert "yml" in result["extensions"]
        assert "yaml" in result["extensions"]
        # No pyproject: must match module defaults, not the checkout's TOML.
        default_markers = (
            update_headers._DEFAULT_BOT_EMAIL_MARKERS
        )  # pylint: disable=protected-access
        assert result["bot_email_markers"] == default_markers

    def test_pyproject_bot_email_markers(self, tmp_path: Path) -> None:
        combined = (*project_bot_email_markers(), "internal")
        pyproject = tmp_path / "pyproject.toml"
        lines = ["[tool.vlz-headers]", "bot_email_markers = ["]
        lines.extend(
            f'  "{m}"' + ("," if i < len(combined) - 1 else "")
            for i, m in enumerate(combined)
        )
        lines.append("]")
        pyproject.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = load_config(tmp_path)
        assert result["bot_email_markers"] == combined

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
            "bot_email_markers": project_bot_email_markers(),
        }
        assert (
            headers_match(
                tmp_path, "test.py", ["2024 Alice <alice@x>"], config
            )
            is True
        )

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
            "bot_email_markers": project_bot_email_markers(),
        }
        assert (
            headers_match(
                tmp_path, "test.py", ["2024 Alice <alice@x>"], config
            )
            is False
        )

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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
        }
        assert headers_match(tmp_path, "nonexistent.py", [], config) is False

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
            "bot_email_markers": project_bot_email_markers(),
        }
        assert (
            headers_match(tmp_path, "test.mmd", ["2024 Alice <a@x>"], config)
            is True
        )


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
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_result = MagicMock(
            returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tfoo.py"
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = get_nontrivial_authors(tmp_path, "foo.py", None, config)
        assert result == ["2024 Alice <a@x>"]

    def test_excludes_bot_from_nontrivial_authors(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        m = _primary_bot_marker()
        log = f"Bot <b{m}@x>\n2024\n20\t0\tfoo.py"
        mock_result = MagicMock(returncode=0, stdout=log)
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = get_nontrivial_authors(tmp_path, "foo.py", None, config)
        assert result == []

    def test_returns_empty_on_git_failure(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_result = MagicMock(returncode=1, stdout="")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = get_nontrivial_authors(tmp_path, "foo.py", None, config)
        assert result == []

    def test_writes_cache_after_git_log(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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

    def test_cache_read_filters_bot_lines(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        rev_result = MagicMock(returncode=0, stdout="abc123")
        digest = hashlib.sha256(b"abc123:foo.py").hexdigest()
        mb = _primary_bot_marker()
        (cache_dir / digest).write_text(
            f"2024 Bot <b{mb}@x>\n2023 Human <h@x>\n"
        )
        with patch("scripts.update_headers.run", return_value=rev_result):
            result = get_nontrivial_authors(
                tmp_path, "foo.py", cache_dir, config
            )
        assert result == ["2023 Human <h@x>"]

    def test_git_log_includes_use_mailmap(self, tmp_path: Path) -> None:
        """get_nontrivial_authors passes --use-mailmap to git log (DOC-013)."""
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        log_result = MagicMock(
            returncode=0,
            stdout="Canonical <canonical@x>\n2024\n20\t0\tfoo.py",
        )

        with patch(
            "scripts.update_headers.run", return_value=log_result
        ) as mock:
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_result = MagicMock(returncode=1, stdout="")
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = resolve_authors(tmp_path, "x.py", [], config)
        assert len(result) == 1
        assert "The verilyze contributors" in result[0]

    def test_raw_authors_bot_only_triggers_git_fallback(
        self, tmp_path: Path
    ) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_result = MagicMock(
            returncode=0, stdout="2024 Human <human@x>"
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            mx = _primary_bot_marker()
            result = resolve_authors(
                tmp_path,
                "x.py",
                [f"2024 Bot <b{mx}@y>"],
                config,
            )
        assert result == ["2024 Human <human@x>"]

    def test_raw_authors_mixed_drops_bots(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        my = _primary_bot_marker()
        result = resolve_authors(
            tmp_path,
            "x.py",
            [f"2024 Bot <b{my}@y>", "2024 Alice <a@x>"],
            config,
        )
        assert result == ["2024 Alice <a@x>"]

    def test_git_oldest_skips_leading_bot_commit(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        mk = _primary_bot_marker()
        mock_result = MagicMock(
            returncode=0,
            stdout=(
                f"2023 Bot <b{mk}@y>\n"
                "2024 Human <h@x>\n"
            ),
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = resolve_authors(tmp_path, "x.py", [], config)
        assert result == ["2024 Human <h@x>"]

    def test_all_git_authors_are_bots_use_default_copyright(
        self, tmp_path: Path
    ) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "The verilyze contributors",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": (),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        m1 = _primary_bot_marker()
        bot_only = MagicMock(
            returncode=0,
            stdout=(
                f"2024 Bot1 <a{m1}@x>\n2023 Bot2 <b{m1}@y>\n"
            ),
        )
        with patch(
            "scripts.update_headers.run",
            side_effect=[bot_only, bot_only],
        ):
            result = resolve_authors(tmp_path, "x.py", [], config)
        assert len(result) == 1
        assert "The verilyze contributors" in result[0]


class TestPathMatchesReuseGlob:
    """Tests for _path_matches_reuse_glob (REUSE.toml path globs)."""

    def test_exact_file(self) -> None:
        assert _path_matches_reuse_glob("biome.json", "biome.json") is True
        assert _path_matches_reuse_glob("other.json", "biome.json") is False

    def test_single_star_one_segment(self) -> None:
        assert (
            _path_matches_reuse_glob("completions/vlz.bash", "completions/*")
            is True
        )
        assert (
            _path_matches_reuse_glob("completions/a/b.sh", "completions/*")
            is False
        )

    def test_double_star_suffix(self) -> None:
        assert _path_matches_reuse_glob(".cursor/foo", ".cursor/**") is True
        assert _path_matches_reuse_glob(".cursor", ".cursor/**") is True
        assert _path_matches_reuse_glob(".cursor/a/b", ".cursor/**") is True
        assert _path_matches_reuse_glob(".git/foo", ".cursor/**") is False

    def test_double_star_prefix_and_suffix(self) -> None:
        assert (
            _path_matches_reuse_glob("pkg/__pycache__/x", "**/__pycache__/**")
            is True
        )
        assert (
            _path_matches_reuse_glob("__pycache__/y.py", "**/__pycache__/**")
            is True
        )
        assert (
            _path_matches_reuse_glob(
                "tests/fuzz/corpus/a", "tests/fuzz/corpus/**"
            )
            is True
        )

    def test_tls_crl_glob(self) -> None:
        p = "crates/core/vlz-cve-client/tests/fixtures/tls_crl/ca.pem"
        pat = "crates/core/vlz-cve-client/tests/fixtures/tls_crl/*.pem"
        assert _path_matches_reuse_glob(p, pat) is True
        assert (
            _path_matches_reuse_glob(p.replace(".pem", ".crt"), pat) is False
        )

    def test_normalizes_backslash(self) -> None:
        assert _path_matches_reuse_glob(r"a\b\foo.py", "a/b/foo.py") is True

    def test_empty_pattern_only_matches_empty_path(self) -> None:
        assert _path_matches_reuse_glob("", "") is True
        assert _path_matches_reuse_glob("a", "") is False

    def test_middle_double_star_requires_suffix(self) -> None:
        assert _path_matches_reuse_glob("a/c", "a/**/b") is False

    def test_rejects_path_shorter_than_pattern(self) -> None:
        assert _path_matches_reuse_glob("a", "a/b") is False


class TestLoadReuseAnnotationGlobs:
    """Tests for load_reuse_annotation_globs."""

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert load_reuse_annotation_globs(tmp_path) == ()

    def test_invalid_toml_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "REUSE.toml").write_text("not toml", encoding="utf-8")
        assert load_reuse_annotation_globs(tmp_path) == ()

    def test_annotations_not_list_returns_empty(self, tmp_path: Path) -> None:
        (tmp_path / "REUSE.toml").write_text(
            'version = 1\nannotations = "bad"\n',
            encoding="utf-8",
        )
        assert load_reuse_annotation_globs(tmp_path) == ()

    def test_skips_non_dict_annotation_entries(self, tmp_path: Path) -> None:
        (tmp_path / "REUSE.toml").write_text("version = 1\n", encoding="utf-8")
        with patch(
            "scripts.update_headers.tomllib.load",
            return_value={"annotations": [42, {"path": "keep"}]},
        ):
            assert load_reuse_annotation_globs(tmp_path) == ("keep",)


class TestCollectFiles:
    """Tests for collect_files."""

    def test_skips_paths_matching_reuse_toml_annotations(
        self, tmp_path: Path
    ) -> None:
        """Paths declared in REUSE.toml [[annotations]] are not header targets."""
        (tmp_path / "REUSE.toml").write_text(
            "version = 1\n"
            "[[annotations]]\n"
            'path = "biome.json"\n'
            'SPDX-License-Identifier = "GPL-3.0-or-later"\n',
            encoding="utf-8",
        )
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("json", "py"),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_result = MagicMock(
            returncode=0,
            stdout="biome.json\0src/main.py\0",
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = collect_files(tmp_path, config)
        assert "src/main.py" in result
        assert "biome.json" not in result

    def test_returns_covered_files(self, tmp_path: Path) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py", "rs"),
            "literal_names": ("Makefile",),
            "exclude_paths": ("vendor",),
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_result = MagicMock(
            returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tmatch.py"
        )
        with patch("scripts.update_headers.run", return_value=mock_result):
            result = process_one_file(tmp_path, "match.py", None, config)
        assert result is None

    def test_returns_annotated_when_reuse_succeeds(
        self, tmp_path: Path
    ) -> None:
        f = tmp_path / "new.py"
        f.write_text("print(1)\n", encoding="utf-8")
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": (),
            "bot_email_markers": project_bot_email_markers(),
        }
        mock_run = MagicMock(
            return_value=MagicMock(returncode=0, stdout="", stderr="")
        )
        with patch("scripts.update_headers.run", mock_run):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                result = process_one_file(tmp_path, "new.py", None, config)
        assert result == "Annotated: new.py"


class TestMainPrintConfig:
    """Tests for main --print-config."""

    def test_print_config_returns_zero(self) -> None:
        with patch("sys.argv", ["update_headers.py", "--print-config"]):
            exit_code = update_headers.main()
        assert exit_code == 0

    def test_is_bot_email_exit_zero_when_bot(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        _write_minimal_pyproject_with_bot_markers(pyproject)
        marker = _primary_bot_marker()
        bot_email = f"49699333+dependabot{marker}@users.noreply.github.com"
        with patch(
            "sys.argv",
            ["update_headers.py", "--is-bot-email", bot_email],
        ):
            with patch(
                "scripts.update_headers.get_repo_root",
                return_value=tmp_path,
            ):
                assert update_headers.main() == 0

    def test_is_bot_email_exit_one_when_human(self, tmp_path: Path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        _write_minimal_pyproject_with_bot_markers(pyproject)
        with patch(
            "sys.argv",
            ["update_headers.py", "--is-bot-email", "human@example.com"],
        ):
            with patch(
                "scripts.update_headers.get_repo_root",
                return_value=tmp_path,
            ):
                assert update_headers.main() == 1

    def test_main_rejects_unknown_argument(self) -> None:
        with patch("sys.argv", ["update_headers.py", "--not-a-flag"]):
            assert update_headers.main() == 2

    def test_main_rejects_is_bot_email_without_value(self) -> None:
        with patch("sys.argv", ["update_headers.py", "--is-bot-email"]):
            assert update_headers.main() == 2

    def test_main_rejects_print_config_with_is_bot_email(self) -> None:
        with patch(
            "sys.argv",
            [
                "update_headers.py",
                "--print-config",
                "--is-bot-email",
                "a@b",
            ],
        ):
            assert update_headers.main() == 2

    def test_main_accepts_argv_without_sys_argv(self) -> None:
        """Callers may pass argv explicitly (sys.argv[1:] style)."""
        exit_code = update_headers.main(["--print-config"])
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
        (tmp_path / "scripts" / "ensure-reuse.sh").write_text(
            "#!/bin/sh\nexit 0\n"
        )
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
        (tmp_path / "scripts" / "ensure-reuse.sh").write_text(
            "#!/bin/sh\nexit 0\n"
        )
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
        (tmp_path / "scripts" / "ensure-reuse.sh").write_text(
            "#!/bin/sh\nexit 0\n"
        )
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

    def test_excludes_path_starting_with_exclude_prefix(
        self, tmp_path: Path
    ) -> None:
        config: update_headers.HeadersConfig = {
            "default_copyright": "x",
            "default_license": "GPL-3.0-or-later",
            "nontrivial_lines": 15,
            "extensions": ("py",),
            "literal_names": (),
            "exclude_paths": ("vendor",),
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
        }
        with patch.object(
            Path, "read_text", side_effect=OSError("read failed")
        ):
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
            "bot_email_markers": project_bot_email_markers(),
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

    def test_returns_true_when_force_dot_license_succeeds(
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
            "bot_email_markers": project_bot_email_markers(),
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
            "bot_email_markers": project_bot_email_markers(),
        }
        result = process_one_file(tmp_path, "nonexistent.py", None, config)
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
            "bot_email_markers": project_bot_email_markers(),
        }
        with patch(
            "scripts.update_headers.run", return_value=MagicMock(returncode=1)
        ):
            with patch(
                "scripts.update_headers.get_reuse_cmd",
                return_value=Path("/bin/echo"),
            ):
                result = process_one_file(
                    tmp_path, "noheader.py", None, config
                )
        assert result is None


class TestParseGitLogNumstatEdgeCases:
    """Tests for _parse_git_log_numstat edge cases."""

    def test_non_digit_add_uses_zero(self) -> None:
        log = "Alice <a@x>\n2024\nabc\t5\tfoo.py"
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
        assert result == []

    def test_author_with_year_unknown_firstyear(self) -> None:
        log = "Alice <a@x>\n2024\n20\t0\tfoo.py"
        result = _parse_git_log_numstat(log, 15, project_bot_email_markers())
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
            "bot_email_markers": project_bot_email_markers(),
        }
        cache_dir = tmp_path / ".cache"
        cache_dir.mkdir()
        rev_result = MagicMock(returncode=0, stdout="abc123")
        digest = hashlib.sha256(b"abc123:foo.py").hexdigest()
        (cache_dir / digest).write_text("x")
        with patch(
            "scripts.update_headers.run",
            side_effect=[
                rev_result,
                MagicMock(
                    returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tfoo.py"
                ),
            ],
        ):
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
            "bot_email_markers": project_bot_email_markers(),
        }
        cache_dir = tmp_path / ".cache"
        rev_result = MagicMock(returncode=0, stdout="abc123")
        log_result = MagicMock(
            returncode=0, stdout="Alice <a@x>\n2024\n20\t0\tfoo.py"
        )
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
