# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# REUSE-IgnoreStart

"""Unit tests for scripts/generate_config_example.py (NFR-012)."""

import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Load generate_config_example module
_script_path = (
    Path(__file__).resolve().parent.parent.parent
    / "scripts"
    / "generate_config_example.py"
)
_spec = importlib.util.spec_from_file_location(
    "generate_config_example", _script_path
)
generate_config_example = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_config_example)  # type: ignore[union-attr]


class TestGetRepoRoot:
    """Tests for get_repo_root."""

    def test_returns_parent_of_scripts(self) -> None:
        root = generate_config_example.get_repo_root()
        assert (root / "scripts" / "generate_config_example.py").exists()
        assert root.name != "scripts"


class TestParseConfigComments:
    """Tests for parse_config_comments."""

    def test_parses_top_level_keys(self, tmp_path: Path) -> None:
        yaml = tmp_path / "config.yaml"
        yaml.write_text(
            "parallel_queries:\n"
            "  description: \"Max queries\"\n"
            "  type: integer\n",
            encoding="utf-8",
        )
        result = generate_config_example.parse_config_comments(yaml)
        assert "parallel_queries" in result
        assert result["parallel_queries"]["description"] == "Max queries"
        assert result["parallel_queries"]["type"] == "integer"

    def test_parses_nested_fields(self, tmp_path: Path) -> None:
        yaml = tmp_path / "config.yaml"
        yaml.write_text(
            "cache_ttl_secs:\n"
            "  description: \"TTL\"\n"
            "  type: integer\n"
            "  env: VLZ_CACHE_TTL_SECS\n"
            "  cli: \"--cache-ttl-secs\"\n"
            "  default: \"432000\"\n",
            encoding="utf-8",
        )
        result = generate_config_example.parse_config_comments(yaml)
        assert result["cache_ttl_secs"]["env"] == "VLZ_CACHE_TTL_SECS"
        assert result["cache_ttl_secs"]["cli"] == "--cache-ttl-secs"
        assert result["cache_ttl_secs"]["default"] == "432000"

    def test_skips_comments_and_blank_lines(self, tmp_path: Path) -> None:
        yaml = tmp_path / "config.yaml"
        yaml.write_text(
            "# comment\n"
            "\n"
            "key1:\n"
            "  desc: \"one\"\n"
            "# another\n"
            "  type: string\n",
            encoding="utf-8",
        )
        result = generate_config_example.parse_config_comments(yaml)
        assert "key1" in result
        assert result["key1"]["desc"] == "one"
        assert result["key1"]["type"] == "string"

    def test_handles_multi_key_yaml(self, tmp_path: Path) -> None:
        yaml = tmp_path / "config.yaml"
        yaml.write_text(
            "a:\n  x: 1\n"
            "b:\n  x: 2\n"
            "c:\n  x: 3\n",
            encoding="utf-8",
        )
        result = generate_config_example.parse_config_comments(yaml)
        assert result["a"]["x"] == "1"
        assert result["b"]["x"] == "2"
        assert result["c"]["x"] == "3"


class TestRunConfigList:
    """Tests for run_config_list."""

    def test_parses_key_value_output(self, tmp_path: Path) -> None:
        with patch(
            "subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout="parallel_queries = 10\ncache_ttl_secs = 432000\n",
                stderr="",
            ),
        ):
            result = generate_config_example.run_config_list(tmp_path)
        assert result["parallel_queries"] == "10"
        assert result["cache_ttl_secs"] == "432000"

    def test_exit_1_when_subprocess_fails(self, tmp_path: Path) -> None:
        with patch(
            "subprocess.run",
            return_value=MagicMock(
                returncode=1,
                stdout="",
                stderr="vlz failed",
            ),
        ):
            with pytest.raises(SystemExit) as exc_info:
                generate_config_example.run_config_list(tmp_path)
        assert exc_info.value.code == 1

    def test_parse_config_list_output_extracts_all_keys(self, tmp_path: Path) -> None:
        """config --list output is parsed; cache_db, severity keys included."""
        output = (
            "cache_db = \n"
            "ignore_db = \n"
            "parallel_queries = 10\n"
            "severity_v2_critical_min = 9\n"
            "severity_v2_high_min = 7\n"
        )
        with patch(
            "subprocess.run",
            return_value=MagicMock(
                returncode=0,
                stdout=output,
                stderr="",
            ),
        ):
            result = generate_config_example.run_config_list(tmp_path)
        assert "cache_db" in result
        assert "ignore_db" in result
        assert "severity_v2_critical_min" in result
        assert result["severity_v2_critical_min"] == "9"


class TestLanguageKeysFromConfig:
    """Tests for _language_keys_from_config."""

    def test_derives_from_config_list(self) -> None:
        config_list = {"python.regex": "^req$", "rust.regex": "^Cargo$"}
        result = generate_config_example._language_keys_from_config(
            config_list, {}
        )
        assert result == [("python", "^req$"), ("rust", "^Cargo$")]

    def test_derives_from_comments_when_config_empty(self) -> None:
        config_list = {}
        comments = {
            "python.regex": {"default": "^requirements\\.txt$"},
            "rust.regex": {"default": "^Cargo\\.toml$"},
        }
        result = generate_config_example._language_keys_from_config(
            config_list, comments
        )
        assert result == [
            ("python", "^requirements\\.txt$"),
            ("rust", "^Cargo\\.toml$"),
        ]

    def test_config_list_overrides_comments(self) -> None:
        config_list = {"java.regex": "^pom\\.xml$"}
        comments = {"java.regex": {"default": "^build\\.xml$"}}
        result = generate_config_example._language_keys_from_config(
            config_list, comments
        )
        assert result == [("java", "^pom\\.xml$")]


class TestBuildConfigData:
    """Tests for build_config_data."""

    def test_merges_config_list_with_comments(self) -> None:
        config_list = {"parallel_queries": "10", "cache_ttl_secs": "432000"}
        comments = {
            "parallel_queries": {
                "type": "integer",
                "env": "VLZ_PARALLEL_QUERIES",
                "cli": "--parallel",
            },
            "cache_ttl_secs": {
                "type": "integer",
                "env": "VLZ_CACHE_TTL_SECS",
                "cli": "--cache-ttl-secs",
            },
        }
        rows = generate_config_example.build_config_data(config_list, comments)
        assert len(rows) >= 2
        pq = next(r for r in rows if r[0] == "parallel_queries")
        assert pq[1] == "10"
        assert pq[2] == "integer"
        assert pq[3] == "VLZ_PARALLEL_QUERIES"
        assert pq[4] == "--parallel"

    def test_uses_manifest_default_when_key_missing(self) -> None:
        config_list = {}
        comments = {"exit_code_on_cve": {"default": "86", "type": "integer"}}
        rows = generate_config_example.build_config_data(config_list, comments)
        ec = next(r for r in rows if r[0] == "exit_code_on_cve")
        assert ec[1] == "86"

    def test_build_config_data_uses_parsed_keys(self) -> None:
        """Keys from config_list are used; order preserved from config --list."""
        config_list = {
            "cache_db": "",
            "ignore_db": "",
            "parallel_queries": "10",
            "custom_key": "custom_val",
        }
        comments = {
            "parallel_queries": {"type": "integer", "env": "VLZ_PARALLEL"},
            "custom_key": {"description": "Custom", "type": "string"},
        }
        rows = generate_config_example.build_config_data(config_list, comments)
        keys = [r[0] for r in rows]
        assert "custom_key" in keys
        ck = next(r for r in rows if r[0] == "custom_key")
        assert ck[1] == "custom_val"


class TestBuildSeverityData:
    """Tests for build_severity_data."""

    def test_produces_markdown_table(self) -> None:
        comments = {
            "severity_v2_critical_min": {"default": "9.0"},
            "severity_v2_high_min": {"default": "7.0"},
            "severity_v3_critical_min": {"default": "9.0"},
        }
        result = generate_config_example.build_severity_data({}, comments)
        assert "| Version |" in result
        assert "| v2 |" in result
        assert "| v3 |" in result
        assert "| v4 |" in result
        assert "9.0" in result
        assert "7.0" in result

    def test_uses_config_list_when_available(self) -> None:
        """Severity values from config_list override manifest defaults."""
        config_list = {"severity_v2_critical_min": "8.5"}
        comments = {"severity_v2_critical_min": {"default": "9.0"}}
        result = generate_config_example.build_severity_data(
            config_list, comments
        )
        assert "8.5" in result
        assert "| v2 |" in result


class TestGetLineLength:
    """Tests for get_line_length."""

    def test_returns_79_from_pyproject(self) -> None:
        """Line length comes from pyproject.toml [tool.verilyze]."""
        result = generate_config_example.get_line_length()
        assert result == 79

    def test_returns_default_when_missing(self, tmp_path: Path) -> None:
        """Defaults to 79 when [tool.verilyze] line-length is missing."""
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = \"test\"\n", encoding="utf-8")
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            result = generate_config_example.get_line_length()
        assert result == 79


class TestWrapComment:
    """Tests for wrap_comment."""

    def test_short_text_single_line(self) -> None:
        result = generate_config_example.wrap_comment("Short description")
        assert result == ["# Short description"]

    def test_empty_returns_empty_list(self) -> None:
        result = generate_config_example.wrap_comment("")
        assert result == []

    def test_wraps_at_word_boundary(self) -> None:
        text = "Minimum count of CVEs meeting min-score to trigger exit code (0 = any)"
        result = generate_config_example.wrap_comment(text, width=79)
        assert all(len(line) <= 79 for line in result)
        assert all(line.startswith("# ") for line in result)
        assert "Minimum count" in result[0]
        assert "(0 = any)" in result[-1]

    def test_long_word_exceeds_width_breaks_anyway(self) -> None:
        text = "a" * 100
        result = generate_config_example.wrap_comment(text, width=79)
        assert all(len(line) <= 79 for line in result)
        assert "".join(line[2:] for line in result) == text


class TestGenerateExampleConf:
    """Tests for generate_example_conf."""

    def test_no_spdx_in_output(self) -> None:
        """Generated output is machine-generated; no SPDX header."""
        result = generate_config_example.generate_example_conf({}, {})
        assert "SPDX-FileCopyrightText" not in result
        assert "SPDX-License-Identifier" not in result

    def test_comment_above_value_not_inline(self) -> None:
        """Comments appear above the value, not on the same line."""
        config_list = {"parallel_queries": "10"}
        comments = {"parallel_queries": {"description": "Max queries"}}
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        assert "# Max queries" in result
        assert "# parallel_queries = 10" in result
        assert "  # Max queries" not in result

    def test_long_comment_wrapped_at_79_chars(self) -> None:
        """Long descriptions are wrapped at 79 characters."""
        long_desc = (
            "Minimum count of CVEs meeting min-score to trigger exit code "
            "(0 = any)"
        )
        config_list = {"min_count": "0"}
        comments = {"min_count": {"description": long_desc}}
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        for line in result.splitlines():
            assert len(line) <= 79, f"Line exceeds 79 chars: {line!r}"

    def test_contains_scalar_keys(self) -> None:
        config_list = {"parallel_queries": "10"}
        comments = {"parallel_queries": {"description": "Max queries"}}
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        assert "parallel_queries" in result
        assert "10" in result
        assert "Max queries" in result

    def test_contains_severity_sections(self) -> None:
        comments = {"severity_v3_critical_min": {"default": "9.0"}}
        result = generate_config_example.generate_example_conf({}, comments)
        assert "[severity.v2]" in result
        assert "[severity.v3]" in result
        assert "[severity.v4]" in result

    def test_generate_example_conf_includes_severity_from_config_list(
        self,
    ) -> None:
        """Severity values in output come from config_list when present."""
        config_list = {"severity_v2_critical_min": "8.5"}
        comments = {"severity_v2_critical_min": {"default": "9.0"}}
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        assert "8.5" in result
        assert "# [severity.v2]" in result

    def test_contains_python_rust_regex(self) -> None:
        comments = {
            "python.regex": {"default": "^requirements\\.txt$"},
            "rust.regex": {"default": "^Cargo\\.toml$"},
        }
        result = generate_config_example.generate_example_conf({}, comments)
        assert "[python]" in result
        assert "[rust]" in result
        assert "requirements" in result
        assert "Cargo" in result

    def test_languages_derived_from_config_not_hardcoded(self) -> None:
        """Language list comes from config_list/comments, not hard-coded."""
        config_list = {"java.regex": "^pom\\.xml$"}
        comments = {"java.regex": {"default": "^pom\\.xml$"}}
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        assert "[java]" in result
        assert "pom" in result

    def test_language_default_fallback_from_comments_when_empty(self) -> None:
        """When config_list has lang.regex empty, default comes from comments."""
        config_list = {"java.regex": ""}
        comments = {"java.regex": {"default": "^pom\\.xml$"}}
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        assert "[java]" in result
        assert 'regex = "^pom\\.xml$"' in result

    def test_blank_line_after_each_scalar_key_value(self) -> None:
        """Blank line after each key/value pair groups comment with value."""
        config_list = {"parallel_queries": "10", "min_count": "0"}
        comments = {
            "parallel_queries": {"description": "Max queries"},
            "min_count": {"description": "Min count"},
        }
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        lines = result.splitlines()
        idx_pq = next(i for i, l in enumerate(lines) if "# parallel_queries =" in l)
        idx_mc = next(i for i, l in enumerate(lines) if "# min_count =" in l)
        assert lines[idx_pq + 1] == "", "blank line after parallel_queries"
        assert lines[idx_mc + 1] == "", "blank line after min_count"

    def test_cache_db_ignore_db_path_placeholder_when_empty(self) -> None:
        result = generate_config_example.generate_example_conf({}, {})
        assert "cache_db" in result
        assert "/path/to/db.redb" in result

    def test_cache_db_ignore_db_sanitized_when_tmp_empty_xdg(self) -> None:
        """Paths containing .tmp-empty-xdg are treated as empty for docs."""
        config_list = {
            "cache_db": "/home/user/proj/.tmp-empty-xdg/cache/verilyze/vlz-cache.redb",
            "ignore_db": "/home/user/proj/.tmp-empty-xdg/data/verilyze/vlz-ignore.redb",
        }
        comments = {
            "cache_db": {"description": "Path to CVE cache database"},
            "ignore_db": {"description": "Path to false-positive database"},
        }
        config_list = generate_config_example._sanitize_config_for_docs(
            config_list
        )
        result = generate_config_example.generate_example_conf(
            config_list, comments
        )
        assert ".tmp-empty-xdg" not in result
        assert "/path/to/db.redb" in result


class TestGenerateConfigTable:
    """Tests for generate_config_table."""

    def test_produces_markdown_rows(self) -> None:
        rows = [
            ("key1", "10", "integer", "VLZ_KEY1", "--key1"),
            ("key2", "", "string", "", ""),
        ]
        result = generate_config_example.generate_config_table(rows)
        assert "| key1 |" in result
        assert "| key2 |" in result
        assert "`VLZ_KEY1`" in result
        assert "`--key1`" in result
        assert "-" in result  # empty env/cli

    def test_empty_rows_returns_empty_string(self) -> None:
        result = generate_config_example.generate_config_table([])
        assert result == ""


class TestGenerateManOptions:
    """Tests for generate_man_options."""

    def test_produces_mdoc_it_va_lines(self) -> None:
        config_list = {"parallel_queries": "10"}
        comments = {
            "parallel_queries": {
                "description": "Max queries",
                "env": "VLZ_PARALLEL_QUERIES",
                "cli": "--parallel",
            },
        }
        result = generate_config_example.generate_man_options(
            config_list, comments
        )
        assert ".It Va parallel_queries" in result
        assert "Max queries" in result
        assert "Default: 10" in result

    def test_includes_severity_and_lang_regex(self) -> None:
        result = generate_config_example.generate_man_options({}, {})
        assert "[severity.v2]" in result
        assert "[lang].regex" in result
        assert ".El" in result


class TestMain:
    """Tests for main entry point."""

    def test_missing_manifest_returns_1(self, tmp_path: Path) -> None:
        (tmp_path / "scripts").mkdir()
        (tmp_path / "docs").mkdir()
        (tmp_path / "man").mkdir()
        (tmp_path / "docs" / "configuration.md.in").write_text(
            "{{CONFIG_TABLE}} {{SEVERITY_SECTION}}", encoding="utf-8"
        )
        (tmp_path / "man" / "verilyze.conf.5.in").write_text(
            "{{OPTIONS_SECTION}}", encoding="utf-8"
        )
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_config_example.main()
        assert exit_code == 1

    def test_missing_md_template_returns_1(self, tmp_path: Path) -> None:
        (tmp_path / "scripts").mkdir()
        (tmp_path / "docs").mkdir()
        (tmp_path / "man").mkdir()
        (tmp_path / "scripts" / "config-comments.yaml").write_text(
            "key:\n  desc: x\n", encoding="utf-8"
        )
        (tmp_path / "man" / "verilyze.conf.5.in").write_text(
            "{{OPTIONS_SECTION}}", encoding="utf-8"
        )
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_config_example.main()
        assert exit_code == 1

    def test_missing_man_template_returns_1(self, tmp_path: Path) -> None:
        (tmp_path / "scripts").mkdir()
        (tmp_path / "docs").mkdir()
        (tmp_path / "man").mkdir()
        (tmp_path / "scripts" / "config-comments.yaml").write_text(
            "key:\n  desc: x\n", encoding="utf-8"
        )
        (tmp_path / "docs" / "configuration.md.in").write_text(
            "{{CONFIG_TABLE}} {{SEVERITY_SECTION}}", encoding="utf-8"
        )
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch("sys.argv", ["gen.py"]):
                exit_code = generate_config_example.main()
        assert exit_code == 1

    def test_check_mode_out_of_sync_returns_1(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        (tmp_path / "verilyze.conf.example").write_text(  # wrong content
            "wrong", encoding="utf-8"
        )
        (tmp_path / "docs").mkdir(exist_ok=True)
        (tmp_path / "man").mkdir(exist_ok=True)
        (tmp_path / "docs" / "configuration.md").write_text("x", encoding="utf-8")
        (tmp_path / "man" / "verilyze.conf.5").write_text("y", encoding="utf-8")
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch.object(
                generate_config_example,
                "run_config_list",
                return_value={"parallel_queries": "10", "cache_ttl_secs": "432000"},
            ):
                with patch("sys.argv", ["gen.py", "--check"]):
                    exit_code = generate_config_example.main()
        assert exit_code == 1

    def test_check_mode_missing_file_returns_1(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch.object(
                generate_config_example,
                "run_config_list",
                return_value={"parallel_queries": "10"},
            ):
                with patch("sys.argv", ["gen.py", "--check"]):
                    exit_code = generate_config_example.main()
        assert exit_code == 1

    def test_check_mode_in_sync_returns_0(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        config_list = {"parallel_queries": "10", "cache_ttl_secs": "432000"}
        comments = generate_config_example.parse_config_comments(
            tmp_path / "scripts" / "config-comments.yaml"
        )
        rows = generate_config_example.build_config_data(config_list, comments)
        example = generate_config_example.generate_example_conf(
            config_list, comments
        )
        table = generate_config_example.generate_config_table(rows)
        severity = generate_config_example.build_severity_data(
            config_list, comments
        )
        options = generate_config_example.generate_man_options(
            config_list, comments
        )
        (tmp_path / "verilyze.conf.example").write_text(example, encoding="utf-8")
        (tmp_path / "docs").mkdir(exist_ok=True)
        (tmp_path / "man").mkdir(exist_ok=True)
        md_content = (tmp_path / "docs" / "configuration.md.in").read_text()
        md_content = md_content.replace("{{CONFIG_TABLE}}", table)
        md_content = md_content.replace("{{SEVERITY_SECTION}}", severity)
        (tmp_path / "docs" / "configuration.md").write_text(
            md_content, encoding="utf-8"
        )
        man_content = (tmp_path / "man" / "verilyze.conf.5.in").read_text()
        man_content = man_content.replace("{{OPTIONS_SECTION}}", options)
        (tmp_path / "man" / "verilyze.conf.5").write_text(
            man_content, encoding="utf-8"
        )
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch.object(
                generate_config_example,
                "run_config_list",
                return_value=config_list,
            ):
                with patch("sys.argv", ["gen.py", "--check"]):
                    exit_code = generate_config_example.main()
        assert exit_code == 0

    def test_default_mode_writes_files(self, tmp_path: Path) -> None:
        self._setup_fixture(tmp_path)
        config_list = {"parallel_queries": "10", "cache_ttl_secs": "432000"}
        with patch.object(
            generate_config_example,
            "get_repo_root",
            return_value=tmp_path,
        ):
            with patch.object(
                generate_config_example,
                "run_config_list",
                return_value=config_list,
            ):
                with patch("sys.argv", ["gen.py"]):
                    exit_code = generate_config_example.main()
        assert exit_code == 0
        assert (tmp_path / "verilyze.conf.example").exists()
        assert (tmp_path / "docs" / "configuration.md").exists()
        assert (tmp_path / "man" / "verilyze.conf.5").exists()

    def _setup_fixture(self, tmp_path: Path) -> None:
        """Create minimal config-comments.yaml and templates."""
        (tmp_path / "scripts").mkdir(parents=True)
        (tmp_path / "docs").mkdir(parents=True)
        (tmp_path / "man").mkdir(parents=True)
        (tmp_path / "scripts" / "config-comments.yaml").write_text(
            "parallel_queries:\n"
            "  description: \"Max queries\"\n"
            "  type: integer\n"
            "  env: VLZ_PARALLEL_QUERIES\n"
            "  cli: \"--parallel\"\n"
            "cache_ttl_secs:\n"
            "  description: \"TTL\"\n"
            "  type: integer\n"
            "  env: VLZ_CACHE_TTL_SECS\n"
            "  cli: \"--cache-ttl-secs\"\n"
            "severity_v3_critical_min:\n"
            "  default: \"9.0\"\n",
            encoding="utf-8",
        )
        (tmp_path / "docs" / "configuration.md.in").write_text(
            "{{CONFIG_TABLE}}\n{{SEVERITY_SECTION}}", encoding="utf-8"
        )
        (tmp_path / "man" / "verilyze.conf.5.in").write_text(
            "{{OPTIONS_SECTION}}", encoding="utf-8"
        )


# REUSE-IgnoreEnd
