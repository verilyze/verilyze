// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;
use std::process::{Command, Stdio};
use vlz::cli::DOCS_ONLINE_URL;

/// Path to the vlz binary (set by Cargo when running tests).
fn vlz_exe() -> String {
    std::env::var("CARGO_BIN_EXE_vlz")
        .expect("CARGO_BIN_EXE_vlz must be set when running tests")
}

fn vlz_exe_exists() -> bool {
    std::env::var("CARGO_BIN_EXE_vlz")
        .map(|p| Path::new(&p).exists())
        .unwrap_or(false)
}

/// Run closure with isolated XDG env so each test uses its own cache (avoids lock contention).
fn with_isolated_env<F, T>(f: F) -> T
where
    F: FnOnce(&str) -> T,
{
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().to_string_lossy();
    f(&p)
}

/// Run vlz with args and broken stdout pipe; assert exit 0 (no panic).
fn assert_broken_pipe_exits_cleanly(args: &[&str]) {
    with_isolated_env(|p| {
        let mut child = Command::new(vlz_exe())
            .args(args)
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vlz");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert!(
            status.code() == Some(0),
            "args {:?} should exit 0 on broken pipe, got {:?}",
            args,
            status.code()
        );
    });
}

#[test]
fn broken_pipe_version() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["--version"]);
}

#[test]
fn broken_pipe_preload() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["preload"]);
}

#[test]
fn broken_pipe_db_migrate() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "migrate"]);
}

#[test]
fn broken_pipe_db_show() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "show"]);
}

#[test]
fn broken_pipe_db_show_full() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "show", "--full"]);
}

#[test]
fn broken_pipe_db_show_format_json() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "show", "--format", "json"]);
}

#[test]
fn broken_pipe_list() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["list"]);
}

#[test]
fn broken_pipe_config_list() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["config", "--list"]);
}

#[test]
fn broken_pipe_config_example() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["config", "--example"]);
}

#[test]
fn broken_pipe_db_list_providers() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "list-providers"]);
}

#[test]
fn broken_pipe_db_stats() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "stats"]);
}

#[test]
fn broken_pipe_db_verify() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "verify"]);
}

#[test]
fn broken_pipe_db_set_ttl_all() {
    if !vlz_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "set-ttl", "3600", "--all"]);
}

#[test]
fn broken_pipe_scan_benchmark() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let mut child = Command::new(vlz_exe())
            .args(["scan", p, "--benchmark", "--offline"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vlz");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert!(
            status.code() == Some(0),
            "scan with broken pipe should exit 0, got {:?}",
            status.code()
        );
    });
}

#[cfg(feature = "redb")]
#[test]
fn broken_pipe_fp_mark() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let ignore_db = std::path::Path::new(p).join("ignore.redb");
        let mut child = Command::new(vlz_exe())
            .args(["fp", "mark", "CVE-2020-1234", "--comment", "test"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .env("VLZ_IGNORE_DB", ignore_db.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vlz");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(0),
            "fp mark should exit 0 on broken pipe"
        );
    });
}

#[cfg(feature = "redb")]
#[test]
fn broken_pipe_fp_unmark() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let ignore_db = std::path::Path::new(p).join("ignore.redb");
        let mark = Command::new(vlz_exe())
            .args(["fp", "mark", "CVE-2020-1234", "--comment", "test"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .env("VLZ_IGNORE_DB", ignore_db.as_os_str())
            .output()
            .expect("spawn vlz fp mark");
        assert!(mark.status.success(), "fp mark must succeed first");
        let mut child = Command::new(vlz_exe())
            .args(["fp", "unmark", "CVE-2020-1234"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .env("VLZ_IGNORE_DB", ignore_db.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn vlz");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(0),
            "fp unmark should exit 0 on broken pipe"
        );
    });
}

/// MOD-009: vlz help exits 2 with error when built without docs; exits 0 when built with docs.
#[test]
fn help_subcommand_respects_docs_feature() {
    if !vlz_exe_exists() {
        return;
    }
    let out = Command::new(vlz_exe())
        .args(["help"])
        .output()
        .expect("run vlz help");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.status.code() == Some(2) {
        assert!(
            stderr.contains("built without documentation")
                || stderr.contains("without documentation"),
            "expected MOD-009 error when docs disabled, stderr: {}",
            stderr
        );
        assert!(
            stderr.contains("cargo build") || stderr.contains(DOCS_ONLINE_URL),
            "expected rebuild hint or URL, stderr: {}",
            stderr
        );
    } else {
        assert!(
            out.status.success(),
            "vlz help should exit 0 when docs enabled, got {}; stderr: {}",
            out.status,
            stderr
        );
        assert!(
            stdout.contains("vlz") || stdout.contains("verilyze"),
            "man page should mention vlz or verilyze, stdout: {}",
            stdout
        );
    }
}

#[test]
fn cli_db_show_help_succeeds() {
    if !vlz_exe_exists() {
        return;
    }
    let exe = vlz_exe();
    let out = Command::new(&exe)
        .args(["db", "show", "--help"])
        .output()
        .expect("run vlz db show --help");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("show") || stdout.contains("cache"));
}

#[test]
fn cli_db_set_ttl_help_succeeds() {
    if !vlz_exe_exists() {
        return;
    }
    let exe = vlz_exe();
    let out = Command::new(&exe)
        .args(["db", "set-ttl", "--help"])
        .output()
        .expect("run vlz db set-ttl --help");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_command_succeeds_and_prints_plugins() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("python") || !stdout.is_empty(),
            "list should print at least plugin names or empty"
        );
    });
}

#[test]
fn config_list_succeeds() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}

/// Parse `key = value` lines from config --list stdout. DOC-003: single source.
fn parse_config_list_output(
    stdout: &[u8],
) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in std::str::from_utf8(stdout).unwrap_or("").lines() {
        if let Some((key, value)) = line.split_once(" = ") {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

/// DOC-003: config --list must include cache_db (effective path when unset).
#[test]
fn config_list_includes_cache_db() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let cfg = parse_config_list_output(&out.stdout);
        assert!(
            cfg.contains_key("cache_db"),
            "config --list must include cache_db"
        );
    });
}

/// DOC-003: config --list must include ignore_db (effective path when unset).
#[test]
fn config_list_includes_ignore_db() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let cfg = parse_config_list_output(&out.stdout);
        assert!(
            cfg.contains_key("ignore_db"),
            "config --list must include ignore_db"
        );
    });
}

/// DOC-003: config --list must include exit_code_on_cve (default 86).
#[test]
fn config_list_includes_exit_code_on_cve() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let cfg = parse_config_list_output(&out.stdout);
        assert!(
            cfg.contains_key("exit_code_on_cve"),
            "config --list must include exit_code_on_cve"
        );
        assert_eq!(
            cfg.get("exit_code_on_cve").map(|s| s.as_str()),
            Some("86")
        );
    });
}

/// DOC-003: config --list must include fp_exit_code (default 0).
#[test]
fn config_list_includes_fp_exit_code() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let cfg = parse_config_list_output(&out.stdout);
        assert!(
            cfg.contains_key("fp_exit_code"),
            "config --list must include fp_exit_code"
        );
        assert_eq!(cfg.get("fp_exit_code").map(|s| s.as_str()), Some("0"));
    });
}

/// DOC-003: config --list must include all 12 severity thresholds (9.0, 7.0, 4.0, 0.1).
#[test]
fn config_list_includes_severity_thresholds() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let cfg = parse_config_list_output(&out.stdout);
        let severity_keys = [
            "severity_v2_critical_min",
            "severity_v2_high_min",
            "severity_v2_medium_min",
            "severity_v2_low_min",
            "severity_v3_critical_min",
            "severity_v3_high_min",
            "severity_v3_medium_min",
            "severity_v3_low_min",
            "severity_v4_critical_min",
            "severity_v4_high_min",
            "severity_v4_medium_min",
            "severity_v4_low_min",
        ];
        for key in &severity_keys {
            assert!(
                cfg.contains_key(*key),
                "config --list must include {}",
                key
            );
        }
        assert_eq!(
            cfg.get("severity_v2_critical_min").map(|s| s.as_str()),
            Some("9")
        );
        assert_eq!(
            cfg.get("severity_v2_high_min").map(|s| s.as_str()),
            Some("7")
        );
        assert_eq!(
            cfg.get("severity_v2_medium_min").map(|s| s.as_str()),
            Some("4")
        );
        assert_eq!(
            cfg.get("severity_v2_low_min").map(|s| s.as_str()),
            Some("0.1")
        );
    });
}

#[test]
fn config_invalid_file_exits_2() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let f = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(f.path(), "invalid toml {{{").expect("write");
        let path = f.path().to_str().unwrap();
        let out = Command::new(vlz_exe())
            .args(["-c", path, "list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz");
        assert_eq!(out.status.code(), Some(2), "invalid config should exit 2");
    });
}

#[test]
fn config_invalid_file_verbose_logs_to_stderr() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let f = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(f.path(), "invalid toml {{{").expect("write");
        let path = f.path().to_str().unwrap();
        let out = Command::new(vlz_exe())
            .args(["-vv", "-c", path, "list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz");
        assert_eq!(out.status.code(), Some(2));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stderr.is_empty(), "verbose error should log to stderr");
    });
}

// FR-028: shell completion generation
#[cfg(feature = "completions")]
#[test]
fn generate_completions_bash_produces_valid_script() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["generate-completions", "bash"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz");
        assert_eq!(out.status.code(), Some(0), "generate-completions bash");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.is_empty(),
            "bash completion script must not be empty"
        );
        assert!(stdout.contains("vlz"), "script must contain vlz");
        assert!(
            stdout.contains("scan"),
            "script must contain scan subcommand"
        );
        assert!(
            stdout.contains("list"),
            "script must contain list subcommand"
        );
    });
}

#[cfg(feature = "completions")]
#[test]
fn generate_completions_zsh_produces_valid_script() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["generate-completions", "zsh"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz");
        assert_eq!(out.status.code(), Some(0), "generate-completions zsh");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.is_empty(),
            "zsh completion script must not be empty"
        );
        assert!(stdout.contains("vlz"), "script must contain vlz");
        assert!(
            stdout.contains("scan"),
            "script must contain scan subcommand"
        );
        assert!(
            stdout.contains("list"),
            "script must contain list subcommand"
        );
    });
}

#[cfg(feature = "completions")]
#[test]
fn generate_completions_fish_produces_valid_script() {
    if !vlz_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(vlz_exe())
            .args(["generate-completions", "fish"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run vlz");
        assert_eq!(out.status.code(), Some(0), "generate-completions fish");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            !stdout.is_empty(),
            "fish completion script must not be empty"
        );
        assert!(stdout.contains("vlz"), "script must contain vlz");
        assert!(
            stdout.contains("scan"),
            "script must contain scan subcommand"
        );
        assert!(
            stdout.contains("list"),
            "script must contain list subcommand"
        );
    });
}
