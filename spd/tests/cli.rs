// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;
use std::process::{Command, Stdio};

/// Path to the spd binary (set by Cargo when running tests).
fn spd_exe() -> String {
    std::env::var("CARGO_BIN_EXE_spd").expect("CARGO_BIN_EXE_spd must be set when running tests")
}

fn spd_exe_exists() -> bool {
    std::env::var("CARGO_BIN_EXE_spd")
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

/// Run spd with args and broken stdout pipe; assert exit 0 (no panic).
fn assert_broken_pipe_exits_cleanly(args: &[&str]) {
    with_isolated_env(|p| {
        let mut child = Command::new(spd_exe())
            .args(args)
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
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
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["version"]);
}

#[test]
fn broken_pipe_preload() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["preload"]);
}

#[test]
fn broken_pipe_db_migrate() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "migrate"]);
}

#[test]
fn broken_pipe_db_show() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "show"]);
}

#[test]
fn broken_pipe_db_show_full() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "show", "--full"]);
}

#[test]
fn broken_pipe_db_show_format_json() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "show", "--format", "json"]);
}

#[test]
fn broken_pipe_list() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["list"]);
}

#[test]
fn broken_pipe_config_list() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["config", "--list"]);
}

#[test]
fn broken_pipe_db_list_providers() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "list-providers"]);
}

#[test]
fn broken_pipe_db_stats() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "stats"]);
}

#[test]
fn broken_pipe_db_verify() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "verify"]);
}

#[test]
fn broken_pipe_db_set_ttl_all() {
    if !spd_exe_exists() {
        return;
    }
    assert_broken_pipe_exits_cleanly(&["db", "set-ttl", "3600", "--all"]);
}

#[test]
fn broken_pipe_scan_benchmark() {
    if !spd_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let mut child = Command::new(spd_exe())
            .args(["scan", p, "--benchmark", "--offline"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
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
    if !spd_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let ignore_db = std::path::Path::new(p).join("ignore.redb");
        let mut child = Command::new(spd_exe())
            .args(["fp", "mark", "CVE-2020-1234", "--comment", "test"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .env("SPD_IGNORE_DB", ignore_db.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
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
    if !spd_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let ignore_db = std::path::Path::new(p).join("ignore.redb");
        let mark = Command::new(spd_exe())
            .args(["fp", "mark", "CVE-2020-1234", "--comment", "test"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .env("SPD_IGNORE_DB", ignore_db.as_os_str())
            .output()
            .expect("spawn spd fp mark");
        assert!(mark.status.success(), "fp mark must succeed first");
        let mut child = Command::new(spd_exe())
            .args(["fp", "unmark", "CVE-2020-1234"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .env("SPD_IGNORE_DB", ignore_db.as_os_str())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn spd");
        drop(child.stdout.take());
        let status = child.wait().expect("wait");
        assert_eq!(
            status.code(),
            Some(0),
            "fp unmark should exit 0 on broken pipe"
        );
    });
}

#[test]
fn cli_db_show_help_succeeds() {
    if !spd_exe_exists() {
        return;
    }
    let exe = spd_exe();
    let out = Command::new(&exe)
        .args(["db", "show", "--help"])
        .output()
        .expect("run spd db show --help");
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
    if !spd_exe_exists() {
        return;
    }
    let exe = spd_exe();
    let out = Command::new(&exe)
        .args(["db", "set-ttl", "--help"])
        .output()
        .expect("run spd db set-ttl --help");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_command_succeeds_and_prints_plugins() {
    if !spd_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(spd_exe())
            .args(["list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run spd list");
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
    if !spd_exe_exists() {
        return;
    }
    with_isolated_env(|p| {
        let out = Command::new(spd_exe())
            .args(["config", "--list"])
            .env("XDG_CACHE_HOME", p)
            .env("XDG_DATA_HOME", p)
            .env("XDG_CONFIG_HOME", p)
            .output()
            .expect("run spd config --list");
        assert!(
            out.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
}
