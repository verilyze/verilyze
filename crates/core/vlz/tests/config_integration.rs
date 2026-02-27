// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;

use vlz::config::{
    ConfigError, DEFAULT_PARALLEL_QUERIES, SeverityOverrides, load,
    set_config_key,
};

fn temp_config(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verilyze.conf");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, content).unwrap();
    (dir, path)
}

#[test]
fn load_cli_overrides_file_cfg007() {
    let (_dir, path) = temp_config("parallel_queries = 5\n");
    let path_str = path.to_string_lossy().into_owned();
    let cfg = load(
        Some(&path_str),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(20),
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        SeverityOverrides::default(),
        SeverityOverrides::default(),
    )
    .unwrap();
    assert_eq!(cfg.parallel_queries, 20);
}

#[test]
fn load_env_overrides_file() {
    let (_dir, path) = temp_config("parallel_queries = 5\n");
    let path_str = path.to_string_lossy().into_owned();
    let cfg = load(
        Some(&path_str),
        Some(15),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        SeverityOverrides::default(),
        SeverityOverrides::default(),
    )
    .unwrap();
    assert_eq!(cfg.parallel_queries, 15);
}

#[test]
fn load_invalid_toml_cfg001() {
    let (_dir, path) = temp_config("not valid toml {{{");
    let path_str = path.to_string_lossy().into_owned();
    let r = load(
        Some(&path_str),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        SeverityOverrides::default(),
        SeverityOverrides::default(),
    );
    assert!(r.is_err());
    assert!(matches!(r.unwrap_err(), ConfigError::InvalidToml { .. }));
}

#[test]
fn load_unknown_key_returns_error_sec006() {
    let (_dir, path) = temp_config("unknown_key = 1\n");
    let path_str = path.to_string_lossy().into_owned();
    let r = load(
        Some(&path_str),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        SeverityOverrides::default(),
        SeverityOverrides::default(),
    );
    assert!(r.is_err());
    let e = r.unwrap_err();
    assert!(
        e.to_string().contains("unknown")
            || e.to_string().contains("InvalidToml")
    );
}

#[test]
fn load_user_config_populates_language_regexes() {
    let (_dir, path) = temp_config("[python]\nregex = \"requirements.txt\"\n");
    let path_str = path.to_string_lossy().into_owned();
    let cfg = load(
        Some(&path_str),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        SeverityOverrides::default(),
        SeverityOverrides::default(),
    )
    .unwrap();
    assert_eq!(cfg.language_regexes.len(), 1);
    assert_eq!(cfg.language_regexes[0].0, "python");
    assert_eq!(cfg.language_regexes[0].1, "requirements.txt");
}

#[test]
fn load_config_file_not_found_uses_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("nonexistent.conf");
    let path_str = missing.to_string_lossy().into_owned();
    let cfg = load(
        Some(&path_str),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        SeverityOverrides::default(),
        SeverityOverrides::default(),
    )
    .unwrap();
    assert_eq!(cfg.parallel_queries, DEFAULT_PARALLEL_QUERIES);
}

#[test]
fn set_config_key_then_load_fr006() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("verilyze")).unwrap();
    let path_str = dir.path().to_string_lossy().into_owned();
    temp_env::with_var("XDG_CONFIG_HOME", Some(path_str.as_str()), || {
        let res = set_config_key("python.regex", "^requirements\\.txt$");
        assert!(res.is_ok());
        let cfg = load(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            SeverityOverrides::default(),
            SeverityOverrides::default(),
        )
        .unwrap();
        assert_eq!(cfg.language_regexes.len(), 1);
        assert_eq!(cfg.language_regexes[0].0, "python");
        assert_eq!(cfg.language_regexes[0].1, "^requirements\\.txt$");
    });
}
