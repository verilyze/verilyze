// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! SEC-004 / SEC-005 / FR-033: `vlz db verify` and `vlz db migrate` against
//! a real redb cache file, using whichever sealer this build enables.

#![cfg(feature = "integrity-sha256")]

#[allow(dead_code)] // only the subprocess env helper is used here
mod support;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use support::apply_isolated_db_env;
use vlz_db::{DatabaseBackend, Package};
use vlz_db_redb::{MIGRATE_HINT, RedbBackend};
use vlz_integrity::{
    active_entry_sealer, integrity_ok_message, seals_backfilled_message,
};

const TTL_SECS: u64 = 3600;
const PROVIDER: &str = "osv";

fn cache_db(xdg: &Path) -> PathBuf {
    xdg.join("vlz-cache.redb")
}

fn pkg(name: &str) -> Package {
    Package {
        name: name.to_string(),
        version: "1.0".to_string(),
        ..Default::default()
    }
}

fn raw(id: &str) -> Vec<serde_json::Value> {
    vec![serde_json::json!({ "id": id, "summary": "integrity test" })]
}

/// Write entries with the build's sealer (what `vlz scan` does).
fn put_sealed(xdg: &Path, names: &[&str]) {
    let path = cache_db(xdg);
    let sealer = active_entry_sealer(&path).expect("sealer enabled");
    let backend = RedbBackend::with_path(path, TTL_SECS)
        .expect("open cache")
        .with_sealer(sealer);
    put_all(&backend, names, "CVE-2024-0001");
}

/// Write entries without sealing, like an edit made outside vlz or a
/// cache written before sealing existed.
fn put_unsealed(xdg: &Path, names: &[&str], id: &str) {
    let backend =
        RedbBackend::with_path(cache_db(xdg), TTL_SECS).expect("open cache");
    put_all(&backend, names, id);
}

fn put_all(backend: &RedbBackend, names: &[&str], id: &str) {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        backend.init().await.expect("init");
        for name in names {
            backend
                .put(&pkg(name), PROVIDER, &raw(id), None)
                .await
                .expect("put");
        }
    });
}

fn vlz_db(xdg: &Path, sub: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vlz"));
    cmd.args(["db", sub]);
    apply_isolated_db_env(&mut cmd, xdg);
    cmd.env_remove("RUST_LOG").output().expect("run vlz")
}

fn label(xdg: &Path) -> &'static str {
    active_entry_sealer(&cache_db(xdg))
        .expect("sealer enabled")
        .label()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn verify_sealed_cache_prints_algorithm_label() {
    let dir = tempfile::tempdir().expect("tempdir");
    put_sealed(dir.path(), &["a", "b"]);
    let out = vlz_db(dir.path(), "verify");
    assert_eq!(out.status.code(), Some(0), "stderr={}", stderr(&out));
    assert_eq!(
        stdout(&out),
        format!("{}\n", integrity_ok_message(label(dir.path())))
    );
}

#[test]
fn verify_exits_1_after_value_edited_outside_vlz() {
    let dir = tempfile::tempdir().expect("tempdir");
    put_sealed(dir.path(), &["a", "b"]);
    put_unsealed(dir.path(), &["a"], "CVE-2099-EDIT");
    let out = vlz_db(dir.path(), "verify");
    let err = stderr(&out);
    assert_eq!(out.status.code(), Some(1), "FR-033; stderr={err}");
    assert!(err.contains("1 mismatched"), "{err}");
    assert!(err.contains("a::1.0::osv"), "{err}");
    assert!(stdout(&out).is_empty(), "no OK line on failure");
}

#[test]
fn migrate_seals_legacy_cache_then_verify_passes() {
    let dir = tempfile::tempdir().expect("tempdir");
    put_unsealed(dir.path(), &["old1", "old2"], "CVE-2024-0002");

    let before = vlz_db(dir.path(), "verify");
    assert_eq!(before.status.code(), Some(1));
    assert!(
        stderr(&before).contains(MIGRATE_HINT),
        "{}",
        stderr(&before)
    );

    let migrate = vlz_db(dir.path(), "migrate");
    assert_eq!(migrate.status.code(), Some(0), "{}", stderr(&migrate));
    assert_eq!(
        stdout(&migrate),
        format!("{}\n", seals_backfilled_message(2))
    );

    let after = vlz_db(dir.path(), "verify");
    assert_eq!(after.status.code(), Some(0), "{}", stderr(&after));
}

#[test]
fn migrate_does_not_launder_tampered_entry() {
    let dir = tempfile::tempdir().expect("tempdir");
    put_sealed(dir.path(), &["a"]);
    put_unsealed(dir.path(), &["a"], "CVE-2099-EDIT");

    let migrate = vlz_db(dir.path(), "migrate");
    assert_eq!(migrate.status.code(), Some(0), "{}", stderr(&migrate));
    assert_eq!(
        stdout(&migrate),
        format!("{}\n", seals_backfilled_message(0))
    );

    let out = vlz_db(dir.path(), "verify");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
    assert!(stderr(&out).contains("1 mismatched"), "{}", stderr(&out));
}
