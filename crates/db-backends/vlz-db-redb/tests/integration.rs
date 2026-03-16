// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::PathBuf;
use vlz_db::DatabaseBackend;
use vlz_db::Package;
use vlz_db_redb::{RedbBackend, RedbIgnoreDb};

fn temp_cache_path(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("vlz_redb_test_{}.redb", name));
    (dir, path)
}

fn temp_ignore_path(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("vlz_ignore_test_{}.redb", name));
    (dir, path)
}

fn sample_raw_vuln() -> serde_json::Value {
    serde_json::json!({
        "id": "CVE-2023-test",
        "database_specific": { "cvss_v3_score": 7.0 },
        "summary": "Test vuln"
    })
}

#[tokio::test]
async fn redb_backend_init_succeeds() {
    let (_dir, path) = temp_cache_path("init");
    let backend = RedbBackend::with_path(path, 3600).unwrap();
    backend.init().await.unwrap();
}

#[tokio::test]
async fn redb_backend_put_then_get() {
    let (_dir, path) = temp_cache_path("put_get");
    let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
    backend.init().await.unwrap();
    let pkg = Package {
        name: "foo".to_string(),
        version: "1.0".to_string(),
        ecosystem: None,
    };
    let raw = vec![sample_raw_vuln()];
    backend.put(&pkg, "osv", &raw, None).await.unwrap();
    let got = backend.get(&pkg, "osv").await.unwrap();
    assert!(got.is_some());
    let recs = got.unwrap();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].id, "CVE-2023-test");
    assert_eq!(recs[0].cvss_score, Some(7.0));
}

#[tokio::test]
async fn redb_backend_get_unknown_returns_none_increments_misses() {
    let (_dir, path) = temp_cache_path("misses");
    let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
    backend.init().await.unwrap();
    let pkg = Package {
        name: "nonexistent".to_string(),
        version: "0".to_string(),
        ecosystem: None,
    };
    let r1 = backend.get(&pkg, "osv").await.unwrap();
    let r2 = backend.get(&pkg, "osv").await.unwrap();
    let stats = backend.stats().await.unwrap();
    assert!(r1.is_none());
    assert!(r2.is_none());
    assert_eq!(stats.misses, 2);
}

#[tokio::test]
async fn redb_backend_stats() {
    let (_dir, path) = temp_cache_path("stats");
    let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
    backend.init().await.unwrap();
    let pkg = Package {
        name: "p".to_string(),
        version: "1".to_string(),
        ecosystem: None,
    };
    backend
        .put(&pkg, "osv", &[sample_raw_vuln()], None)
        .await
        .unwrap();
    let _ = backend.get(&pkg, "osv").await.unwrap();
    let stats = backend.stats().await.unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(stats.cached_entries >= 1);
    assert!(stats.hits >= 1);
}

#[tokio::test]
async fn stats_reflect_hits_after_get() {
    let (_dir, path) = temp_cache_path("stats_hits");
    let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
    backend.init().await.unwrap();
    let pkg = Package {
        name: "pkg".to_string(),
        version: "1.0".to_string(),
        ecosystem: None,
    };
    backend
        .put(&pkg, "osv", &[sample_raw_vuln()], None)
        .await
        .unwrap();
    let _ = backend.get(&pkg, "osv").await.unwrap();
    let _ = backend.get(&pkg, "osv").await.unwrap();
    let stats = backend.stats().await.unwrap();
    assert_eq!(stats.hits, 2, "stats should show 2 hits after two get(hit)");
    assert_eq!(stats.misses, 0);
}

#[tokio::test]
async fn stats_persisted_across_backend_instances() {
    let (_dir, path) = temp_cache_path("stats_persist");
    {
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "foo".to_string(),
            version: "2.0".to_string(),
            ecosystem: None,
        };
        backend
            .put(&pkg, "osv", &[sample_raw_vuln()], None)
            .await
            .unwrap();
        let _ = backend.get(&pkg, "osv").await.unwrap();
    }
    let backend2 = RedbBackend::with_path(path.clone(), 3600).unwrap();
    backend2.init().await.unwrap();
    let stats = backend2.stats().await.unwrap();
    assert!(
        stats.hits >= 1,
        "new backend must see persisted hits (got {})",
        stats.hits
    );
    assert!(stats.cached_entries >= 1);
}

#[tokio::test]
async fn stats_persisted_misses_across_backend_instances() {
    let (_dir, path) = temp_cache_path("stats_misses_persist");
    {
        let backend = RedbBackend::with_path(path.clone(), 3600).unwrap();
        backend.init().await.unwrap();
        let pkg = Package {
            name: "nonexistent".to_string(),
            version: "0".to_string(),
            ecosystem: None,
        };
        let _ = backend.get(&pkg, "osv").await.unwrap();
        let _ = backend.get(&pkg, "osv").await.unwrap();
    }
    let backend2 = RedbBackend::with_path(path.clone(), 3600).unwrap();
    backend2.init().await.unwrap();
    let stats = backend2.stats().await.unwrap();
    assert_eq!(
        stats.misses, 2,
        "new backend must see persisted misses (got {})",
        stats.misses
    );
}

#[tokio::test]
async fn redb_ignore_db_mark_unmark_fr015() {
    let (_dir, path) = temp_ignore_path("mark_unmark");
    let db = RedbIgnoreDb::with_path(path.clone()).unwrap();
    db.mark("CVE-2023-1234", "vendor bug", Some("proj1"))
        .unwrap();
    assert!(db.is_marked("CVE-2023-1234").unwrap());
    let ids = db.marked_ids(Some("proj1")).unwrap();
    assert!(ids.contains("CVE-2023-1234"));
    assert!(
        db.marked_ids(None).unwrap().is_empty(),
        "scoped FP not in global"
    );
    db.unmark("CVE-2023-1234").unwrap();
    assert!(!db.is_marked("CVE-2023-1234").unwrap());
    assert!(db.marked_ids(Some("proj1")).unwrap().is_empty());
}
