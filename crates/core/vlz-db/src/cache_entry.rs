// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared CVE cache entry types and helpers (NFR-024).
//! Used by RedB and in-memory backends so TTL/key semantics stay DRY.

use crate::Package;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Serialized form of a cache entry (raw vuln JSON per package+provider + TTL).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredEntry {
    pub raw_vulns: Vec<serde_json::Value>,
    pub provider_id: String,
    #[serde(rename = "expires_at_secs")]
    pub expires_at_secs: u64,
    #[serde(default)]
    pub added_at_secs: Option<u64>,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
}

/// Minimal struct for purge: only need expires_at to decide whether to remove.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PurgeEntry {
    #[serde(rename = "expires_at_secs")]
    pub expires_at_secs: u64,
}

/// Cache key: `name::version::provider_id`.
pub fn pkg_cache_key(pkg: &Package, provider_id: &str) -> String {
    format!("{}::{}::{}", pkg.name, pkg.version, provider_id)
}

/// Unix seconds since epoch (0 if clock is before epoch).
pub fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Normalize after deserialization: fill added_at_secs/ttl_secs from expiry if missing.
pub fn normalize_stored_entry(entry: &mut StoredEntry, default_ttl_secs: u64) {
    if entry.added_at_secs.is_none() || entry.ttl_secs.is_none() {
        let ttl = entry.ttl_secs.unwrap_or(default_ttl_secs);
        entry.added_at_secs = Some(entry.expires_at_secs.saturating_sub(ttl));
        entry.ttl_secs = Some(ttl);
    }
}

/// Build a new stored entry for a fresh put.
pub fn new_stored_entry(
    provider_id: &str,
    raw_vulns: &[serde_json::Value],
    ttl_secs: u64,
    now_secs: u64,
) -> StoredEntry {
    let ttl = ttl_secs.max(1);
    StoredEntry {
        raw_vulns: raw_vulns.to_vec(),
        provider_id: provider_id.to_string(),
        expires_at_secs: now_secs.saturating_add(ttl),
        added_at_secs: Some(now_secs),
        ttl_secs: Some(ttl),
    }
}

/// True when the entry is past its expiry (treat as cache miss).
pub fn entry_is_expired(entry: &StoredEntry, now_secs: u64) -> bool {
    entry.expires_at_secs <= now_secs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkg_cache_key_includes_provider() {
        let pkg = Package {
            name: "foo".into(),
            version: "1.0".into(),
            ecosystem: None,
        };
        assert_eq!(pkg_cache_key(&pkg, "osv"), "foo::1.0::osv");
    }

    #[test]
    fn normalize_fills_missing_added_and_ttl() {
        let mut entry = StoredEntry {
            raw_vulns: vec![],
            provider_id: "osv".into(),
            expires_at_secs: 1000,
            added_at_secs: None,
            ttl_secs: None,
        };
        normalize_stored_entry(&mut entry, 100);
        assert_eq!(entry.ttl_secs, Some(100));
        assert_eq!(entry.added_at_secs, Some(900));
    }

    #[test]
    fn normalize_uses_existing_ttl_when_added_missing() {
        let mut entry = StoredEntry {
            raw_vulns: vec![],
            provider_id: "osv".into(),
            expires_at_secs: 500,
            added_at_secs: None,
            ttl_secs: Some(50),
        };
        normalize_stored_entry(&mut entry, 999);
        assert_eq!(entry.ttl_secs, Some(50));
        assert_eq!(entry.added_at_secs, Some(450));
    }

    #[test]
    fn new_stored_entry_clamps_ttl_and_sets_expiry() {
        let entry = new_stored_entry("osv", &[], 0, 1000);
        assert_eq!(entry.ttl_secs, Some(1));
        assert_eq!(entry.expires_at_secs, 1001);
        assert_eq!(entry.added_at_secs, Some(1000));
    }

    #[test]
    fn entry_is_expired_at_boundary() {
        let entry = new_stored_entry("osv", &[], 10, 100);
        assert!(!entry_is_expired(&entry, 109));
        assert!(entry_is_expired(&entry, 110));
    }

    #[test]
    fn stored_entry_serde_roundtrip() {
        let entry = new_stored_entry(
            "osv",
            &[serde_json::json!({"id": "CVE-1"})],
            60,
            1_700_000_000,
        );
        let json = serde_json::to_string(&entry).unwrap();
        let back: StoredEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn purge_entry_deserializes_expires_only() {
        let json = r#"{"expires_at_secs":42,"raw_vulns":[]}"#;
        let p: PurgeEntry = serde_json::from_str(json).unwrap();
        assert_eq!(p.expires_at_secs, 42);
    }
}
