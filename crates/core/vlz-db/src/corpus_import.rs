// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Airgap CVE corpus import (FR-021a): parse a versioned snapshot and
//! map entries onto cache keys for `DatabaseBackend::put`.

use crate::{Package, pkg_cache_key};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Schema version for the vlz corpus JSON envelope.
pub const CORPUS_SCHEMA_VERSION: u32 = 1;

/// One cache entry to import (FR-021a).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CorpusEntry {
    /// Cache key `name::version::provider_id` (same as `pkg_cache_key`).
    pub key: String,
    /// Effective TTL in seconds for the imported entry.
    pub ttl_secs: u64,
    /// Optional added-at Unix seconds from the export; import may refresh.
    #[serde(default)]
    pub added_at_secs: Option<u64>,
    /// Full raw provider vuln JSON required for offline hits.
    pub raw_vulns: Vec<serde_json::Value>,
}

/// Versioned corpus document (`vlz db import`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CorpusDocument {
    pub schema_version: u32,
    pub entries: Vec<CorpusEntry>,
}

/// Errors while parsing or verifying a corpus file.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CorpusImportError {
    #[error("corpus JSON parse error: {0}")]
    Parse(String),
    #[error(
        "unsupported corpus schema_version {found} (supported: {supported})"
    )]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("corpus entry missing raw_vulns for key {0}")]
    MissingRawVulns(String),
    #[error("invalid cache key (expected name::version::provider): {0}")]
    InvalidKey(String),
    #[error("SHA-256 mismatch: expected {expected}, got {actual}")]
    Sha256Mismatch { expected: String, actual: String },
    #[error("SHA-256 digest must be 64 lowercase hex characters")]
    InvalidSha256Digest,
}

/// Parsed entry ready for `DatabaseBackend::put`.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportableEntry {
    pub package: Package,
    pub provider_id: String,
    pub raw_vulns: Vec<serde_json::Value>,
    pub ttl_secs: u64,
}

/// Hex-encode bytes as lowercase.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// SHA-256 of `bytes` as lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

/// Verify file bytes against an expected lowercase hex SHA-256 digest.
pub fn verify_sha256(
    bytes: &[u8],
    expected_hex: &str,
) -> Result<(), CorpusImportError> {
    let expected = expected_hex.trim().to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(CorpusImportError::InvalidSha256Digest);
    }
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(CorpusImportError::Sha256Mismatch { expected, actual });
    }
    Ok(())
}

/// Split `name::version::provider_id` (name may contain `::`).
pub fn parse_pkg_cache_key(
    key: &str,
) -> Result<(Package, String), CorpusImportError> {
    let parts: Vec<&str> = key.rsplitn(3, "::").collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err(CorpusImportError::InvalidKey(key.to_string()));
    }
    // rsplitn yields [provider, version, name]
    let provider_id = parts[0].to_string();
    let version = parts[1].to_string();
    let name = parts[2].to_string();
    Ok((
        Package {
            name,
            version,
            ecosystem: None,
        },
        provider_id,
    ))
}

fn entry_from_cache_info_like(
    key: String,
    ttl_secs: u64,
    added_at_secs: Option<u64>,
    raw_vulns: Option<Vec<serde_json::Value>>,
) -> Result<CorpusEntry, CorpusImportError> {
    let Some(raw_vulns) = raw_vulns else {
        return Err(CorpusImportError::MissingRawVulns(key));
    };
    // Reject slim exports without payloads even if the field is present empty
    // only when key cannot round-trip -- empty raw_vulns is a valid "no CVE"
    // cache hit for offline.
    let _ = parse_pkg_cache_key(&key)?;
    Ok(CorpusEntry {
        key,
        ttl_secs: ttl_secs.max(1),
        added_at_secs,
        raw_vulns,
    })
}

/// Parse corpus JSON: versioned envelope or bare `db show --full --format json`
/// array of cache entry objects.
pub fn parse_corpus_json(
    bytes: &[u8],
) -> Result<CorpusDocument, CorpusImportError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|e| CorpusImportError::Parse(e.to_string()))?;

    if let Some(obj) = value.as_object()
        && (obj.contains_key("schema_version") || obj.contains_key("entries"))
    {
        let doc: CorpusDocument = serde_json::from_value(value)
            .map_err(|e| CorpusImportError::Parse(e.to_string()))?;
        if doc.schema_version != CORPUS_SCHEMA_VERSION {
            return Err(CorpusImportError::UnsupportedSchema {
                found: doc.schema_version,
                supported: CORPUS_SCHEMA_VERSION,
            });
        }
        for entry in &doc.entries {
            let _ = parse_pkg_cache_key(&entry.key)?;
        }
        return Ok(doc);
    }

    if let Some(arr) = value.as_array() {
        let mut entries = Vec::with_capacity(arr.len());
        for item in arr {
            #[derive(serde::Deserialize)]
            struct Slim {
                key: String,
                ttl_secs: u64,
                #[serde(default)]
                added_at_secs: Option<u64>,
                #[serde(default)]
                raw_vulns: Option<Vec<serde_json::Value>>,
            }
            let slim: Slim = serde_json::from_value(item.clone())
                .map_err(|e| CorpusImportError::Parse(e.to_string()))?;
            entries.push(entry_from_cache_info_like(
                slim.key,
                slim.ttl_secs,
                slim.added_at_secs,
                slim.raw_vulns,
            )?);
        }
        return Ok(CorpusDocument {
            schema_version: CORPUS_SCHEMA_VERSION,
            entries,
        });
    }

    Err(CorpusImportError::Parse(
        "expected corpus object with schema_version/entries or a JSON array"
            .into(),
    ))
}

/// Convert parsed corpus entries into put-ready records.
pub fn importable_entries(
    doc: &CorpusDocument,
) -> Result<Vec<ImportableEntry>, CorpusImportError> {
    let mut out = Vec::with_capacity(doc.entries.len());
    for entry in &doc.entries {
        let (package, provider_id) = parse_pkg_cache_key(&entry.key)?;
        debug_assert_eq!(
            pkg_cache_key(&package, &provider_id),
            entry.key,
            "key round-trip"
        );
        out.push(ImportableEntry {
            package,
            provider_id,
            raw_vulns: entry.raw_vulns.clone(),
            ttl_secs: entry.ttl_secs.max(1),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_envelope_v1() {
        let body = json!({
            "schema_version": 1,
            "entries": [{
                "key": "requests::2.0.0::osv",
                "ttl_secs": 100,
                "raw_vulns": [{"id": "CVE-2024-1"}]
            }]
        });
        let doc = parse_corpus_json(body.to_string().as_bytes()).unwrap();
        assert_eq!(doc.entries.len(), 1);
        let ready = importable_entries(&doc).unwrap();
        assert_eq!(ready[0].package.name, "requests");
        assert_eq!(ready[0].package.version, "2.0.0");
        assert_eq!(ready[0].provider_id, "osv");
        assert_eq!(ready[0].ttl_secs, 100);
    }

    #[test]
    fn parse_db_show_array_requires_raw_vulns() {
        let body = json!([{
            "key": "foo::1.0::osv",
            "ttl_secs": 50,
            "added_at_secs": 10,
            "cve_count": 0,
            "cve_ids": []
        }]);
        let err = parse_corpus_json(body.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, CorpusImportError::MissingRawVulns(_)));
    }

    #[test]
    fn parse_db_show_array_with_raw_vulns() {
        let body = json!([{
            "key": "group:artifact::1.2.3::osv",
            "ttl_secs": 50,
            "added_at_secs": 10,
            "cve_count": 1,
            "cve_ids": ["CVE-1"],
            "raw_vulns": [{"id": "CVE-1"}]
        }]);
        let doc = parse_corpus_json(body.to_string().as_bytes()).unwrap();
        let ready = importable_entries(&doc).unwrap();
        assert_eq!(ready[0].package.name, "group:artifact");
        assert_eq!(ready[0].package.version, "1.2.3");
    }

    #[test]
    fn reject_unsupported_schema() {
        let body = json!({"schema_version": 99, "entries": []});
        let err = parse_corpus_json(body.to_string().as_bytes()).unwrap_err();
        assert_eq!(
            err,
            CorpusImportError::UnsupportedSchema {
                found: 99,
                supported: CORPUS_SCHEMA_VERSION
            }
        );
    }

    #[test]
    fn reject_bad_key() {
        let body = json!({
            "schema_version": 1,
            "entries": [{
                "key": "not-a-key",
                "ttl_secs": 1,
                "raw_vulns": []
            }]
        });
        let err = parse_corpus_json(body.to_string().as_bytes()).unwrap_err();
        assert!(matches!(err, CorpusImportError::InvalidKey(_)));
    }

    #[test]
    fn sha256_verify_ok_and_mismatch() {
        let bytes = b"hello corpus";
        let digest = sha256_hex(bytes);
        verify_sha256(bytes, &digest).unwrap();
        let err = verify_sha256(bytes, &"0".repeat(64)).unwrap_err();
        assert!(matches!(err, CorpusImportError::Sha256Mismatch { .. }));
        assert!(verify_sha256(bytes, "abc").is_err());
    }

    #[test]
    fn parse_pkg_cache_key_round_trip() {
        let pkg = Package {
            name: "a::b".into(),
            version: "9".into(),
            ecosystem: None,
        };
        let key = pkg_cache_key(&pkg, "osv");
        let (parsed, provider) = parse_pkg_cache_key(&key).unwrap();
        assert_eq!(parsed.name, "a::b");
        assert_eq!(parsed.version, "9");
        assert_eq!(provider, "osv");
    }
}
