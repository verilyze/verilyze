// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Portable JSON false-positive (ignore) database (FR-015).
//! Shared by RedB-cache and mem-cache builds so Docker can mount the same file.
//!
//! Concurrent writers (separate processes) take an advisory lock and reload
//! from disk before mutating so marks are not lost. Last-writer-wins still
//! applies to the same CVE id marked by two processes at once.

use crate::{DatabaseError, IgnoreDb, reject_world_writable_db};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Schema version for on-disk JSON ignore files.
pub const IGNORE_FILE_SCHEMA_VERSION: u32 = 1;

/// Default ignore filename for new installs (OP-002, OP-003).
pub const DEFAULT_IGNORE_FILE_NAME: &str = "vlz-ignore.json";

/// Legacy RedB ignore filename (migration source for the default JSON name).
pub const LEGACY_IGNORE_REDB_FILE_NAME: &str = "vlz-ignore.redb";

/// File mode for ignore JSON (SEC-014).
#[cfg(unix)]
const IGNORE_FILE_MODE: u32 = 0o640;

/// Directory mode for ignore parent dirs (SEC-014).
#[cfg(unix)]
const IGNORE_DIR_MODE: u32 = 0o755;

/// Stored row for a CVE marked as false positive (FR-015).
/// Optional VEX triage fields (`justification`, `status`, `detail`) are
/// schema-compatible with v1: absent on disk deserializes as `None`.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct FpEntry {
    pub comment: String,
    pub timestamp_secs: u64,
    pub user: Option<String>,
    pub host: Option<String>,
    pub project_id: Option<String>,
    /// CISA VEX justification when status is not_affected (FR-044).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub justification: Option<String>,
    /// VEX status override (typically `not_affected`) when marked FP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Free-form impact / triage detail for VEX statements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Unix timestamp when this suppression expires (W3-2). Absent = never.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_secs: Option<u64>,
    /// Manifest path prefixes this mark applies to (W3-2). Empty / absent =
    /// all paths for the project scope.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

impl FpEntry {
    /// Build an FP entry for mark/re-mark.
    ///
    /// When `justification`, `status`, or `detail` is `None`, prior values from
    /// `existing` are preserved so a later `fp mark` without VEX flags does not
    /// erase triage metadata (FR-044). `project_id` and `comment` always take
    /// the new values (including clearing project scope when `project_id` is
    /// `None`).
    pub fn from_mark(
        existing: Option<&Self>,
        fields: FpMarkFields<'_>,
        meta: FpMarkMeta,
    ) -> Self {
        Self {
            comment: fields.comment.to_string(),
            timestamp_secs: meta.timestamp_secs,
            user: meta.user,
            host: meta.host,
            project_id: fields.project_id.map(String::from),
            justification: fields
                .justification
                .map(String::from)
                .or_else(|| existing.and_then(|e| e.justification.clone())),
            status: fields
                .status
                .map(String::from)
                .or_else(|| existing.and_then(|e| e.status.clone())),
            detail: fields
                .detail
                .map(String::from)
                .or_else(|| existing.and_then(|e| e.detail.clone())),
            expires_at_secs: fields
                .expires_at_secs
                .or_else(|| existing.and_then(|e| e.expires_at_secs)),
            paths: fields
                .paths
                .map(|p| p.iter().map(|s| (*s).to_string()).collect())
                .unwrap_or_else(|| {
                    existing.map(|e| e.paths.clone()).unwrap_or_default()
                }),
        }
    }
}

/// True when the FP entry is still active at `now_secs` (W3-2).
pub fn fp_entry_is_active(entry: &FpEntry, now_secs: u64) -> bool {
    match entry.expires_at_secs {
        None => true,
        Some(exp) => exp > now_secs,
    }
}

/// True when the FP entry applies to the given finding manifest paths (W3-2).
///
/// Empty `entry.paths` means all paths. Otherwise the mark applies when any
/// finding path equals or is under any configured path prefix (segment
/// boundary). A scope with no directory separator matches the finding
/// basename only (e.g. `--path composer.lock`). Empty scope strings are
/// ignored.
pub fn fp_entry_applies_to_paths(
    entry: &FpEntry,
    manifest_paths: &[impl AsRef<str>],
) -> bool {
    let scopes: Vec<&str> = entry
        .paths
        .iter()
        .map(String::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    if scopes.is_empty() {
        // No non-empty scopes: treat like an unscoped mark when `paths` was
        // empty; empty-string-only scopes never match (fail closed).
        return entry.paths.is_empty();
    }
    if manifest_paths.is_empty() {
        return false;
    }
    for finding_path in manifest_paths {
        let finding = finding_path.as_ref();
        for scoped in &scopes {
            if path_scope_matches(finding, scoped) {
                return true;
            }
        }
    }
    false
}

/// Path-prefix (with `/` or `\` boundary) or basename-only scope match.
fn path_scope_matches(finding: &str, scoped: &str) -> bool {
    let finding = finding.replace('\\', "/");
    let scoped = scoped.replace('\\', "/");
    let scoped = scoped.trim_end_matches('/');
    if scoped.is_empty() {
        return false;
    }
    if finding == scoped {
        return true;
    }
    if let Some(rest) = finding.strip_prefix(scoped)
        && rest.starts_with('/')
    {
        return true;
    }
    // Basename-only scopes (no directory separator).
    if !scoped.contains('/') {
        return std::path::Path::new(finding.as_str())
            .file_name()
            .and_then(|n| n.to_str())
            == Some(scoped);
    }
    false
}

/// Like [`fp_entry_applies_to_paths`], also matching repo-relative scopes
/// against absolute manifests under `scan_root` (W3-2).
///
/// Discovery stores canonical absolute paths; CLI `--path` is typically
/// relative to the scan root. Each manifest is compared as-is and, when it
/// lies under `scan_root`, as the stripped relative form.
pub fn fp_entry_applies_to_paths_under_root(
    entry: &FpEntry,
    manifest_paths: &[impl AsRef<std::path::Path>],
    scan_root: Option<&std::path::Path>,
) -> bool {
    let mut candidates: Vec<String> = Vec::new();
    for path in manifest_paths {
        let path = path.as_ref();
        candidates.push(path.to_string_lossy().into_owned());
        if let Some(root) = scan_root
            && let Ok(rel) = path.strip_prefix(root)
        {
            let rel_s = rel.to_string_lossy();
            if !rel_s.is_empty() {
                candidates.push(rel_s.into_owned());
            }
        }
    }
    fp_entry_applies_to_paths(entry, &candidates)
}

/// Caller-supplied FP mark fields (comment / project / VEX triage / W3-2).
#[derive(Debug, Clone, Copy)]
pub struct FpMarkFields<'a> {
    pub comment: &'a str,
    pub project_id: Option<&'a str>,
    pub justification: Option<&'a str>,
    pub status: Option<&'a str>,
    pub detail: Option<&'a str>,
    pub expires_at_secs: Option<u64>,
    pub paths: Option<&'a [&'a str]>,
}

/// Audit metadata written on each FP mark.
#[derive(Debug, Clone)]
pub struct FpMarkMeta {
    pub timestamp_secs: u64,
    pub user: Option<String>,
    pub host: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IgnoreFileDocument {
    version: u32,
    entries: HashMap<String, FpEntry>,
}

impl Default for IgnoreFileDocument {
    fn default() -> Self {
        Self {
            version: IGNORE_FILE_SCHEMA_VERSION,
            entries: HashMap::new(),
        }
    }
}

/// File-backed `IgnoreDb` using versioned JSON and atomic rename writes.
pub struct FileIgnoreDb {
    path: PathBuf,
    state: RwLock<HashMap<String, FpEntry>>,
}

impl std::fmt::Debug for FileIgnoreDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileIgnoreDb")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileIgnoreDb {
    /// Open or create the ignore DB at `path`.
    pub fn with_path(path: PathBuf) -> Result<Self, DatabaseError> {
        ensure_parent_dir(&path)?;
        reject_world_writable_db(&path)?;
        let entries = if path.exists() {
            load_document(&path)?.entries
        } else {
            HashMap::new()
        };
        Ok(Self {
            path,
            state: RwLock::new(entries),
        })
    }

    /// Create a new ignore file exclusively (`O_EXCL`). Fails if `path` exists.
    ///
    /// Used by legacy RedB → JSON migration so an existing JSON is never
    /// overwritten (TOCTOU-safe vs a plain exists-check).
    pub fn create_new(path: PathBuf) -> Result<Self, DatabaseError> {
        ensure_parent_dir(&path)?;
        write_document_create_new(&path, &IgnoreFileDocument::default())?;
        Ok(Self {
            path,
            state: RwLock::new(HashMap::new()),
        })
    }

    /// Path to the JSON ignore file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Replace in-memory state and persist (used by migration helpers).
    pub fn replace_entries(
        &self,
        entries: HashMap<String, FpEntry>,
    ) -> Result<(), DatabaseError> {
        self.with_locked_mutation(|map| {
            *map = entries;
            Ok(())
        })
    }

    fn with_locked_mutation<F>(&self, f: F) -> Result<(), DatabaseError>
    where
        F: FnOnce(&mut HashMap<String, FpEntry>) -> Result<(), DatabaseError>,
    {
        let _lock = acquire_ignore_lock(&self.path)?;
        let mut entries = if self.path.exists() {
            load_document(&self.path)?.entries
        } else {
            HashMap::new()
        };
        f(&mut entries)?;
        let doc = IgnoreFileDocument {
            version: IGNORE_FILE_SCHEMA_VERSION,
            entries: entries.clone(),
        };
        write_document_atomic(&self.path, &doc)?;
        let mut guard = self.state.write().map_err(|_| {
            DatabaseError::Other("ignore lock poisoned".into())
        })?;
        *guard = entries;
        Ok(())
    }
}

impl IgnoreDb for FileIgnoreDb {
    fn mark(
        &self,
        cve_id: &str,
        comment: &str,
        project_id: Option<&str>,
    ) -> Result<(), DatabaseError> {
        self.mark_with_details(
            cve_id, comment, project_id, None, None, None, None, None,
        )
    }

    fn mark_with_details(
        &self,
        cve_id: &str,
        comment: &str,
        project_id: Option<&str>,
        justification: Option<&str>,
        status: Option<&str>,
        detail: Option<&str>,
        expires_at_secs: Option<u64>,
        paths: Option<&[&str]>,
    ) -> Result<(), DatabaseError> {
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        self.with_locked_mutation(|map| {
            let existing = map.get(cve_id).cloned();
            let entry = FpEntry::from_mark(
                existing.as_ref(),
                FpMarkFields {
                    comment,
                    project_id,
                    justification,
                    status,
                    detail,
                    expires_at_secs,
                    paths,
                },
                FpMarkMeta {
                    timestamp_secs: now_secs,
                    user: std::env::var("USER").ok(),
                    host: std::env::var("HOSTNAME").ok(),
                },
            );
            map.insert(cve_id.to_string(), entry);
            Ok(())
        })
    }

    fn unmark(&self, cve_id: &str) -> Result<(), DatabaseError> {
        self.with_locked_mutation(|map| {
            map.remove(cve_id);
            Ok(())
        })
    }

    fn is_marked(&self, cve_id: &str) -> Result<bool, DatabaseError> {
        let guard = self.state.read().map_err(|_| {
            DatabaseError::Other("ignore lock poisoned".into())
        })?;
        Ok(guard.contains_key(cve_id))
    }

    fn marked_ids(
        &self,
        project_id: Option<&str>,
    ) -> Result<HashSet<String>, DatabaseError> {
        Ok(self.marked_entries(project_id)?.into_keys().collect())
    }

    fn marked_entries(
        &self,
        project_id: Option<&str>,
    ) -> Result<HashMap<String, FpEntry>, DatabaseError> {
        let guard = self.state.read().map_err(|_| {
            DatabaseError::Other("ignore lock poisoned".into())
        })?;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let map: HashMap<String, FpEntry> = guard
            .iter()
            .filter(|(_, entry)| match (&entry.project_id, project_id) {
                (None, _) => true,
                (Some(pid), Some(scan_pid)) => pid == scan_pid,
                (Some(_), None) => false,
            })
            .filter(|(_, entry)| fp_entry_is_active(entry, now_secs))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Ok(map)
    }
}

fn load_document(path: &Path) -> Result<IgnoreFileDocument, DatabaseError> {
    let bytes = fs::read(path).map_err(DatabaseError::Io)?;
    if bytes.is_empty() {
        return Ok(IgnoreFileDocument::default());
    }
    let doc: IgnoreFileDocument =
        serde_json::from_slice(&bytes).map_err(|e| {
            DatabaseError::Other(format!(
                "Invalid ignore database JSON at {}: {e}. \
                 Expected versioned FileIgnoreDb format (not legacy RedB).",
                path.display()
            ))
        })?;
    if doc.version != IGNORE_FILE_SCHEMA_VERSION {
        return Err(DatabaseError::Other(format!(
            "Unsupported ignore database schema version {} at {} (expected {})",
            doc.version,
            path.display(),
            IGNORE_FILE_SCHEMA_VERSION
        )));
    }
    Ok(doc)
}

fn ensure_parent_dir(path: &Path) -> Result<(), DatabaseError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() || parent.exists() {
        return Ok(());
    }
    create_dir_all_mode(parent)
}

fn create_dir_all_mode(dir: &Path) -> Result<(), DatabaseError> {
    if dir.exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        create_dir_all_mode(parent)?;
    }
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(DatabaseError::Io(e)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(IGNORE_DIR_MODE))
            .map_err(DatabaseError::Io)?;
    }
    Ok(())
}

fn lock_path_for(json_path: &Path) -> PathBuf {
    let parent = json_path.parent().unwrap_or_else(|| Path::new("."));
    let name = json_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(DEFAULT_IGNORE_FILE_NAME);
    parent.join(format!(".{name}.lock"))
}

struct IgnorePathLock {
    _file: File,
}

fn acquire_ignore_lock(
    json_path: &Path,
) -> Result<IgnorePathLock, DatabaseError> {
    ensure_parent_dir(json_path)?;
    let lock_path = lock_path_for(json_path);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(DatabaseError::Io)?;
    #[cfg(unix)]
    {
        use rustix::fs::{FlockOperation, flock};
        flock(&file, FlockOperation::LockExclusive).map_err(|e| {
            DatabaseError::Io(std::io::Error::from_raw_os_error(
                e.raw_os_error(),
            ))
        })?;
    }
    Ok(IgnorePathLock { _file: file })
}

fn set_file_mode_640(path: &Path) -> Result<(), DatabaseError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(IGNORE_FILE_MODE),
        )
        .map_err(DatabaseError::Io)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn write_document_atomic(
    path: &Path,
    doc: &IgnoreFileDocument,
) -> Result<(), DatabaseError> {
    reject_world_writable_db(path)?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_name = format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(DEFAULT_IGNORE_FILE_NAME),
        std::process::id()
    );
    let tmp_path = parent.join(tmp_name);
    let json = serde_json::to_vec_pretty(doc).map_err(DatabaseError::Serde)?;
    {
        let mut file = File::create(&tmp_path).map_err(DatabaseError::Io)?;
        file.write_all(&json).map_err(DatabaseError::Io)?;
        file.sync_all().map_err(DatabaseError::Io)?;
    }
    set_file_mode_640(&tmp_path)?;
    fs::rename(&tmp_path, path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        DatabaseError::Io(e)
    })?;
    Ok(())
}

fn write_document_create_new(
    path: &Path,
    doc: &IgnoreFileDocument,
) -> Result<(), DatabaseError> {
    reject_world_writable_db(path)?;
    let json = serde_json::to_vec_pretty(doc).map_err(DatabaseError::Serde)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(DatabaseError::Io)?;
    file.write_all(&json).map_err(DatabaseError::Io)?;
    file.sync_all().map_err(DatabaseError::Io)?;
    drop(file);
    set_file_mode_640(path)?;
    Ok(())
}

/// Derive the legacy `.redb` path for a JSON ignore path (same stem, `.redb`
/// extension). Example: `vlz-ignore.json` → `vlz-ignore.redb`,
/// `fps.json` → `fps.redb`.
pub fn legacy_redb_path_for_json(json_path: &Path) -> PathBuf {
    json_path.with_extension("redb")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::thread;

    fn temp_ignore_path(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(format!("vlz_ignore_{name}.json"));
        (dir, path)
    }

    #[test]
    fn mark_unmark_roundtrip_persists() {
        let (_dir, path) = temp_ignore_path("roundtrip");
        {
            let db = FileIgnoreDb::with_path(path.clone()).unwrap();
            db.mark("CVE-A", "comment", None).unwrap();
            assert!(db.is_marked("CVE-A").unwrap());
        }
        let db2 = FileIgnoreDb::with_path(path).unwrap();
        assert!(db2.is_marked("CVE-A").unwrap());
        db2.unmark("CVE-A").unwrap();
        assert!(!db2.is_marked("CVE-A").unwrap());
    }

    #[test]
    fn marked_ids_project_scoping_fr015() {
        let (_dir, path) = temp_ignore_path("scope");
        let db = FileIgnoreDb::with_path(path).unwrap();
        db.mark("CVE-GLOBAL", "g", None).unwrap();
        db.mark("CVE-P1", "p", Some("proj1")).unwrap();
        db.mark("CVE-P2", "p", Some("proj2")).unwrap();
        let global = db.marked_ids(None).unwrap();
        assert_eq!(global.len(), 1);
        assert!(global.contains("CVE-GLOBAL"));
        let p1 = db.marked_ids(Some("proj1")).unwrap();
        assert_eq!(p1.len(), 2);
        assert!(p1.contains("CVE-GLOBAL"));
        assert!(p1.contains("CVE-P1"));
    }

    #[test]
    fn corrupt_json_returns_clear_error() {
        let (_dir, path) = temp_ignore_path("corrupt");
        {
            let mut f = fs::File::create(&path).unwrap();
            write!(f, "not-json").unwrap();
        }
        let err = FileIgnoreDb::with_path(path).unwrap_err();
        assert!(err.to_string().contains("Invalid ignore database JSON"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_world_writable_existing_file() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_ignore_path("world");
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        let err = FileIgnoreDb::with_path(path).unwrap_err();
        assert!(err.to_string().contains("world-writable"));
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("ignore.json");
        let db = FileIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-X", "t", None).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn unsupported_schema_version_errors() {
        let (_dir, path) = temp_ignore_path("ver");
        fs::write(&path, r#"{"version":99,"entries":{}}"#).unwrap();
        let err = FileIgnoreDb::with_path(path).unwrap_err();
        assert!(err.to_string().contains("Unsupported ignore database"));
    }

    #[test]
    fn legacy_redb_path_for_json_uses_stem() {
        let p = PathBuf::from("/data/verilyze/vlz-ignore.json");
        assert_eq!(
            legacy_redb_path_for_json(&p),
            PathBuf::from("/data/verilyze/vlz-ignore.redb")
        );
        let custom = PathBuf::from("/repo/fps.json");
        assert_eq!(
            legacy_redb_path_for_json(&custom),
            PathBuf::from("/repo/fps.redb")
        );
    }

    #[test]
    fn fp_entry_serde_roundtrip() {
        let e = FpEntry {
            comment: "fp".into(),
            timestamp_secs: 1,
            user: Some("u".into()),
            host: None,
            project_id: Some("p".into()),
            justification: None,
            status: None,
            detail: None,
            expires_at_secs: None,
            paths: Vec::new(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: FpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn fp_entry_legacy_json_deserializes_without_vex_fields() {
        let json = r#"{
            "comment": "legacy",
            "timestamp_secs": 42,
            "user": null,
            "host": null,
            "project_id": null
        }"#;
        let e: FpEntry = serde_json::from_str(json).unwrap();
        assert_eq!(e.comment, "legacy");
        assert_eq!(e.timestamp_secs, 42);
        assert!(e.justification.is_none());
        assert!(e.status.is_none());
        assert!(e.detail.is_none());
    }

    #[test]
    fn fp_entry_vex_fields_roundtrip_and_omit_when_none() {
        let e = FpEntry {
            comment: "triaged".into(),
            timestamp_secs: 7,
            user: None,
            host: None,
            project_id: None,
            justification: Some("vulnerable_code_not_in_execute_path".into()),
            status: Some("not_affected".into()),
            detail: Some("not imported".into()),
            expires_at_secs: None,
            paths: Vec::new(),
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("vulnerable_code_not_in_execute_path"));
        assert!(json.contains("not_affected"));
        assert!(json.contains("not imported"));
        let back: FpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);

        let minimal = FpEntry {
            comment: "c".into(),
            timestamp_secs: 1,
            user: None,
            host: None,
            project_id: None,
            justification: None,
            status: None,
            detail: None,
            expires_at_secs: None,
            paths: Vec::new(),
        };
        let minimal_json = serde_json::to_string(&minimal).unwrap();
        assert!(!minimal_json.contains("justification"));
        assert!(!minimal_json.contains("\"status\""));
        assert!(!minimal_json.contains("detail"));
    }

    #[test]
    fn fp_entry_is_active_respects_expires_at() {
        let active = FpEntry {
            comment: "c".into(),
            timestamp_secs: 1,
            user: None,
            host: None,
            project_id: None,
            justification: None,
            status: None,
            detail: None,
            expires_at_secs: Some(200),
            paths: Vec::new(),
        };
        assert!(fp_entry_is_active(&active, 100));
        assert!(!fp_entry_is_active(&active, 200));
        assert!(!fp_entry_is_active(&active, 201));
        let never = FpEntry {
            expires_at_secs: None,
            ..active.clone()
        };
        assert!(fp_entry_is_active(&never, u64::MAX));
    }

    #[test]
    fn fp_entry_applies_to_paths_prefix_and_empty() {
        let all_paths = FpEntry {
            comment: "c".into(),
            timestamp_secs: 1,
            user: None,
            host: None,
            project_id: None,
            justification: None,
            status: None,
            detail: None,
            expires_at_secs: None,
            paths: Vec::new(),
        };
        assert!(fp_entry_applies_to_paths(&all_paths, &["any/path"]));

        let scoped = FpEntry {
            paths: vec!["apps/api/composer.lock".into()],
            ..all_paths
        };
        assert!(fp_entry_applies_to_paths(
            &scoped,
            &["apps/api/composer.lock"]
        ));
        assert!(!fp_entry_applies_to_paths(
            &scoped,
            &["apps/web/composer.lock"]
        ));
    }

    #[test]
    fn fp_entry_applies_to_paths_rejects_suffix_and_empty_scope() {
        let base = FpEntry {
            comment: "c".into(),
            timestamp_secs: 1,
            user: None,
            host: None,
            project_id: None,
            justification: None,
            status: None,
            detail: None,
            expires_at_secs: None,
            paths: vec!["pkg/Cargo.toml".into()],
        };
        assert!(fp_entry_applies_to_paths(&base, &["pkg/Cargo.toml"]));
        assert!(!fp_entry_applies_to_paths(
            &base,
            &["/repo/other-pkg/Cargo.toml"]
        ));
        assert!(!fp_entry_applies_to_paths(
            &base,
            &["apps/web-api/composer.lock"]
        ));

        let api_lock = FpEntry {
            paths: vec!["api/composer.lock".into()],
            ..base.clone()
        };
        assert!(fp_entry_applies_to_paths(&api_lock, &["api/composer.lock"]));
        assert!(!fp_entry_applies_to_paths(
            &api_lock,
            &["apps/web-api/composer.lock"]
        ));
        assert!(!fp_entry_applies_to_paths(
            &api_lock,
            &["apps/api/composer.lock"]
        ));
        assert!(fp_entry_applies_to_paths(
            &FpEntry {
                paths: vec!["apps/api".into()],
                ..base.clone()
            },
            &["apps/api/composer.lock"]
        ));

        let basename = FpEntry {
            paths: vec!["composer.lock".into()],
            ..base.clone()
        };
        assert!(fp_entry_applies_to_paths(
            &basename,
            &["apps/api/composer.lock"]
        ));

        let empty_scope = FpEntry {
            paths: vec!["".into()],
            ..base
        };
        assert!(!fp_entry_applies_to_paths(
            &empty_scope,
            &["/abs/manifest.lock"]
        ));
    }

    #[test]
    fn fp_entry_applies_to_paths_under_root_relative_scope() {
        use std::path::Path;
        let root = Path::new("/workspace");
        let scoped = FpEntry {
            comment: "c".into(),
            timestamp_secs: 1,
            user: None,
            host: None,
            project_id: None,
            justification: None,
            status: None,
            detail: None,
            expires_at_secs: None,
            paths: vec!["apps/api/composer.lock".into()],
        };
        assert!(fp_entry_applies_to_paths_under_root(
            &scoped,
            &[Path::new("/workspace/apps/api/composer.lock")],
            Some(root),
        ));
        assert!(fp_entry_applies_to_paths_under_root(
            &FpEntry {
                paths: vec!["apps/api".into()],
                ..scoped.clone()
            },
            &[Path::new("/workspace/apps/api/composer.lock")],
            Some(root),
        ));
        assert!(!fp_entry_applies_to_paths_under_root(
            &scoped,
            &[Path::new("/workspace/apps/web/composer.lock")],
            Some(root),
        ));
        // Without root stripping, absolute finding does not match relative scope.
        assert!(!fp_entry_applies_to_paths(
            &scoped,
            &["/workspace/apps/api/composer.lock"]
        ));
        // other-pkg must not match scope pkg/Cargo.toml even under a root.
        assert!(!fp_entry_applies_to_paths_under_root(
            &FpEntry {
                paths: vec!["pkg/Cargo.toml".into()],
                ..scoped
            },
            &[Path::new("/workspace/other-pkg/Cargo.toml")],
            Some(root),
        ));
    }

    #[test]
    fn marked_entries_skips_expired_suppressions_w3_2() {
        let (_dir, path) = temp_ignore_path("expiry");
        let db = FileIgnoreDb::with_path(path).unwrap();
        let past = 1_u64;
        db.mark_with_details(
            "CVE-EXPIRED",
            "old",
            None,
            None,
            None,
            None,
            Some(past),
            None,
        )
        .unwrap();
        db.mark_with_details(
            "CVE-LIVE",
            "live",
            None,
            None,
            None,
            None,
            Some(u64::MAX),
            None,
        )
        .unwrap();
        let entries = db.marked_entries(None).unwrap();
        assert!(!entries.contains_key("CVE-EXPIRED"));
        assert!(entries.contains_key("CVE-LIVE"));
    }

    #[test]
    fn mark_with_details_persists_expiry_and_paths_w3_2() {
        let (_dir, path) = temp_ignore_path("paths");
        let db = FileIgnoreDb::with_path(path).unwrap();
        db.mark_with_details(
            "CVE-PATH",
            "scoped",
            None,
            None,
            None,
            None,
            Some(9_999_999_999),
            Some(&["apps/api/composer.lock"]),
        )
        .unwrap();
        let entry = db
            .marked_entries(None)
            .unwrap()
            .remove("CVE-PATH")
            .expect("entry");
        assert_eq!(entry.expires_at_secs, Some(9_999_999_999));
        assert_eq!(entry.paths, vec!["apps/api/composer.lock".to_string()]);
    }

    #[test]
    fn mark_with_details_persists_justification_and_status() {
        let (_dir, path) = temp_ignore_path("vex_details");
        {
            let db = FileIgnoreDb::with_path(path.clone()).unwrap();
            db.mark_with_details(
                "CVE-VEX-1",
                "triaged",
                Some("proj"),
                Some("vulnerable_code_not_present"),
                Some("not_affected"),
                Some("library unused"),
                None,
                None,
            )
            .unwrap();
        }
        let db2 = FileIgnoreDb::with_path(path).unwrap();
        let entries = db2.marked_entries(Some("proj")).unwrap();
        let entry = entries.get("CVE-VEX-1").expect("entry present");
        assert_eq!(
            entry.justification.as_deref(),
            Some("vulnerable_code_not_present")
        );
        assert_eq!(entry.status.as_deref(), Some("not_affected"));
        assert_eq!(entry.detail.as_deref(), Some("library unused"));
        assert_eq!(entry.project_id.as_deref(), Some("proj"));
    }

    #[test]
    fn re_mark_without_vex_flags_preserves_justification() {
        let (_dir, path) = temp_ignore_path("vex_preserve");
        let db = FileIgnoreDb::with_path(path.clone()).unwrap();
        db.mark_with_details(
            "CVE-KEEP",
            "first",
            None,
            Some("vulnerable_code_not_present"),
            Some("not_affected"),
            Some("detail"),
            None,
            None,
        )
        .unwrap();
        db.mark("CVE-KEEP", "updated comment", None).unwrap();
        let entry = db
            .marked_entries(None)
            .unwrap()
            .remove("CVE-KEEP")
            .expect("entry");
        assert_eq!(entry.comment, "updated comment");
        assert_eq!(
            entry.justification.as_deref(),
            Some("vulnerable_code_not_present")
        );
        assert_eq!(entry.status.as_deref(), Some("not_affected"));
        assert_eq!(entry.detail.as_deref(), Some("detail"));
    }

    #[test]
    fn replace_entries_persists() {
        let (_dir, path) = temp_ignore_path("replace");
        let db = FileIgnoreDb::with_path(path.clone()).unwrap();
        let mut map = HashMap::new();
        map.insert(
            "CVE-Z".into(),
            FpEntry {
                comment: "z".into(),
                timestamp_secs: 9,
                user: None,
                host: None,
                project_id: None,
                justification: None,
                status: None,
                detail: None,
                expires_at_secs: None,
                paths: Vec::new(),
            },
        );
        db.replace_entries(map).unwrap();
        let db2 = FileIgnoreDb::with_path(path).unwrap();
        assert!(db2.is_marked("CVE-Z").unwrap());
    }

    #[test]
    fn create_new_fails_when_file_exists() {
        let (_dir, path) = temp_ignore_path("excl");
        FileIgnoreDb::create_new(path.clone()).unwrap();
        let err = FileIgnoreDb::create_new(path).unwrap_err();
        match err {
            DatabaseError::Io(e) => {
                assert_eq!(e.kind(), ErrorKind::AlreadyExists);
            }
            other => panic!("expected AlreadyExists, got {other}"),
        }
    }

    #[test]
    fn concurrent_marks_preserve_both_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("concurrent.json");
        FileIgnoreDb::create_new(path.clone()).unwrap();
        let p1 = path.clone();
        let p2 = path.clone();
        let t1 = thread::spawn(move || {
            let db = FileIgnoreDb::with_path(p1).unwrap();
            for _ in 0..20 {
                db.mark("CVE-1", "a", None).unwrap();
            }
        });
        let t2 = thread::spawn(move || {
            let db = FileIgnoreDb::with_path(p2).unwrap();
            for _ in 0..20 {
                db.mark("CVE-2", "b", None).unwrap();
            }
        });
        t1.join().expect("t1");
        t2.join().expect("t2");
        let db = FileIgnoreDb::with_path(path).unwrap();
        assert!(db.is_marked("CVE-1").unwrap());
        assert!(db.is_marked("CVE-2").unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn written_file_mode_is_not_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path) = temp_ignore_path("mode");
        let db = FileIgnoreDb::with_path(path.clone()).unwrap();
        db.mark("CVE-M", "m", None).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode & 0o022,
            0,
            "must not be group/world writable: {mode:o}"
        );
    }
}
