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
const IGNORE_FILE_MODE: u32 = 0o640;

/// Directory mode for ignore parent dirs (SEC-014).
const IGNORE_DIR_MODE: u32 = 0o755;

/// Stored row for a CVE marked as false positive (FR-015).
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct FpEntry {
    pub comment: String,
    pub timestamp_secs: u64,
    pub user: Option<String>,
    pub host: Option<String>,
    pub project_id: Option<String>,
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
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let entry = FpEntry {
            comment: comment.to_string(),
            timestamp_secs: now_secs,
            user: std::env::var("USER").ok(),
            host: std::env::var("HOSTNAME").ok(),
            project_id: project_id.map(String::from),
        };
        self.with_locked_mutation(|map| {
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
        let guard = self.state.read().map_err(|_| {
            DatabaseError::Other("ignore lock poisoned".into())
        })?;
        let set: HashSet<String> = guard
            .iter()
            .filter(|(_, entry)| match (&entry.project_id, project_id) {
                (None, _) => true,
                (Some(pid), Some(scan_pid)) => pid == scan_pid,
                (Some(_), None) => false,
            })
            .map(|(k, _)| k.clone())
            .collect();
        Ok(set)
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
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: FpEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
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
