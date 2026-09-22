// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use vlz_manifest_parser::{ParserError, lock_declarations_from_parsed};

use crate::finder::is_requirements_manifest_name;
use crate::lock_names::{
    filter_lock_paths_by_allowlist, is_pylock_variant, manifest_is_lock_file,
    verify_lock_allowlist_for_dir,
};
use crate::parser::parse_lock_file_with_declarations;

/// Basenames searched adjacent to manifests (Appendix A). `pylock.*.toml` via [`collect_pylock_variants`].
const LOCK_CANDIDATE_BASENAMES: &[&str] = &[
    "pylock.toml",
    "poetry.lock",
    "uv.lock",
    "pdm.lock",
    "Pipfile.lock",
];

/// Find all applicable lock file paths for `manifest_path`.
///
/// When `scan_root` is `Some`, also walks parent directories up to (and
/// including) `scan_root` and returns the locks from the first directory
/// (adjacent or parent) that contains any. Locks are unioned within a single
/// directory and never merged across directories. When `scan_root` is `None`,
/// only the manifest's own directory is searched (backward-compatible).
pub fn find_lock_files(
    manifest_path: &Path,
    lock_file_allowlist: &[String],
    scan_root: Option<&Path>,
) -> Vec<PathBuf> {
    let dir = match manifest_path.parent() {
        Some(d) => d,
        None => return Vec::new(),
    };
    let name = match manifest_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return Vec::new(),
    };

    // Pipfile is paired only with an adjacent Pipfile.lock (no parent walk).
    if name == "Pipfile" {
        let pipfile_lock = dir.join("Pipfile.lock");
        if pipfile_lock.is_file() {
            return filter_lock_paths_by_allowlist(
                &[pipfile_lock],
                lock_file_allowlist,
            );
        }
        return Vec::new();
    }

    let use_candidates =
        matches!(name, "pyproject.toml" | "setup.py" | "setup.cfg")
            || is_requirements_manifest_name(name);
    if !use_candidates {
        return Vec::new();
    }

    // Adjacent directory first.
    let adjacent = collect_dir_locks(dir, lock_file_allowlist);
    if !adjacent.is_empty() {
        return adjacent;
    }

    // Parent walk up to scan_root (when provided).
    if let Some(root) = scan_root {
        let mut parent = dir.parent().map(Path::to_path_buf);
        while let Some(p) = parent {
            // Stop once we have climbed above the scan root.
            if !p.starts_with(root) {
                break;
            }
            let locks = collect_dir_locks(&p, lock_file_allowlist);
            if !locks.is_empty() {
                return locks;
            }
            if p == root {
                break;
            }
            parent = p.parent().map(Path::to_path_buf);
        }
    }

    Vec::new()
}

/// Collect and allowlist-filter lock file paths in a single directory.
fn collect_dir_locks(
    dir: &Path,
    lock_file_allowlist: &[String],
) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for candidate in LOCK_CANDIDATE_BASENAMES {
        let lock_path = dir.join(candidate);
        if lock_path.is_file() {
            found.push(lock_path);
        }
    }
    collect_pylock_variants(dir, &mut found);
    found.sort();
    found.dedup();
    filter_lock_paths_by_allowlist(&found, lock_file_allowlist)
}

/// Legacy helper: first adjacent (or parent-walked) lock file, if any.
pub fn find_lock_file(
    manifest_path: &Path,
    lock_file_allowlist: &[String],
    scan_root: Option<&Path>,
) -> Option<PathBuf> {
    find_lock_files(manifest_path, lock_file_allowlist, scan_root)
        .into_iter()
        .next()
}

/// Packages merged from adjacent lock files plus FR-036 source attribution.
pub struct ResolvedLockFiles {
    pub packages: Vec<vlz_db::Package>,
    pub package_source_paths: HashMap<vlz_db::Package, Vec<PathBuf>>,
    pub package_declarations:
        HashMap<vlz_db::Package, Vec<vlz_db::PackageDeclarationLocation>>,
    pub lock_paths: Vec<PathBuf>,
}

/// Parse and union all applicable lock files for `manifest_path`.
///
/// Returns `Ok(None)` when no locks exist, when the entry point is itself a
/// lock file (handled by resolver short-circuit), or when every lock parsed
/// successfully but yielded zero packages (fall through to pip / FR-022).
/// When `scan_root` is `Some`, parent directories up to `scan_root` are
/// searched when the manifest's own directory has no usable lock.
pub fn resolve_lock_files(
    manifest_path: &Path,
    lock_file_allowlist: &[String],
    scan_root: Option<&Path>,
) -> Result<Option<ResolvedLockFiles>, ParserError> {
    if manifest_is_lock_file(manifest_path) {
        return Ok(None);
    }
    if let Some(dir) = manifest_path.parent() {
        verify_lock_allowlist_for_dir(dir, lock_file_allowlist)
            .map_err(ParserError::Other)?;
    }
    let lock_paths =
        find_lock_files(manifest_path, lock_file_allowlist, scan_root);
    if lock_paths.is_empty() {
        return Ok(None);
    }

    let mut packages = Vec::new();
    let mut package_source_paths: HashMap<vlz_db::Package, Vec<PathBuf>> =
        HashMap::new();
    let mut package_declarations: HashMap<
        vlz_db::Package,
        Vec<vlz_db::PackageDeclarationLocation>,
    > = HashMap::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut any_success = false;
    let mut last_err = None;

    for lock_path in &lock_paths {
        match std::fs::read_to_string(lock_path) {
            Ok(content) => {
                match parse_lock_file_with_declarations(
                    lock_path.as_path(),
                    &content,
                ) {
                    Ok((pkgs, parsed)) => {
                        any_success = true;
                        let lock_decls =
                            lock_declarations_from_parsed(&parsed);
                        for pkg in pkgs {
                            package_source_paths
                                .entry(pkg.clone())
                                .or_default()
                                .push(lock_path.clone());
                            if let Some(decls) = lock_decls.get(&pkg) {
                                package_declarations
                                    .entry(pkg.clone())
                                    .or_default()
                                    .extend(decls.iter().cloned());
                            }
                            let key = (pkg.name.clone(), pkg.version.clone());
                            if seen.insert(key) {
                                packages.push(pkg);
                            }
                        }
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            Err(e) => last_err = Some(ParserError::Io(e)),
        }
    }

    if !any_success {
        return Err(last_err.unwrap_or_else(|| {
            ParserError::Parse("lock read failed".to_string())
        }));
    }

    if packages.is_empty() {
        return Ok(None);
    }

    Ok(Some(ResolvedLockFiles {
        packages,
        package_source_paths,
        package_declarations,
        lock_paths,
    }))
}

fn collect_pylock_variants(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_pylock_variant(name) && name != "pylock.toml" {
            out.push(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_lock_files_requirements_variant_returns_locks() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let req = tmp.join("requirements-dev.txt");
        let poetry = tmp.join("poetry.lock");
        std::fs::write(&req, "pkg==1.0\n").unwrap();
        std::fs::write(
            &poetry,
            "[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(req.as_path(), &[], None);
        assert_eq!(found, vec![poetry]);
    }

    #[test]
    fn find_lock_files_requirements_txt_returns_all_present() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let req = tmp.join("requirements.txt");
        let pylock = tmp.join("pylock.toml");
        let poetry = tmp.join("poetry.lock");
        std::fs::write(&req, "pkg==1.0\n").unwrap();
        std::fs::write(
            &pylock,
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            &poetry,
            "[[package]]\nname = \"other\"\nversion = \"2.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(req.as_path(), &[], None);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&pylock));
        assert!(found.contains(&poetry));
    }

    #[test]
    fn find_lock_files_pipfile_returns_pipfile_lock() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let pipfile = tmp.join("Pipfile");
        let pipfile_lock = tmp.join("Pipfile.lock");
        std::fs::write(&pipfile, "").unwrap();
        std::fs::write(&pipfile_lock, "{}").unwrap();
        let found = find_lock_files(pipfile.as_path(), &[], None);
        assert_eq!(found, vec![pipfile_lock]);
    }

    #[test]
    fn find_lock_files_setup_cfg_includes_poetry_lock() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let setup_cfg = tmp.join("setup.cfg");
        let poetry_lock = tmp.join("poetry.lock");
        std::fs::write(&setup_cfg, "[options]\ninstall_requires =\n    a\n")
            .unwrap();
        std::fs::write(
            &poetry_lock,
            "[[package]]\nname = \"a\"\nversion = \"1\"\n",
        )
        .unwrap();
        let found = find_lock_files(setup_cfg.as_path(), &[], None);
        assert_eq!(found, vec![poetry_lock]);
    }

    #[test]
    fn find_lock_files_includes_pylock_variant() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let req = tmp.join("requirements.txt");
        let variant = tmp.join("pylock.dev.toml");
        std::fs::write(&req, "pkg==1.0\n").unwrap();
        std::fs::write(
            &variant,
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(req.as_path(), &[], None);
        assert_eq!(found, vec![variant]);
    }

    #[test]
    fn find_lock_files_filters_by_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let req = tmp.join("requirements.txt");
        std::fs::write(&req, "pkg==1.0\n").unwrap();
        std::fs::write(
            tmp.join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"a\"\nversion = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("poetry.lock"),
            "[[package]]\nname = \"b\"\nversion = \"1\"\n",
        )
        .unwrap();
        let found =
            find_lock_files(req.as_path(), &["poetry.lock".to_string()], None);
        assert_eq!(found, vec![tmp.join("poetry.lock")]);
    }

    #[test]
    fn find_lock_file_returns_first_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let req = tmp.join("requirements.txt");
        std::fs::write(&req, "pkg==1.0\n").unwrap();
        std::fs::write(
            tmp.join("pylock.toml"),
            "lock-version = \"1.0\"\ncreated-by = \"test\"\n\n[[packages]]\nname = \"a\"\nversion = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("poetry.lock"),
            "[[package]]\nname = \"b\"\nversion = \"1\"\n",
        )
        .unwrap();
        let found = find_lock_file(req.as_path(), &[], None);
        assert!(found.is_some());
    }

    #[test]
    fn find_lock_files_parent_walk_uses_root_lock() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let member = root.join("member");
        std::fs::create_dir_all(&member).unwrap();
        let pyproject = member.join("pyproject.toml");
        let uv_lock = root.join("uv.lock");
        std::fs::write(&pyproject, "[project]\nname = \"x\"\n").unwrap();
        std::fs::write(
            &uv_lock,
            "version = 1\n\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(pyproject.as_path(), &[], Some(root));
        assert_eq!(found, vec![uv_lock]);
    }

    #[test]
    fn find_lock_files_adjacent_lock_wins_over_parent() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let member = root.join("member");
        std::fs::create_dir_all(&member).unwrap();
        let pyproject = member.join("pyproject.toml");
        let adjacent_poetry = member.join("poetry.lock");
        let parent_uv = root.join("uv.lock");
        std::fs::write(&pyproject, "[project]\nname = \"x\"\n").unwrap();
        std::fs::write(
            &adjacent_poetry,
            "[[package]]\nname = \"adj\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            &parent_uv,
            "version = 1\n\n[[package]]\nname = \"par\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(pyproject.as_path(), &[], Some(root));
        assert_eq!(found, vec![adjacent_poetry]);
    }

    #[test]
    fn find_lock_files_parent_walk_stops_at_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let member = root.join("member");
        std::fs::create_dir_all(&member).unwrap();
        let pyproject = member.join("pyproject.toml");
        let outside_lock = root.join("uv.lock");
        std::fs::write(&pyproject, "[project]\nname = \"x\"\n").unwrap();
        std::fs::write(
            &outside_lock,
            "version = 1\n\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        // scan_root is the member dir; the root lock is outside it.
        let found = find_lock_files(pyproject.as_path(), &[], Some(&member));
        assert!(found.is_empty());
    }

    #[test]
    fn find_lock_files_pipfile_no_parent_walk() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let member = root.join("member");
        std::fs::create_dir_all(&member).unwrap();
        let pipfile = member.join("Pipfile");
        let parent_pipfile_lock = root.join("Pipfile.lock");
        std::fs::write(&pipfile, "").unwrap();
        std::fs::write(&parent_pipfile_lock, "{}").unwrap();
        let found = find_lock_files(pipfile.as_path(), &[], Some(root));
        assert!(found.is_empty());
    }

    #[test]
    fn find_lock_files_no_parent_walk_without_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let member = root.join("member");
        std::fs::create_dir_all(&member).unwrap();
        let pyproject = member.join("pyproject.toml");
        let parent_lock = root.join("uv.lock");
        std::fs::write(&pyproject, "[project]\nname = \"x\"\n").unwrap();
        std::fs::write(
            &parent_lock,
            "version = 1\n\n[[package]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        // No scan_root: no parent walk (backward-compatible adjacent-only).
        let found = find_lock_files(pyproject.as_path(), &[], None);
        assert!(found.is_empty());
    }
}
