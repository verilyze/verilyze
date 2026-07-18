// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use vlz_manifest_parser::{ParserError, lock_declarations_from_parsed};

use crate::lock_names::{
    filter_lock_paths_by_allowlist, is_pylock_variant, manifest_is_lock_file,
    verify_lock_allowlist_for_dir,
};
use crate::parser::parse_lock_file_with_declarations;

/// Basenames searched adjacent to manifests (Appendix A). `pylock.*.toml` via [`collect_pylock_variants`].
const LOCK_CANDIDATE_BASENAMES: &[&str] =
    &["pylock.toml", "poetry.lock", "uv.lock", "Pipfile.lock"];

/// Find all applicable adjacent lock file paths for `manifest_path`.
pub fn find_lock_files(
    manifest_path: &Path,
    lock_file_allowlist: &[String],
) -> Vec<PathBuf> {
    let dir = match manifest_path.parent() {
        Some(d) => d,
        None => return Vec::new(),
    };
    let name = match manifest_path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return Vec::new(),
    };

    let use_candidates = match name {
        "pyproject.toml" | "setup.py" | "setup.cfg" | "requirements.txt" => {
            true
        }
        "Pipfile" => false,
        _ => false,
    };

    let mut found = Vec::new();
    if name == "Pipfile" {
        let pipfile_lock = dir.join("Pipfile.lock");
        if pipfile_lock.is_file() {
            found.push(pipfile_lock);
        }
        return found;
    }

    if !use_candidates {
        return found;
    }

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

/// Legacy helper: first adjacent lock file, if any.
pub fn find_lock_file(
    manifest_path: &Path,
    lock_file_allowlist: &[String],
) -> Option<PathBuf> {
    find_lock_files(manifest_path, lock_file_allowlist)
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

/// Parse and union all adjacent lock files for `manifest_path`.
///
/// Returns `Ok(None)` when no locks exist, when the entry point is itself a
/// lock file (handled by resolver short-circuit), or when every lock parsed
/// successfully but yielded zero packages (fall through to pip / FR-022).
pub fn resolve_lock_files(
    manifest_path: &Path,
    lock_file_allowlist: &[String],
) -> Result<Option<ResolvedLockFiles>, ParserError> {
    if manifest_is_lock_file(manifest_path) {
        return Ok(None);
    }
    if let Some(dir) = manifest_path.parent() {
        verify_lock_allowlist_for_dir(dir, lock_file_allowlist)
            .map_err(ParserError::Other)?;
    }
    let lock_paths = find_lock_files(manifest_path, lock_file_allowlist);
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
    fn find_lock_files_requirements_txt_returns_all_present() {
        let dir = tempfile::tempdir().unwrap();
        let tmp = dir.path();
        let req = tmp.join("requirements.txt");
        let pylock = tmp.join("pylock.toml");
        let poetry = tmp.join("poetry.lock");
        std::fs::write(&req, "pkg==1.0\n").unwrap();
        std::fs::write(
            &pylock,
            "[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        std::fs::write(
            &poetry,
            "[[package]]\nname = \"other\"\nversion = \"2.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(req.as_path(), &[]);
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
        let found = find_lock_files(pipfile.as_path(), &[]);
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
        let found = find_lock_files(setup_cfg.as_path(), &[]);
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
            "[[packages]]\nname = \"pkg\"\nversion = \"1.0\"\n",
        )
        .unwrap();
        let found = find_lock_files(req.as_path(), &[]);
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
            "[[packages]]\nname = \"a\"\nversion = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("poetry.lock"),
            "[[package]]\nname = \"b\"\nversion = \"1\"\n",
        )
        .unwrap();
        let found =
            find_lock_files(req.as_path(), &["poetry.lock".to_string()]);
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
            "[[packages]]\nname = \"a\"\nversion = \"1\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.join("poetry.lock"),
            "[[package]]\nname = \"b\"\nversion = \"1\"\n",
        )
        .unwrap();
        let found = find_lock_file(req.as_path(), &[]);
        assert!(found.is_some());
    }
}
