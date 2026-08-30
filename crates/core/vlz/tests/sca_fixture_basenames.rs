// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Committed test trees must not use SCA-detectable manifest or lock names.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use vlz::registry::{ensure_default_manifest_finder, finders};

/// Languages registered by the default `runtime` feature set.
const RUNTIME_FINDER_LANGUAGES: &[&str] =
    &["go", "java", "javascript", "python", "ruby", "rust", "sbom"];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("workspace root")
}

fn is_afl_package_manifest(rel: &Path) -> bool {
    let mut comps = rel.components();
    matches!(
        (comps.next(), comps.next(), comps.next(), comps.next()),
        (
            Some(std::path::Component::Normal(tests)),
            Some(std::path::Component::Normal(fuzz)),
            Some(std::path::Component::Normal(name)),
            None
        ) if tests == "tests"
            && fuzz == "fuzz"
            && (name == "Cargo.toml" || name == "Cargo.lock")
    )
}

fn should_skip_dir(name: &str) -> bool {
    matches!(name, "target" | ".git")
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if should_skip_dir(name) {
                continue;
            }
            collect_files(&path, out);
        } else if meta.is_file() {
            out.push(path);
        }
    }
}

fn collect_crate_tests_dirs(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read_dir {}: {err}", dir.display()));
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if should_skip_dir(name) {
            continue;
        }
        if name == "tests" {
            out.push(path);
        } else {
            collect_crate_tests_dirs(&path, out);
        }
    }
}

#[test]
fn committed_test_trees_avoid_sca_sensitive_basenames() {
    ensure_default_manifest_finder();
    let guard = finders().lock().expect("finders lock");
    let got: BTreeSet<&str> =
        guard.iter().map(|f| f.language_name()).collect();
    let want: BTreeSet<&str> =
        RUNTIME_FINDER_LANGUAGES.iter().copied().collect();
    assert_eq!(
        got, want,
        "walk test requires the full runtime finder set; \
         add the language to RUNTIME_FINDER_LANGUAGES when registering a finder"
    );

    let root = repo_root();
    let tests_root = root.join("tests");
    let crates_root = root.join("crates");
    assert!(
        tests_root.is_dir() && crates_root.is_dir(),
        "expected tests/ and crates/ under {}",
        root.display()
    );
    let mut files = Vec::new();
    collect_files(&tests_root, &mut files);
    let mut tests_dirs = Vec::new();
    collect_crate_tests_dirs(&crates_root, &mut tests_dirs);
    for dir in tests_dirs {
        collect_files(&dir, &mut files);
    }
    assert!(
        !files.is_empty(),
        "walk found no files under tests/ or crates/**/tests/**"
    );

    let mut violations = Vec::new();
    for path in files {
        let Ok(rel) = path.strip_prefix(&root) else {
            continue;
        };
        if is_afl_package_manifest(rel) {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        for finder in guard.iter() {
            if finder.is_sca_sensitive_basename(name) {
                violations.push(format!(
                    "{} ({}); rename to `{name}.fixture` or copy into a temp dir",
                    rel.display(),
                    finder.language_name()
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "SCA-sensitive fixture names:\n{}",
        violations.join("\n")
    );
}

#[test]
fn afl_package_paths_are_exempt() {
    assert!(is_afl_package_manifest(Path::new("tests/fuzz/Cargo.toml")));
    assert!(is_afl_package_manifest(Path::new("tests/fuzz/Cargo.lock")));
    assert!(!is_afl_package_manifest(Path::new(
        "tests/fuzz/corpus/gemfile/seed1"
    )));
    let joined = PathBuf::from("tests").join("fuzz").join("Cargo.toml");
    assert!(is_afl_package_manifest(&joined));
}
