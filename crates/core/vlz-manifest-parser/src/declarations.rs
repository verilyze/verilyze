// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use vlz_db::{
    DeclarationKind, Package, PackageDeclarationLocation,
    dedupe_sort_declarations,
};

/// Parser output: package plus declaration line in a specific manifest file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDependency {
    pub package: Package,
    pub path: PathBuf,
    pub start_line: u32,
    pub end_line: Option<u32>,
    pub kind: DeclarationKind,
}

/// Cached resolver output including declaration metadata.
#[derive(Debug, Clone, Default)]
pub struct CachedResolution {
    pub packages: Vec<Package>,
    pub package_declarations:
        HashMap<Package, Vec<PackageDeclarationLocation>>,
    pub package_source_paths: HashMap<Package, Vec<PathBuf>>,
}

/// Merge key for manifest declarations (constraint versions differ from pins).
pub fn manifest_merge_key(package: &Package) -> (Option<String>, String) {
    (package.ecosystem.clone(), package.name.to_lowercase())
}

/// Convert a parsed dependency into a manifest declaration location.
pub fn parsed_to_declaration(
    dep: &ParsedDependency,
) -> Option<PackageDeclarationLocation> {
    PackageDeclarationLocation::new(
        dep.path.display().to_string(),
        dep.start_line,
        dep.end_line,
        dep.kind,
    )
}

/// Index manifest declarations by `(ecosystem, normalized_name)`.
pub fn index_manifest_declarations(
    parsed: &[ParsedDependency],
) -> HashMap<(Option<String>, String), Vec<PackageDeclarationLocation>> {
    let mut index: HashMap<
        (Option<String>, String),
        Vec<PackageDeclarationLocation>,
    > = HashMap::new();
    for dep in parsed {
        if dep.kind != DeclarationKind::Manifest {
            continue;
        }
        if let Some(loc) = parsed_to_declaration(dep) {
            index
                .entry(manifest_merge_key(&dep.package))
                .or_default()
                .push(loc);
        }
    }
    for decls in index.values_mut() {
        dedupe_sort_declarations(decls);
    }
    index
}

/// Build manifest declarations keyed by resolved package (name+version pin).
pub fn manifest_declarations_for_packages(
    parsed: &[ParsedDependency],
    packages: &[Package],
) -> HashMap<Package, Vec<PackageDeclarationLocation>> {
    let index = index_manifest_declarations(parsed);
    let mut out = HashMap::new();
    for pkg in packages {
        if let Some(decls) = index.get(&manifest_merge_key(pkg)) {
            out.insert(pkg.clone(), decls.clone());
        }
    }
    out
}

/// Attach manifest + lock declarations for one resolved package.
pub fn declarations_for_resolved_package(
    resolved: &Package,
    manifest_index: &HashMap<
        (Option<String>, String),
        Vec<PackageDeclarationLocation>,
    >,
    lock_declarations: &HashMap<Package, Vec<PackageDeclarationLocation>>,
) -> Vec<PackageDeclarationLocation> {
    let mut decls = Vec::new();
    if let Some(manifest) = manifest_index.get(&manifest_merge_key(resolved)) {
        decls.extend(manifest.iter().cloned());
    }
    if let Some(lock) = lock_declarations.get(resolved) {
        decls.extend(lock.iter().cloned());
    }
    dedupe_sort_declarations(&mut decls);
    decls
}

/// Build per-package declaration map for a resolved package list.
pub fn build_package_declarations(
    packages: &[Package],
    manifest_index: &HashMap<
        (Option<String>, String),
        Vec<PackageDeclarationLocation>,
    >,
    lock_declarations: &HashMap<Package, Vec<PackageDeclarationLocation>>,
) -> HashMap<Package, Vec<PackageDeclarationLocation>> {
    let mut out = HashMap::new();
    for pkg in packages {
        let decls = declarations_for_resolved_package(
            pkg,
            manifest_index,
            lock_declarations,
        );
        if !decls.is_empty() {
            out.insert(pkg.clone(), decls);
        }
    }
    out
}

/// Merge declaration maps from multiple resolution steps.
pub fn merge_declaration_maps(
    target: &mut HashMap<Package, Vec<PackageDeclarationLocation>>,
    source: HashMap<Package, Vec<PackageDeclarationLocation>>,
) {
    for (pkg, mut decls) in source {
        let entry = target.entry(pkg).or_default();
        entry.append(&mut decls);
        dedupe_sort_declarations(entry);
    }
}

/// Lock declaration from a parsed lock stanza.
pub fn lock_declaration(
    lock_path: &Path,
    start_line: u32,
    end_line: Option<u32>,
) -> Option<PackageDeclarationLocation> {
    PackageDeclarationLocation::new(
        lock_path.display().to_string(),
        start_line,
        end_line,
        DeclarationKind::Lockfile,
    )
}

/// Lock declarations keyed by pinned package from parser output.
pub fn lock_declarations_from_parsed(
    parsed: &[ParsedDependency],
) -> HashMap<Package, Vec<PackageDeclarationLocation>> {
    let mut out: HashMap<Package, Vec<PackageDeclarationLocation>> =
        HashMap::new();
    for dep in parsed {
        if dep.kind != DeclarationKind::Lockfile {
            continue;
        }
        if let Some(loc) =
            lock_declaration(&dep.path, dep.start_line, dep.end_line)
        {
            out.entry(dep.package.clone()).or_default().push(loc);
        }
    }
    for decls in out.values_mut() {
        dedupe_sort_declarations(decls);
    }
    out
}

/// Merge manifest graph declarations with lock declarations for resolved packages.
pub fn resolve_declarations_for_packages(
    packages: &[Package],
    graph: &super::DependencyGraph,
    lock_declarations: &HashMap<Package, Vec<PackageDeclarationLocation>>,
) -> HashMap<Package, Vec<PackageDeclarationLocation>> {
    let manifest_index =
        index_manifest_declarations(&graph.parsed_dependencies);
    build_package_declarations(packages, &manifest_index, lock_declarations)
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::PYPI_ECOSYSTEM;

    fn pkg(name: &str, version: &str) -> Package {
        Package {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
        }
    }

    fn parsed(
        name: &str,
        version: &str,
        path: &str,
        line: u32,
    ) -> ParsedDependency {
        ParsedDependency {
            package: pkg(name, version),
            path: PathBuf::from(path),
            start_line: line,
            end_line: None,
            kind: DeclarationKind::Manifest,
        }
    }

    #[test]
    fn manifest_merge_matches_constraint_to_pinned_version() {
        let parsed = vec![parsed("requests", "any", "pyproject.toml", 5)];
        let index = index_manifest_declarations(&parsed);
        let resolved = pkg("requests", "2.31.0");
        let decls = declarations_for_resolved_package(
            &resolved,
            &index,
            &HashMap::new(),
        );
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].start_line, 5);
        assert_eq!(decls[0].kind, DeclarationKind::Manifest);
    }

    #[test]
    fn merge_reports_manifest_and_lock() {
        let parsed = vec![parsed("requests", ">=2.0", "pyproject.toml", 5)];
        let index = index_manifest_declarations(&parsed);
        let resolved = pkg("requests", "2.31.0");
        let mut lock = HashMap::new();
        lock.insert(
            resolved.clone(),
            vec![
                PackageDeclarationLocation::new(
                    "poetry.lock",
                    42,
                    None,
                    DeclarationKind::Lockfile,
                )
                .unwrap(),
            ],
        );
        let decls =
            declarations_for_resolved_package(&resolved, &index, &lock);
        assert_eq!(decls.len(), 2);
        assert_eq!(decls[0].kind, DeclarationKind::Manifest);
        assert_eq!(decls[1].kind, DeclarationKind::Lockfile);
    }

    #[test]
    fn dedupe_identical_declarations() {
        let mut decls = vec![
            PackageDeclarationLocation::new(
                "Cargo.toml",
                10,
                None,
                DeclarationKind::Manifest,
            )
            .unwrap(),
            PackageDeclarationLocation::new(
                "Cargo.toml",
                10,
                None,
                DeclarationKind::Manifest,
            )
            .unwrap(),
        ];
        dedupe_sort_declarations(&mut decls);
        assert_eq!(decls.len(), 1);
    }
}
