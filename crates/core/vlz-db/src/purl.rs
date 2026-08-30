// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Package URL (PURL) helpers shared by SBOM export and import (NFR-024, FR-038).

use crate::{
    CRATES_IO_ECOSYSTEM, GO_ECOSYSTEM, MAVEN_ECOSYSTEM, NPM_ECOSYSTEM,
    PYPI_ECOSYSTEM, Package, RUBYGEMS_ECOSYSTEM,
};

/// PURL type string for SBOM output from a package ecosystem (SEC-019).
pub fn purl_type_for_ecosystem(ecosystem: Option<&str>) -> &'static str {
    match ecosystem {
        Some(CRATES_IO_ECOSYSTEM) => "cargo",
        Some(GO_ECOSYSTEM) => "golang",
        Some(NPM_ECOSYSTEM) => "npm",
        Some(MAVEN_ECOSYSTEM) => "maven",
        Some(RUBYGEMS_ECOSYSTEM) => "gem",
        Some(PYPI_ECOSYSTEM) | None => "pypi",
        _ => "pypi",
    }
}

/// OSV ecosystem label for a PURL type (FR-038 import).
pub fn ecosystem_for_purl_type(purl_type: &str) -> Option<&'static str> {
    match purl_type.to_ascii_lowercase().as_str() {
        "cargo" => Some(CRATES_IO_ECOSYSTEM),
        "golang" => Some(GO_ECOSYSTEM),
        "npm" => Some(NPM_ECOSYSTEM),
        "maven" => Some(MAVEN_ECOSYSTEM),
        "gem" => Some(RUBYGEMS_ECOSYSTEM),
        "pypi" => Some(PYPI_ECOSYSTEM),
        _ => None,
    }
}

/// PURL for a resolved package (SEC-019 CycloneDX 1.6, SPDX 3.0).
pub fn purl_for_package(pkg: &Package) -> String {
    let purl_type = purl_type_for_ecosystem(pkg.ecosystem.as_deref());
    format!("pkg:{}/{}@{}", purl_type, pkg.name, pkg.version)
}

/// Parse a Package URL into a [`Package`] for CVE lookup (FR-038).
///
/// Supported types: `pypi`, `cargo`, `golang`, `npm`, `maven`, `gem`.
/// Maven names use OSV `groupId:artifactId`. Accepts both
/// `pkg:maven/group/artifact@version` and `pkg:maven/group:artifact@version`
/// (the latter matches vlz export).
pub fn package_from_purl(purl: &str) -> Option<Package> {
    let rest = purl.strip_prefix("pkg:")?;
    let (type_and_name, version) = rest.rsplit_once('@')?;
    if version.is_empty() {
        return None;
    }
    let (purl_type, name_path) = type_and_name.split_once('/')?;
    if name_path.is_empty() {
        return None;
    }
    let ecosystem = ecosystem_for_purl_type(purl_type)?;
    let name = normalize_purl_name(purl_type, name_path)?;
    if name.is_empty() {
        return None;
    }
    Some(Package {
        name,
        version: version.to_string(),
        ecosystem: Some(ecosystem.to_string()),
    })
}

fn normalize_purl_name(purl_type: &str, name_path: &str) -> Option<String> {
    if purl_type.eq_ignore_ascii_case("maven") {
        if let Some((group, artifact)) = name_path.split_once('/') {
            if group.is_empty() || artifact.is_empty() {
                return None;
            }
            // Drop optional classifier/type after artifact if present.
            let artifact = artifact.split('/').next().unwrap_or(artifact);
            return Some(format!("{group}:{artifact}"));
        }
        // vlz export form: group:artifact in a single path segment.
        if name_path.contains(':') {
            return Some(name_path.to_string());
        }
        return Some(name_path.to_string());
    }
    Some(name_path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn purl_round_trip_pypi() {
        let pkg = Package {
            name: "requests".to_string(),
            version: "2.31.0".to_string(),
            ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
        };
        let purl = purl_for_package(&pkg);
        assert_eq!(purl, "pkg:pypi/requests@2.31.0");
        assert_eq!(package_from_purl(&purl), Some(pkg));
    }

    #[test]
    fn package_from_purl_maven_standard_and_colon() {
        let std = package_from_purl(
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        )
        .unwrap();
        assert_eq!(std.name, "org.apache.commons:commons-lang3");
        assert_eq!(std.version, "3.12.0");
        assert_eq!(std.ecosystem.as_deref(), Some(MAVEN_ECOSYSTEM));

        let colon = package_from_purl(
            "pkg:maven/org.apache.commons:commons-lang3@3.12.0",
        )
        .unwrap();
        assert_eq!(colon.name, "org.apache.commons:commons-lang3");
    }

    #[test]
    fn package_from_purl_rejects_unknown_type() {
        assert!(package_from_purl("pkg:apk/openssl@3.0.0").is_none());
        assert!(package_from_purl("not-a-purl").is_none());
        assert!(package_from_purl("pkg:pypi/foo@").is_none());
    }

    #[test]
    fn ecosystem_for_purl_type_case_insensitive() {
        assert_eq!(ecosystem_for_purl_type("PyPI"), Some(PYPI_ECOSYSTEM));
        assert_eq!(
            ecosystem_for_purl_type("CARGO"),
            Some(CRATES_IO_ECOSYSTEM)
        );
    }
}
