// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Package URL (PURL) helpers shared by SBOM export and import (NFR-024, FR-038).

use std::collections::BTreeMap;

use crate::{
    CRATES_IO_ECOSYSTEM, GO_ECOSYSTEM, MAVEN_ECOSYSTEM, NPM_ECOSYSTEM,
    NUGET_ECOSYSTEM, PACKAGIST_ECOSYSTEM, PUB_ECOSYSTEM, PUB_PURL_TYPE,
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
        Some(PACKAGIST_ECOSYSTEM) => "composer",
        Some(NUGET_ECOSYSTEM) => "nuget",
        Some(PUB_ECOSYSTEM) => PUB_PURL_TYPE,
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
        "composer" => Some(PACKAGIST_ECOSYSTEM),
        "nuget" => Some(NUGET_ECOSYSTEM),
        PUB_PURL_TYPE => Some(PUB_ECOSYSTEM),
        "pypi" => Some(PYPI_ECOSYSTEM),
        _ => None,
    }
}

/// PURL for a resolved package (SEC-019 CycloneDX 1.6, SPDX 3.0).
///
/// Re-emits preserved W3-3 qualifiers and subpath when present.
pub fn purl_for_package(pkg: &Package) -> String {
    let purl_type = purl_type_for_ecosystem(pkg.ecosystem.as_deref());
    let mut out = format!("pkg:{}/{}@{}", purl_type, pkg.name, pkg.version);
    if let Some(ref quals) = pkg.purl_qualifiers
        && !quals.is_empty()
    {
        let encoded: Vec<String> =
            quals.iter().map(|(k, v)| format!("{k}={v}")).collect();
        out.push('?');
        out.push_str(&encoded.join("&"));
    }
    if let Some(ref sub) = pkg.purl_subpath
        && !sub.is_empty()
    {
        out.push('#');
        out.push_str(sub);
    }
    out
}

/// Parse PURL qualifier string (`k=v&k2=v2`) into a sorted map.
fn parse_qualifiers(raw: &str) -> Option<BTreeMap<String, String>> {
    if raw.is_empty() {
        return None;
    }
    let mut map = BTreeMap::new();
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        if k.is_empty() {
            return None;
        }
        map.insert(k.to_string(), v.to_string());
    }
    if map.is_empty() { None } else { Some(map) }
}

/// Parse a Package URL into a [`Package`] for CVE lookup (FR-038 / W3-3).
///
/// Supported types: `pypi`, `cargo`, `golang`, `npm`, `maven`, `gem`,
/// `composer`, `nuget`. Maven names use OSV `groupId:artifactId`. Accepts both
/// `pkg:maven/group/artifact@version` and `pkg:maven/group:artifact@version`
/// (the latter matches vlz export). Qualifiers and subpath are preserved on
/// the package but ignored for OSV query identity (Eq/Hash).
pub fn package_from_purl(purl: &str) -> Option<Package> {
    let rest = purl.strip_prefix("pkg:")?;
    let (type_and_name, version_and_rest) = rest.rsplit_once('@')?;
    // PURL: version may be followed by ?qualifiers and/or #subpath.
    let (version, quals_and_sub) = match version_and_rest.find(['?', '#']) {
        Some(idx) => {
            (&version_and_rest[..idx], Some(&version_and_rest[idx..]))
        }
        None => (version_and_rest, None),
    };
    if version.is_empty() {
        return None;
    }
    let mut purl_qualifiers = None;
    let mut purl_subpath = None;
    if let Some(rest) = quals_and_sub {
        let (quals_part, sub_part) = if let Some(hash) = rest.find('#') {
            let (before, after) = rest.split_at(hash);
            (before, Some(&after[1..]))
        } else {
            (rest, None)
        };
        if let Some(q) = quals_part.strip_prefix('?') {
            purl_qualifiers = parse_qualifiers(q);
        } else if !quals_part.is_empty() && !quals_part.starts_with('#') {
            return None;
        }
        if let Some(sub) = sub_part
            && !sub.is_empty()
        {
            purl_subpath = Some(sub.to_string());
        }
    }
    let (purl_type, name_path) = type_and_name.split_once('/')?;
    if name_path.is_empty() {
        return None;
    }
    let ecosystem = ecosystem_for_purl_type(purl_type)?;
    let decoded_name_path = percent_decode_purl_segment(name_path)?;
    let name = normalize_purl_name(purl_type, &decoded_name_path)?;
    if name.is_empty() {
        return None;
    }
    Some(Package {
        name,
        version: version.to_string(),
        ecosystem: Some(ecosystem.to_string()),
        purl_qualifiers,
        purl_subpath,
    })
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode percent-encoded PURL name segments (FR-038 import).
fn percent_decode_purl_segment(segment: &str) -> Option<String> {
    if !segment.as_bytes().contains(&b'%') {
        return Some(segment.to_string());
    }
    let mut out = Vec::with_capacity(segment.len());
    let bytes = segment.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let hi = hex_digit(bytes[index + 1])?;
            let lo = hex_digit(bytes[index + 2])?;
            out.push((hi << 4) | lo);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
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
            ..Default::default()
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
    fn package_from_purl_preserves_qualifiers_and_subpath_w3_3() {
        let pkg = package_from_purl(
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar",
        )
        .unwrap();
        assert_eq!(pkg.version, "3.12.0");
        assert_eq!(pkg.name, "org.apache.commons:commons-lang3");
        assert_eq!(
            pkg.purl_qualifiers
                .as_ref()
                .and_then(|m| m.get("type"))
                .map(String::as_str),
            Some("jar")
        );

        let with_sub =
            package_from_purl("pkg:npm/lodash@4.17.21#lib/index.js").unwrap();
        assert_eq!(with_sub.version, "4.17.21");
        assert_eq!(with_sub.name, "lodash");
        assert_eq!(with_sub.purl_subpath.as_deref(), Some("lib/index.js"));

        let round = package_from_purl(&purl_for_package(&pkg)).unwrap();
        assert_eq!(round.purl_qualifiers, pkg.purl_qualifiers);
    }

    #[test]
    fn package_eq_ignores_qualifiers_for_cve_identity() {
        let a = package_from_purl(
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0?type=jar",
        )
        .unwrap();
        let b = package_from_purl(
            "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn package_from_purl_rejects_unknown_type() {
        assert!(package_from_purl("pkg:unknown/foo@1.0.0").is_none());
    }

    #[test]
    fn package_from_purl_decodes_percent_encoded_name() {
        let pkg = package_from_purl("pkg:npm/%40scope%2Fpkg@1.0.0").unwrap();
        assert_eq!(pkg.name, "@scope/pkg");
    }

    #[test]
    fn package_from_purl_rejects_invalid_percent_encoding() {
        assert!(package_from_purl("pkg:npm/%zz@1.0.0").is_none());
    }

    #[test]
    fn purl_round_trip_packagist() {
        let pkg = Package {
            name: "symfony/http-foundation".to_string(),
            version: "6.4.0".to_string(),
            ecosystem: Some(PACKAGIST_ECOSYSTEM.to_string()),
            ..Default::default()
        };
        let purl = purl_for_package(&pkg);
        assert_eq!(purl, "pkg:composer/symfony/http-foundation@6.4.0");
        assert_eq!(package_from_purl(&purl), Some(pkg));
    }

    #[test]
    fn purl_round_trip_nuget() {
        let pkg = Package {
            name: "Newtonsoft.Json".to_string(),
            version: "13.0.1".to_string(),
            ecosystem: Some(NUGET_ECOSYSTEM.to_string()),
            ..Default::default()
        };
        let purl = purl_for_package(&pkg);
        assert_eq!(purl, "pkg:nuget/Newtonsoft.Json@13.0.1");
        assert_eq!(package_from_purl(&purl), Some(pkg));
    }

    #[test]
    fn purl_round_trip_pub() {
        let pkg = Package {
            name: "http".to_string(),
            version: "1.2.2".to_string(),
            ecosystem: Some(PUB_ECOSYSTEM.to_string()),
            ..Default::default()
        };
        let purl = purl_for_package(&pkg);
        assert_eq!(purl, format!("pkg:{PUB_PURL_TYPE}/http@1.2.2"));
        assert_eq!(package_from_purl(&purl), Some(pkg));
    }

    #[test]
    fn pub_purl_type_maps_both_ways() {
        assert_eq!(
            purl_type_for_ecosystem(Some(PUB_ECOSYSTEM)),
            PUB_PURL_TYPE
        );
        assert_eq!(ecosystem_for_purl_type("PUB"), Some(PUB_ECOSYSTEM));
    }

    #[test]
    fn ecosystem_for_purl_type_case_insensitive() {
        assert_eq!(ecosystem_for_purl_type("NPM"), Some(NPM_ECOSYSTEM));
    }
}
