// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Allowlisted SBOM basenames for discovery (FR-038, Appendix A).

/// Plugin language name registered with finders / parsers / resolvers.
pub const SBOM_LANGUAGE_NAME: &str = "sbom";

/// Exact basenames discovered by default (CycloneDX recognized + plan extras).
pub const SBOM_EXACT_BASENAMES: &[&str] = &["bom.json", "sbom.json"];

/// True when `name` matches FR-038 discovery allowlist.
pub fn is_sbom_basename(name: &str) -> bool {
    if SBOM_EXACT_BASENAMES.contains(&name) {
        return true;
    }
    // CycloneDX / SPDX conformance suffixes (JSON only in v1).
    name.ends_with(".cdx.json") || name.ends_with(".spdx.json")
}

/// True when the path's file name is an allowlisted SBOM basename.
pub fn is_sbom_entry_path(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(is_sbom_basename)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn exact_and_suffix_basenames() {
        assert!(is_sbom_basename("bom.json"));
        assert!(is_sbom_basename("sbom.json"));
        assert!(is_sbom_basename("app.cdx.json"));
        assert!(is_sbom_basename("verilyze.spdx.json"));
        assert!(!is_sbom_basename("package.json"));
        assert!(!is_sbom_basename("inventory.json"));
        assert!(!is_sbom_basename("bom.xml"));
    }

    #[test]
    fn entry_path_uses_file_name() {
        assert!(is_sbom_entry_path(Path::new("/tmp/bom.json")));
        assert!(!is_sbom_entry_path(Path::new("/tmp/Cargo.toml")));
    }
}
