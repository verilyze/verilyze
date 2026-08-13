// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::collections::BTreeMap;
use std::path::Path;
use vlz_db::{DeclarationKind, Package, RUBYGEMS_ECOSYSTEM};
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::util::looks_like_requirement;

#[derive(Clone)]
struct Candidate {
    version: String,
    platform: Option<String>,
    line: u32,
}

fn lock_platforms(content: &str) -> Vec<String> {
    let mut in_platforms = false;
    let mut platforms = Vec::new();
    for line in content.lines() {
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_platforms = line.trim() == "PLATFORMS";
            continue;
        }
        if in_platforms {
            let value = line.trim();
            if !value.is_empty() {
                platforms.push(value.to_string());
            }
        }
    }
    platforms
}

fn split_version_platform(
    raw: &str,
    platforms: &[String],
) -> (String, Option<String>) {
    let mut ordered: Vec<&String> = platforms
        .iter()
        .filter(|platform| platform.as_str() != "ruby")
        .collect();
    // Longest suffix first so x86_64-linux wins over linux.
    ordered.sort_by_key(|platform| std::cmp::Reverse(platform.len()));
    for platform in ordered {
        let suffix = format!("-{platform}");
        if let Some(version) = raw.strip_suffix(&suffix) {
            return (version.to_string(), Some((*platform).clone()));
        }
    }
    (raw.to_string(), None)
}

fn host_matches(platform: &str) -> bool {
    let arch_matches = match std::env::consts::ARCH {
        "aarch64" => {
            platform.contains("aarch64") || platform.contains("arm64")
        }
        "x86_64" => platform.contains("x86_64") || platform.contains("x64"),
        other => platform.contains(other),
    };
    let os_matches = match std::env::consts::OS {
        "macos" => platform.contains("darwin") || platform.contains("macos"),
        "windows" => {
            platform.contains("mingw")
                || platform.contains("mswin")
                || platform.contains("windows")
        }
        other => platform.contains(other),
    };
    arch_matches && os_matches
}

fn choose_candidate(candidates: &mut [Candidate]) -> Candidate {
    // Prefer higher version strings among equals of the same preference tier.
    candidates.sort_by(|left, right| right.version.cmp(&left.version));
    candidates
        .iter()
        .find(|item| item.platform.as_deref().is_some_and(host_matches))
        .or_else(|| {
            candidates.iter().find(|item| {
                item.platform
                    .as_deref()
                    .is_none_or(|platform| platform == "ruby")
            })
        })
        .unwrap_or(&candidates[0])
        .clone()
}

pub fn parse_gemfile_lock(content: &str) -> Result<Vec<Package>, ParserError> {
    Ok(parse_gemfile_lock_with_declarations(
        content,
        Path::new("Gemfile.lock"),
    )?
    .0)
}

/// Parse registry SPECS from a Bundler lock with FR-036a locations.
pub fn parse_gemfile_lock_with_declarations(
    content: &str,
    path: &Path,
) -> Result<(Vec<Package>, Vec<ParsedDependency>), ParserError> {
    let platforms = lock_platforms(content);
    // Allow spaces or tabs; reject requirement lines via looks_like_requirement.
    let spec = regex::Regex::new(r"^[\t ]+([A-Za-z0-9_.-]+) \(([^()]+)\)\s*$")
        .expect("valid Bundler spec regex");
    let mut section = "";
    let mut in_specs = false;
    let mut candidates: BTreeMap<String, Vec<Candidate>> = BTreeMap::new();

    for (index, line) in content.lines().enumerate() {
        if !line.starts_with(' ') && !line.starts_with('\t') {
            section = line.trim();
            in_specs = false;
            continue;
        }
        if line.trim() == "specs:" {
            in_specs = section == "GEM";
            continue;
        }
        if !in_specs {
            continue;
        }
        if let Some(captures) = spec.captures(line) {
            if looks_like_requirement(&captures[2]) {
                continue;
            }
            let (version, platform) =
                split_version_platform(&captures[2], &platforms);
            candidates.entry(captures[1].to_string()).or_default().push(
                Candidate {
                    version,
                    platform,
                    line: (index + 1) as u32,
                },
            );
        }
    }

    let mut parsed = Vec::new();
    for (name, mut versions) in candidates {
        let chosen = choose_candidate(&mut versions);
        parsed.push(ParsedDependency {
            package: Package {
                name,
                version: chosen.version,
                ecosystem: Some(RUBYGEMS_ECOSYSTEM.to_string()),
            },
            path: path.to_path_buf(),
            start_line: chosen.line,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        });
    }
    let packages = parsed.iter().map(|item| item.package.clone()).collect();
    Ok((packages, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_non_registry_sections_and_bundler_version() {
        let input = "PATH\n  specs:\n    local (1.0.0)\n\nGIT\n  specs:\n    gitgem (2.0.0)\n\nGEM\n  specs:\n    rack (2.2.8)\n\nBUNDLED WITH\n   2.4.10\n";
        let packages = parse_gemfile_lock(input).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "rack");
    }

    #[test]
    fn chooses_ruby_variant_over_foreign_platform() {
        let input = "GEM\n  specs:\n    ffi (1.0.0-x86_64-linux)\n    ffi (1.0.1)\n\nPLATFORMS\n  ruby\n  x86_64-linux\n";
        let packages = parse_gemfile_lock(input).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "ffi");
        // Prefer ruby/no-platform (1.0.1) when host platform is not linux x86_64,
        // or host match when it is. Either way version must be stripped.
        assert!(
            packages[0].version == "1.0.1" || packages[0].version == "1.0.0",
            "unexpected version {}",
            packages[0].version
        );
        assert!(!packages[0].version.contains("linux"));
    }

    #[test]
    fn strips_longest_platform_suffix_first() {
        let input = "GEM\n  specs:\n    nokogiri (1.15.5-x86_64-linux)\n\nPLATFORMS\n  linux\n  x86_64-linux\n";
        let packages = parse_gemfile_lock(input).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].version, "1.15.5");
    }

    #[test]
    fn accepts_tab_indented_specs_and_skips_requirements() {
        let input = "GEM\n\tspecs:\n\track (2.2.8)\n\t\track-session (>= 0)\n";
        let packages = parse_gemfile_lock(input).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "rack");
        assert_eq!(packages[0].version, "2.2.8");
        assert!(!packages.iter().any(|p| p.name == "rack-session"));
    }
}
