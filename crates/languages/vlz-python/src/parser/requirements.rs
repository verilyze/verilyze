// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::pep508::parse_pep508_dependency;
use std::path::{Path, PathBuf};
use vlz_db::DeclarationKind;
use vlz_manifest_parser::{ParsedDependency, ParserError};

/// Actionable hint for invalid requirement lines (NFR-018, SEC-008).
pub const REQUIREMENTS_PARSE_LINE_HINT: &str = "invalid requirement syntax; use \
    PEP 508 operators (==, >=, <=, ~=, !=, >, <, ===)";

/// Format a parse error for a requirements.txt line without echoing line content.
pub fn format_requirements_line_error(line: u32) -> String {
    format!("line {line}: {REQUIREMENTS_PARSE_LINE_HINT}")
}

/// Parse requirements.txt with declaration line metadata.
pub fn parse_requirements_txt_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    let mut parsed = Vec::new();
    for (i, line) in content.lines().enumerate() {
        let start_line = (i + 1) as u32;
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if is_requirement_directive(trimmed) {
            continue;
        }
        match parse_requirement_line(trimmed) {
            Some(pkg) => parsed.push(ParsedDependency {
                package: pkg,
                path: path.to_path_buf(),
                start_line,
                end_line: None,
                kind: DeclarationKind::Manifest,
            }),
            None => {
                return Err(ParserError::Parse(
                    format_requirements_line_error(start_line),
                ));
            }
        }
    }
    Ok(parsed)
}

/// Parse requirements.txt content into a list of packages (name, version).
/// Skips comments, empty lines, and directive lines (-r, -e, etc.).
/// Version: exact from `==`, first version from `>=`/`<=`/`~=`, else `"any"`.
/// Public for fuzzing (NFR-020).
pub fn parse_requirements_txt(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ParserError> {
    Ok(parse_requirements_txt_with_declarations(
        content,
        Path::new("requirements.txt"),
    )?
    .into_iter()
    .map(|dep| dep.package)
    .collect())
}

/// Maximum nesting depth for `-r` / `--requirement` includes (NFR-022 robustness).
pub const MAX_REQUIREMENT_INCLUDE_DEPTH: u32 = 16;

/// True when the line is a pip requirements-file directive, not a package spec.
fn is_requirement_directive(trimmed: &str) -> bool {
    trimmed.starts_with("-r ")
        || trimmed.starts_with("-e ")
        || trimmed.starts_with("-c ")
        || trimmed.starts_with("--")
        || trimmed.starts_with("-f ")
        || trimmed.starts_with("-i ")
}

/// Extract the referenced path from a `-r` / `--requirement` directive line.
/// Returns None for `-c` / `--constraint` and other directives; those are not
/// followed because constraint files bound versions rather than declare
/// installed distributions.
fn requirement_include_target(line: &str) -> Option<String> {
    let line = line.trim();
    if let Some(rest) = line.strip_prefix("-r ") {
        return Some(rest.trim().to_string());
    }
    if let Some(rest) = line.strip_prefix("--requirement ") {
        return Some(rest.trim().to_string());
    }
    if let Some(rest) = line.strip_prefix("--requirement=") {
        return Some(rest.trim().to_string());
    }
    None
}

/// Parse a requirements.txt manifest, following `-r` / `--requirement` includes
/// relative to each file's directory. Includes are confined under the manifest's
/// directory: `..`, absolute paths, and symlinks escaping the directory are not
/// followed. Cycles and depth overflows stop recursion without failing the parse.
/// Missing or unresolvable includes are skipped so the remaining dependencies still
/// resolve. Each parsed dependency carries the path of the file it came from.
pub async fn parse_requirements_txt_with_includes(
    manifest: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    let ceiling = match std::fs::canonicalize(
        manifest.parent().unwrap_or(Path::new("")),
    ) {
        Ok(c) => c,
        Err(_) => {
            let content = tokio::fs::read_to_string(manifest).await?;
            return parse_requirements_txt_with_declarations(
                &content, manifest,
            );
        }
    };
    let mut visited: std::collections::HashSet<PathBuf> =
        std::collections::HashSet::new();
    let mut out = Vec::new();
    Box::pin(parse_requirements_includes(
        manifest,
        &ceiling,
        0,
        &mut visited,
        &mut out,
    ))
    .await?;
    Ok(out)
}

fn parse_requirements_includes<'a>(
    file: &'a Path,
    ceiling: &'a Path,
    depth: u32,
    visited: &'a mut std::collections::HashSet<PathBuf>,
    out: &'a mut Vec<ParsedDependency>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<(), ParserError>> + Send + 'a>,
> {
    Box::pin(async move {
        let canon = match std::fs::canonicalize(file) {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        if !canon.starts_with(ceiling) {
            return Ok(());
        }
        if !visited.insert(canon.clone()) {
            return Ok(());
        }
        let content = match tokio::fs::read_to_string(&canon).await {
            Ok(c) => c,
            Err(_) => return Ok(()),
        };
        let parsed =
            parse_requirements_txt_with_declarations(&content, &canon)?;
        out.extend(parsed);
        if depth >= MAX_REQUIREMENT_INCLUDE_DEPTH {
            return Ok(());
        }
        let file_dir = canon.parent().unwrap_or(Path::new(""));
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(target) = requirement_include_target(trimmed) {
                let target_path = file_dir.join(&target);
                parse_requirements_includes(
                    &target_path,
                    ceiling,
                    depth + 1,
                    visited,
                    out,
                )
                .await?;
            }
        }
        Ok(())
    })
}

/// Parse a single requirement line into Package (name, version), or None if unparseable.
fn parse_requirement_line(line: &str) -> Option<vlz_db::Package> {
    let line = line
        .find('#')
        .map(|i| line[..i].trim())
        .unwrap_or(line)
        .trim();
    if line.is_empty() || line == "[]" {
        return None;
    }
    parse_pep508_dependency(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requirements_txt_with_declarations_records_lines() {
        let content = "# comment\nfoo==1.0\n\nbar>=2.0\n";
        let deps = parse_requirements_txt_with_declarations(
            content,
            std::path::Path::new("requirements.txt"),
        )
        .unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].start_line, 2);
        assert_eq!(deps[1].start_line, 4);
    }

    #[test]
    fn parse_requirement_line_strips_extras() {
        let pkg = parse_requirement_line("foo[dev]==1.0").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_requirement_line_skips_empty_after_comment() {
        assert!(parse_requirement_line("  # x").is_none());
    }

    #[test]
    fn parse_requirement_line_skips_empty_name() {
        assert!(parse_requirement_line("==1.0").is_none());
    }

    #[test]
    fn parse_requirement_line_skips_brackets_only() {
        assert!(parse_requirement_line("[]").is_none());
    }

    #[test]
    fn parse_requirements_txt_skips_double_dash_directive() {
        let content =
            "foo==1.0\n--extra-index-url https://pypi.org\nbar>=2.0\n";
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[1].name, "bar");
    }

    #[test]
    fn parse_requirements_txt_skips_constraint_directive() {
        let content = "foo==1.0\n-c constraints.txt\nbar>=2.0\n";
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn parse_requirements_txt_rejects_lone_equals() {
        let err = parse_requirements_txt("foo=1.0\n").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("line 1"));
        assert!(msg.contains("PEP 508"));
        assert!(!msg.contains("foo=1.0"));
    }

    #[test]
    fn parse_requirements_txt_all_operators() {
        let content = "\
pkg==1.0\n\
arbitrary===1.0.0\n\
a~=2.0\n\
b!=3.0\n\
c>=4.0\n\
d<=5.0\n\
e>6.0\n\
f<7.0\n";
        let packages = parse_requirements_txt(content).unwrap();
        assert_eq!(packages.len(), 8);
        assert_eq!(packages[0].version, "1.0");
        assert_eq!(packages[1].version, "1.0.0");
        assert_eq!(packages[4].version, "4.0");
    }

    #[test]
    fn format_requirements_line_error_omits_line_content() {
        let msg = format_requirements_line_error(3);
        assert!(msg.contains("line 3"));
        assert!(msg.contains("PEP 508"));
    }

    fn block_on<F>(future: F)
    where
        F: std::future::Future<Output = ()>,
    {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(future);
    }

    #[test]
    fn requirement_include_target_short_form() {
        assert_eq!(
            requirement_include_target("-r sub.txt"),
            Some("sub.txt".to_string())
        );
        assert_eq!(
            requirement_include_target("  -r   sub.txt  "),
            Some("sub.txt".to_string())
        );
    }

    #[test]
    fn requirement_include_target_long_form() {
        assert_eq!(
            requirement_include_target("--requirement sub.txt"),
            Some("sub.txt".to_string())
        );
        assert_eq!(
            requirement_include_target("--requirement=sub.txt"),
            Some("sub.txt".to_string())
        );
    }

    #[test]
    fn requirement_include_target_rejects_constraint_directive() {
        assert_eq!(requirement_include_target("-c constraints.txt"), None);
        assert_eq!(requirement_include_target("--constraint=x"), None);
    }

    #[test]
    fn parse_requirements_with_includes_follows_nested_include() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        let sub = dir.path().join("base.txt");
        std::fs::write(&root, "foo==1.0\n-r base.txt\n").unwrap();
        std::fs::write(&sub, "bar==2.0\n").unwrap();
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            let names: Vec<&str> =
                deps.iter().map(|d| d.package.name.as_str()).collect();
            assert!(names.contains(&"foo"));
            assert!(names.contains(&"bar"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_supports_long_form() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        let sub = dir.path().join("base.txt");
        std::fs::write(&root, "foo==1.0\n--requirement base.txt\n").unwrap();
        std::fs::write(&sub, "bar==2.0\n").unwrap();
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            assert!(deps.iter().any(|d| d.package.name == "bar"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_rejects_parent_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        let secret = outside.path().join("secret.txt");
        std::fs::write(&root, "foo==1.0\n-r ../secret.txt\n").unwrap();
        std::fs::write(&secret, "stolen==9.9\n").unwrap();
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            let names: Vec<&str> =
                deps.iter().map(|d| d.package.name.as_str()).collect();
            assert!(names.contains(&"foo"));
            assert!(!names.contains(&"stolen"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_rejects_absolute_path() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        let secret = outside.path().join("secret.txt");
        std::fs::write(&secret, "abs==1.0\n").unwrap();
        let abs_arg = secret.to_string_lossy().to_string();
        std::fs::write(&root, format!("foo==1.0\n-r {abs_arg}\n")).unwrap();
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            let names: Vec<&str> =
                deps.iter().map(|d| d.package.name.as_str()).collect();
            assert!(names.contains(&"foo"));
            assert!(!names.contains(&"abs"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_rejects_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, "a==1.0\n-r b.txt\n").unwrap();
        std::fs::write(&b, "b==2.0\n-r a.txt\n").unwrap();
        block_on(async {
            let deps = parse_requirements_txt_with_includes(&a).await.unwrap();
            let names: Vec<&str> =
                deps.iter().map(|d| d.package.name.as_str()).collect();
            assert!(names.contains(&"a"));
            assert!(names.contains(&"b"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_skips_missing_include() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        std::fs::write(&root, "foo==1.0\n-r missing.txt\n").unwrap();
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            let names: Vec<&str> =
                deps.iter().map(|d| d.package.name.as_str()).collect();
            assert!(names.contains(&"foo"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_skips_constraint_directive() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("requirements.txt");
        let constraints = dir.path().join("constraints.txt");
        std::fs::write(&root, "foo==1.0\n-c constraints.txt\n").unwrap();
        std::fs::write(&constraints, "bar==2.0\n").unwrap();
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            let names: Vec<&str> =
                deps.iter().map(|d| d.package.name.as_str()).collect();
            assert!(names.contains(&"foo"));
            assert!(!names.contains(&"bar"));
        });
    }

    #[test]
    fn parse_requirements_with_includes_caps_depth() {
        let dir = tempfile::tempdir().unwrap();
        // Build a chain longer than MAX_REQUIREMENT_INCLUDE_DEPTH.
        let depth = (MAX_REQUIREMENT_INCLUDE_DEPTH + 2) as usize;
        for i in 0..depth {
            let name = if i == 0 {
                "requirements.txt".to_string()
            } else {
                format!("lvl{i}.txt")
            };
            let next = if i + 1 < depth {
                format!("-r lvl{}.txt", i + 1)
            } else {
                String::new()
            };
            let content = format!("pkg{i}=={i}.0\n{next}\n");
            std::fs::write(dir.path().join(&name), content).unwrap();
        }
        let root = dir.path().join("requirements.txt");
        block_on(async {
            let deps =
                parse_requirements_txt_with_includes(&root).await.unwrap();
            // The chain is deeper than the cap; we still get at least the
            // root package plus every package within the depth budget.
            assert!(deps.iter().any(|d| d.package.name == "pkg0"));
            assert!(deps.len() <= depth);
        });
    }
}
