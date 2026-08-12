// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Safe Maven CLI invocation and output parsing.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use vlz_db::{MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::ResolverError;

use crate::coordinate::maven_package_name;

const MVN_WRAPPER_NAMES: &[&str] = &["mvnw", "mvnw.cmd"];

/// Maximum combined stdout/stderr from package manager subprocesses.
pub const PM_MAX_OUTPUT_BYTES: usize = 10 * 1024 * 1024;

const MVN_LIST_SCOPES: &[Option<&str>] = &[None, Some("test")];

/// Resolve a safe wrapper path under `project_dir` within `scan_root`.
pub fn safe_mvn_wrapper(
    project_dir: &Path,
    scan_root: &Path,
) -> Option<PathBuf> {
    safe_wrapper(project_dir, scan_root, MVN_WRAPPER_NAMES)
}

pub fn safe_wrapper(
    project_dir: &Path,
    scan_root: &Path,
    names: &[&str],
) -> Option<PathBuf> {
    let project = std::fs::canonicalize(project_dir).ok()?;
    let root = std::fs::canonicalize(scan_root).ok()?;
    for name in names {
        let candidate = project_dir.join(name);
        if !candidate.is_file() {
            continue;
        }
        let abs = std::fs::canonicalize(&candidate).ok()?;
        if abs.starts_with(&root) && abs.starts_with(&project) {
            return Some(abs);
        }
    }
    None
}

pub fn mvn_on_path() -> bool {
    command_ok("mvn", &["--version"])
}

pub fn command_ok(bin: &str, args: &[&str]) -> bool {
    std::process::Command::new(bin)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Parse `mvn dependency:list` / tree style lines into packages.
pub fn parse_mvn_dependency_lines(content: &str) -> Vec<Package> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let group = parts[0];
        let artifact = parts[1];
        let version = parts[3];
        if group.is_empty() || artifact.is_empty() || version.is_empty() {
            continue;
        }
        let name = maven_package_name(group, artifact);
        let key = format!("{name}:{version}");
        if seen.insert(key) {
            out.push(Package {
                name,
                version: version.to_string(),
                ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
            });
        }
    }
    out
}

pub(crate) fn pm_output_text(
    stdout: &[u8],
    stderr: &[u8],
) -> Result<String, ResolverError> {
    let total = stdout.len().saturating_add(stderr.len());
    if total > PM_MAX_OUTPUT_BYTES {
        return Err(ResolverError::Resolve(format!(
            "package manager output exceeded {PM_MAX_OUTPUT_BYTES} bytes"
        )));
    }
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    Ok(format!("{stdout}\n{stderr}"))
}

fn merge_packages(into: &mut Vec<Package>, mut more: Vec<Package>) {
    let mut seen: HashSet<String> = into
        .iter()
        .map(|p| format!("{}:{}", p.name, p.version))
        .collect();
    for pkg in more.drain(..) {
        let key = format!("{}:{}", pkg.name, pkg.version);
        if seen.insert(key) {
            into.push(pkg);
        }
    }
}

pub fn maven_pm_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install Maven via: apt-get install maven (Debian/Ubuntu) or dnf install maven (Fedora).";
    #[cfg(target_os = "macos")]
    return "Install Maven via: brew install maven.";
    #[cfg(target_os = "windows")]
    return "Install Maven from https://maven.apache.org/download.cgi and add mvn to PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Maven (mvn) for your platform.";
}

pub async fn run_mvn_dependency_list(
    mvn_bin: &Path,
    project_dir: &Path,
) -> Result<Vec<Package>, ResolverError> {
    let mut packages = Vec::new();
    for scope in MVN_LIST_SCOPES {
        let mut args = vec![
            "-q".to_string(),
            "dependency:list".to_string(),
            "-DoutputAbsoluteArtifactFilename=false".to_string(),
        ];
        if let Some(s) = scope {
            args.push(format!("-DincludeScope={s}"));
        }
        let output = tokio::process::Command::new(mvn_bin)
            .current_dir(project_dir)
            .args(&args)
            .output()
            .await?;
        if !output.status.success() {
            return Err(ResolverError::Resolve(format!(
                "mvn dependency:list failed with status {}",
                output.status
            )));
        }
        let combined = pm_output_text(&output.stdout, &output.stderr)?;
        merge_packages(&mut packages, parse_mvn_dependency_lines(&combined));
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mvn_list_line() {
        let content = "com.google.guava:guava:jar:33.0.0-jre:compile\n";
        let pkgs = parse_mvn_dependency_lines(content);
        assert_eq!(pkgs[0].name, "com.google.guava:guava");
        assert_eq!(pkgs[0].version, "33.0.0-jre");
    }

    #[test]
    fn wrapper_rejected_outside_scan_root() {
        let dir = tempfile::tempdir().unwrap();
        let scan = dir.path().join("scan");
        std::fs::create_dir_all(&scan).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("mvnw"), "#!/bin/sh\n").unwrap();
        assert!(safe_mvn_wrapper(&outside, &scan).is_none());
    }

    #[test]
    fn wrapper_rejected_outside_project_dir() {
        let dir = tempfile::tempdir().unwrap();
        let scan = dir.path();
        let module = scan.join("module");
        std::fs::create_dir_all(&module).unwrap();
        std::fs::write(scan.join("mvnw"), "#!/bin/sh\n").unwrap();
        assert!(safe_mvn_wrapper(&module, scan).is_none());
    }

    #[test]
    fn pm_output_cap_rejects_oversized() {
        let huge = vec![b'a'; PM_MAX_OUTPUT_BYTES + 1];
        let err = pm_output_text(&huge, &[]).unwrap_err();
        assert!(err.to_string().contains("exceeded"));
    }

    #[cfg(unix)]
    fn write_executable(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_mvn_dependency_list_with_fake_mvn() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let mvn = bin.join("mvn");
        write_executable(
            &mvn,
            "#!/bin/sh\n\
             echo 'com.test:lib:jar:1.0:compile'\n\
             echo 'com.test:testlib:jar:2.0:test'\n",
        );
        let pkgs = run_mvn_dependency_list(&mvn, &project).await.unwrap();
        assert!(pkgs.iter().any(|p| p.name == "com.test:lib"));
        assert!(pkgs.iter().any(|p| p.name == "com.test:testlib"));
    }
}
