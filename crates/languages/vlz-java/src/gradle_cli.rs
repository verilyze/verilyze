// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Safe Gradle CLI invocation and output parsing.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use vlz_db::{MAVEN_ECOSYSTEM, Package};
use vlz_manifest_parser::ResolverError;

use crate::coordinate::{maven_package_name, parse_gav_triple};
use crate::gradle_root::find_gradle_root;
use crate::maven_cli::{command_ok, pm_output_text, safe_wrapper};

const GRADLE_WRAPPER_NAMES: &[&str] = &["gradlew", "gradlew.bat"];

const GRADLE_CLASSPATH_CONFIGS: &[&str] = &[
    "runtimeClasspath",
    "compileClasspath",
    "testRuntimeClasspath",
];

pub fn gradle_on_path() -> bool {
    command_ok("gradle", &["--version"])
}

pub fn safe_gradle_wrapper(
    project_dir: &Path,
    scan_root: &Path,
) -> Option<PathBuf> {
    let root = find_gradle_root(project_dir, Some(scan_root));
    safe_wrapper(&root, scan_root, GRADLE_WRAPPER_NAMES)
}

pub fn gradle_pm_hint() -> &'static str {
    #[cfg(target_os = "linux")]
    return "Install Gradle via: apt-get install gradle (Debian/Ubuntu) or sdk install gradle.";
    #[cfg(target_os = "macos")]
    return "Install Gradle via: brew install gradle.";
    #[cfg(target_os = "windows")]
    return "Install Gradle from https://gradle.org/install/ and add gradle to PATH.";
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )))]
    return "Install Gradle for your platform.";
}

/// Parse Gradle `dependencies` tree output for `group:artifact:version` coordinates.
pub fn parse_gradle_dependencies_output(content: &str) -> Vec<Package> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        for token in trimmed.split_whitespace() {
            let token =
                token.trim_start_matches("+---").trim_start_matches("\\---");
            if let Some((g, a, v)) =
                parse_gav_triple(token.trim_matches(|c| c == '(' || c == ')'))
                && !v.is_empty()
            {
                let name = maven_package_name(&g, &a);
                let key = format!("{name}:{v}");
                if seen.insert(key) {
                    out.push(Package {
                        name,
                        version: v,
                        ecosystem: Some(MAVEN_ECOSYSTEM.to_string()),
                    });
                }
            }
        }
    }
    out
}

fn merge_packages(into: &mut Vec<Package>, more: Vec<Package>) {
    let mut seen: HashSet<String> = into
        .iter()
        .map(|p| format!("{}:{}", p.name, p.version))
        .collect();
    for pkg in more {
        let key = format!("{}:{}", pkg.name, pkg.version);
        if seen.insert(key) {
            into.push(pkg);
        }
    }
}

async fn run_gradle_dependencies_for_config(
    gradle_bin: &Path,
    project_dir: &Path,
    subproject: Option<&str>,
    configuration: &str,
) -> Result<Vec<Package>, ResolverError> {
    let mut args = vec!["-q".to_string()];
    let task = match subproject {
        Some(sp) => format!(":{sp}:dependencies"),
        None => "dependencies".to_string(),
    };
    args.push(task);
    args.push("--configuration".to_string());
    args.push(configuration.to_string());

    let output = tokio::process::Command::new(gradle_bin)
        .current_dir(project_dir)
        .args(&args)
        .output()
        .await?;
    if !output.status.success() {
        return Err(ResolverError::Resolve(format!(
            "gradle dependencies ({configuration}) failed with status {}",
            output.status
        )));
    }
    let stdout = pm_output_text(&output.stdout, &output.stderr)?;
    Ok(parse_gradle_dependencies_output(&stdout))
}

pub async fn run_gradle_dependencies(
    gradle_bin: &Path,
    project_dir: &Path,
    subproject: Option<&str>,
) -> Result<Vec<Package>, ResolverError> {
    let mut packages = Vec::new();
    for config in GRADLE_CLASSPATH_CONFIGS {
        match run_gradle_dependencies_for_config(
            gradle_bin,
            project_dir,
            subproject,
            config,
        )
        .await
        {
            Ok(found) => merge_packages(&mut packages, found),
            Err(_) => continue,
        }
    }
    if packages.is_empty() {
        return Err(ResolverError::Resolve(
            "gradle dependencies produced no packages".into(),
        ));
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tree_line() {
        let content = "+--- com.google.guava:guava:33.0.0-jre\n";
        let pkgs = parse_gradle_dependencies_output(content);
        assert_eq!(pkgs[0].name, "com.google.guava:guava");
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
    async fn run_gradle_dependencies_with_fake_gradle() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("settings.gradle"),
            "rootProject.name = 'p'\n",
        )
        .unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let gradle = bin.join("gradle");
        write_executable(
            &gradle,
            "#!/bin/sh\n\
             echo '+--- com.example:app:1.0'\n",
        );
        let pkgs = run_gradle_dependencies(&gradle, &project, None)
            .await
            .unwrap();
        assert!(pkgs.iter().any(|p| p.name == "com.example:app"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn run_gradle_dependencies_errors_when_all_configs_fail() {
        let dir = tempfile::tempdir().unwrap();
        let project = dir.path().join("proj");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(
            project.join("settings.gradle"),
            "rootProject.name = 'p'\n",
        )
        .unwrap();
        let gradle = project.join("gradle");
        write_executable(
            &gradle,
            "#!/bin/sh\n\
             exit 1\n",
        );
        let err = run_gradle_dependencies(&gradle, &project, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("no packages"));
    }
}
