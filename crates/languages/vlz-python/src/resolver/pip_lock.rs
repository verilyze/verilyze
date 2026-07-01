// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Run `pip lock` and parse pylock.toml stdout (FR-022 primary pip path).

use std::path::Path;

use vlz_manifest_parser::{ResolveContext, ResolverError};

use super::lock_parser::parse_pylock_toml;
use super::manifest_dir::{PipInstallStrategy, pip_install_strategy};
use super::pip_version::{detect_pip_version, pip_version_supports_lock};
use crate::resolver::python_package_manager_available;

/// `--only-binary :all:` flag for secure-default pip lock (SEC-023).
pub const PIP_LOCK_ONLY_BINARY_ALL: &str = ":all:";

/// Returns true when the manifest basename is `Pipfile` (pip lock unsupported).
pub fn manifest_is_pipfile(manifest_path: &Path) -> bool {
    manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "Pipfile")
}

/// Returns true when the manifest basename is `requirements.txt`.
pub fn manifest_is_requirements_txt(manifest_path: &Path) -> bool {
    manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n == "requirements.txt")
}

/// Returns true for local project manifests that may execute build code during resolution.
#[allow(dead_code)]
pub fn manifest_is_local_project(manifest_path: &Path) -> bool {
    manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| {
            matches!(n, "setup.py" | "pyproject.toml" | "setup.cfg")
        })
}

/// Build argv for `pip lock` (testable without subprocess).
pub fn build_pip_lock_args(
    strategy: PipInstallStrategy,
    manifest_path: &Path,
    project_dir: &Path,
    allow_execution: bool,
) -> Option<Vec<String>> {
    if manifest_is_pipfile(manifest_path) {
        return None;
    }
    match strategy {
        PipInstallStrategy::InstallRequirementsFile => {
            let mut args = vec![
                "lock".to_string(),
                "-r".to_string(),
                manifest_path.to_string_lossy().into_owned(),
                "-o".to_string(),
                "-".to_string(),
            ];
            if !allow_execution {
                args.push("--only-binary".to_string());
                args.push(PIP_LOCK_ONLY_BINARY_ALL.to_string());
            }
            Some(args)
        }
        PipInstallStrategy::InstallProjectDirectory => {
            if !allow_execution {
                return None;
            }
            Some(vec![
                "lock".to_string(),
                "-e".to_string(),
                project_dir.to_string_lossy().into_owned(),
                "-o".to_string(),
                "-".to_string(),
            ])
        }
    }
}

fn find_pip_binary() -> Option<&'static str> {
    ["pip3", "pip"].into_iter().find(|&cmd| {
        std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn pip_lock_env() -> std::collections::HashMap<String, String> {
    let mut env: std::collections::HashMap<String, String> =
        std::env::vars().collect();
    env.insert("PIP_NO_CACHE_DIR".to_string(), "1".to_string());
    env.remove("PYTHONUSERBASE");
    env
}

/// Run `pip lock` when policy allows; parse stdout as pylock.toml.
pub fn run_pip_lock(
    manifest_path: &Path,
    project_dir: &Path,
    ctx: &ResolveContext,
) -> Result<Vec<vlz_db::Package>, ResolverError> {
    if ctx.skip_pip_resolution || !python_package_manager_available() {
        return Err(ResolverError::Resolve("pip lock skipped".to_string()));
    }
    if manifest_is_pipfile(manifest_path) {
        return Err(ResolverError::Resolve(
            "pip lock unsupported for Pipfile".to_string(),
        ));
    }
    let version = detect_pip_version();
    if !version
        .map(|(maj, min)| pip_version_supports_lock(maj, min))
        .unwrap_or(false)
    {
        return Err(ResolverError::Resolve(
            "pip lock requires pip >= 25.1".to_string(),
        ));
    }
    let strategy = pip_install_strategy(manifest_path);
    let args = build_pip_lock_args(
        strategy,
        manifest_path,
        project_dir,
        ctx.allow_dependency_code_execution,
    )
    .ok_or_else(|| {
        ResolverError::Resolve(
            "pip lock not permitted for this manifest".to_string(),
        )
    })?;
    let pip = find_pip_binary().ok_or_else(|| {
        ResolverError::Resolve("pip not found on PATH".to_string())
    })?;
    let mut cmd = std::process::Command::new(pip);
    cmd.args(&args).envs(pip_lock_env());
    if strategy == PipInstallStrategy::InstallProjectDirectory {
        cmd.current_dir(project_dir);
    }
    let output = cmd.output().map_err(ResolverError::Io)?;
    if !output.status.success() {
        return Err(ResolverError::Resolve(format!(
            "pip lock failed for {}",
            manifest_path.display()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Err(ResolverError::Resolve(
            "pip lock produced empty output".to_string(),
        ));
    }
    let packages = parse_pylock_toml(&stdout).map_err(|e| {
        ResolverError::Resolve(format!("pip lock pylock parse: {e}"))
    })?;
    if packages.is_empty() {
        return Err(ResolverError::Resolve(
            "pip lock produced no packages".to_string(),
        ));
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_pip_lock_args_safe_requirements_uses_only_binary() {
        let manifest = PathBuf::from("/proj/requirements.txt");
        let project = PathBuf::from("/proj");
        let args = build_pip_lock_args(
            PipInstallStrategy::InstallRequirementsFile,
            &manifest,
            &project,
            false,
        )
        .unwrap();
        assert!(args.contains(&"-r".to_string()));
        assert!(args.contains(&"--only-binary".to_string()));
        assert!(args.contains(&":all:".to_string()));
    }

    #[test]
    fn build_pip_lock_args_executable_requirements_no_only_binary() {
        let manifest = PathBuf::from("/proj/requirements.txt");
        let project = PathBuf::from("/proj");
        let args = build_pip_lock_args(
            PipInstallStrategy::InstallRequirementsFile,
            &manifest,
            &project,
            true,
        )
        .unwrap();
        assert!(!args.contains(&"--only-binary".to_string()));
    }

    #[test]
    fn build_pip_lock_args_safe_local_project_returns_none() {
        let manifest = PathBuf::from("/proj/setup.py");
        let project = PathBuf::from("/proj");
        assert!(
            build_pip_lock_args(
                PipInstallStrategy::InstallProjectDirectory,
                &manifest,
                &project,
                false,
            )
            .is_none()
        );
    }

    #[test]
    fn build_pip_lock_args_executable_local_project_uses_editable() {
        let manifest = PathBuf::from("/proj/pyproject.toml");
        let project = PathBuf::from("/proj");
        let args = build_pip_lock_args(
            PipInstallStrategy::InstallProjectDirectory,
            &manifest,
            &project,
            true,
        )
        .unwrap();
        assert!(args.contains(&"-e".to_string()));
    }

    #[test]
    fn build_pip_lock_args_pipfile_returns_none() {
        let manifest = PathBuf::from("/proj/Pipfile");
        let project = PathBuf::from("/proj");
        assert!(
            build_pip_lock_args(
                PipInstallStrategy::InstallProjectDirectory,
                &manifest,
                &project,
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn manifest_type_helpers() {
        assert!(manifest_is_requirements_txt(Path::new(
            "/a/requirements.txt"
        )));
        assert!(manifest_is_pipfile(Path::new("/a/Pipfile")));
        assert!(manifest_is_local_project(Path::new("/a/setup.py")));
        assert!(!manifest_is_local_project(Path::new("/a/requirements.txt")));
    }
}
