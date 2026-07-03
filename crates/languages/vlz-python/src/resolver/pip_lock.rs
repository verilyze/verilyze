// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Run `pip lock` and parse pylock.toml stdout (FR-022 primary pip path).

use std::path::Path;

use vlz_manifest_parser::{ResolveContext, ResolverError};

use super::manifest_dir::{PipInstallStrategy, pip_install_strategy};
use super::pip_version::{detect_pip_version, pip_version_supports_lock};
use crate::parser::parse_pylock_toml;
use crate::resolver::python_package_manager_available;

/// `--only-binary :all:` flag for secure-default pip lock (SEC-023).
pub const PIP_LOCK_ONLY_BINARY_ALL: &str = ":all:";

/// Suppress pip resolver progress on stdout so `-o -` is parseable pylock.toml.
pub const PIP_LOCK_QUIET_FLAG: &str = "-q";

/// Return the pylock.toml body when pip writes resolver progress before the lock file.
pub fn extract_pylock_stdout(stdout: &str) -> &str {
    if let Some(idx) = stdout.find("lock-version") {
        let start = stdout[..idx].rfind('\n').map_or(0, |i| i + 1);
        return stdout[start..].trim_start();
    }
    stdout.trim()
}

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
                PIP_LOCK_QUIET_FLAG.to_string(),
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
                PIP_LOCK_QUIET_FLAG.to_string(),
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

/// Prefer pip `ERROR:` lines; fall back to trimmed stderr, then stdout.
fn summarize_pip_command_output(stderr: &str, stdout: &str) -> String {
    let errors: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("ERROR:"))
        .collect();
    if !errors.is_empty() {
        return errors.join("\n");
    }
    let trimmed_stderr = stderr.trim();
    if !trimmed_stderr.is_empty() {
        return trimmed_stderr.to_string();
    }
    stdout.trim().to_string()
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
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = summarize_pip_command_output(&stderr, &stdout);
        let detail = if detail.is_empty() {
            format!("exit status {}", output.status)
        } else {
            detail
        };
        return Err(ResolverError::Resolve(format!(
            "pip lock failed for {}: {detail}",
            manifest_path.display()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pylock = extract_pylock_stdout(&stdout);
    if pylock.is_empty() {
        return Err(ResolverError::Resolve(
            "pip lock produced empty output".to_string(),
        ));
    }
    let packages = parse_pylock_toml(pylock).map_err(|e| {
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

    use crate::resolver::test_fixtures::{
        empty_path, fake_pip_lock_empty_output, fake_pip_lock_failure,
        fake_pip_lock_no_packages, fake_pip_lock_success, fake_pip_too_old,
    };

    fn default_ctx() -> ResolveContext {
        ResolveContext::default()
    }

    fn exec_ctx() -> ResolveContext {
        ResolveContext {
            allow_dependency_code_execution: true,
            ..Default::default()
        }
    }

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
        assert!(args.contains(&PIP_LOCK_QUIET_FLAG.to_string()));
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

    #[test]
    fn run_pip_lock_skipped_when_offline() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"pkg\n").unwrap();
        let ctx = ResolveContext {
            skip_pip_resolution: true,
            ..Default::default()
        };
        let err = run_pip_lock(&req, dir.path(), &ctx).unwrap_err();
        assert!(err.to_string().contains("pip lock skipped"));
    }

    #[test]
    fn run_pip_lock_rejects_pipfile() {
        let dir = tempfile::tempdir().unwrap();
        let pipfile = dir.path().join("Pipfile");
        std::fs::write(&pipfile, b"").unwrap();
        let err = run_pip_lock(&pipfile, dir.path(), &exec_ctx()).unwrap_err();
        assert!(err.to_string().contains("unsupported for Pipfile"));
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_requires_modern_pip() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"pkg\n").unwrap();
        let fake = fake_pip_too_old();
        fake.with_path(|| {
            let err =
                run_pip_lock(&req, dir.path(), &default_ctx()).unwrap_err();
            assert!(err.to_string().contains("pip lock requires pip >= 25.1"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_local_project_requires_execution_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let setup = dir.path().join("setup.py");
        std::fs::write(&setup, b"from setuptools import setup\nsetup()\n")
            .unwrap();
        let fake = fake_pip_lock_success(
            "[[packages]]\nname = \"demo\"\nversion = \"1.0.0\"\n",
        );
        fake.with_path(|| {
            let err =
                run_pip_lock(&setup, dir.path(), &default_ctx()).unwrap_err();
            assert!(err.to_string().contains("not permitted"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_success_requirements() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests\n").unwrap();
        let fake = fake_pip_lock_success(
            "[[packages]]\nname = \"requests\"\nversion = \"2.31.0\"\n",
        );
        fake.with_path(|| {
            let packages =
                run_pip_lock(&req, dir.path(), &default_ctx()).unwrap();
            assert_eq!(packages.len(), 1);
            assert_eq!(packages[0].name, "requests");
        });
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_success_local_project_with_execution() {
        let dir = tempfile::tempdir().unwrap();
        let setup = dir.path().join("setup.py");
        std::fs::write(&setup, b"from setuptools import setup\nsetup()\n")
            .unwrap();
        let fake = fake_pip_lock_success(
            "[[packages]]\nname = \"demo\"\nversion = \"1.0.0\"\n",
        );
        fake.with_path(|| {
            let packages =
                run_pip_lock(&setup, dir.path(), &exec_ctx()).unwrap();
            assert_eq!(packages[0].name, "demo");
        });
    }

    #[test]
    fn summarize_pip_command_output_prefers_error_lines() {
        let stderr =
            "WARNING: experimental\nERROR: No matching distribution\n";
        assert_eq!(
            summarize_pip_command_output(stderr, ""),
            "ERROR: No matching distribution"
        );
    }

    #[test]
    fn extract_pylock_stdout_strips_pip_resolver_progress() {
        let stdout = "Collecting requests==2.0.1\n  Downloading...\nlock-version = \"1.0\"\n\n[[packages]]\nname = \"requests\"\nversion = \"2.0.1\"\n";
        let pylock = extract_pylock_stdout(stdout);
        assert!(pylock.starts_with("lock-version"));
        let packages = parse_pylock_toml(pylock).unwrap();
        assert_eq!(packages[0].name, "requests");
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_command_failure_includes_stderr() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests\n").unwrap();
        let fake = fake_pip_lock_failure();
        fake.with_path(|| {
            let err =
                run_pip_lock(&req, dir.path(), &default_ctx()).unwrap_err();
            let msg = err.to_string();
            assert!(msg.contains("pip lock failed for"));
            assert!(msg.contains("pip lock failed"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_empty_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests\n").unwrap();
        let fake = fake_pip_lock_empty_output();
        fake.with_path(|| {
            let err =
                run_pip_lock(&req, dir.path(), &default_ctx()).unwrap_err();
            assert!(err.to_string().contains("empty output"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_no_packages_in_output() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests\n").unwrap();
        let fake = fake_pip_lock_no_packages();
        fake.with_path(|| {
            let err =
                run_pip_lock(&req, dir.path(), &default_ctx()).unwrap_err();
            assert!(err.to_string().contains("no packages"));
        });
    }

    #[cfg(unix)]
    #[test]
    fn run_pip_lock_skipped_without_pip_on_path() {
        let dir = tempfile::tempdir().unwrap();
        let req = dir.path().join("requirements.txt");
        std::fs::write(&req, b"requests\n").unwrap();
        let fake = empty_path();
        fake.with_path(|| {
            let err =
                run_pip_lock(&req, dir.path(), &default_ctx()).unwrap_err();
            assert!(err.to_string().contains("pip lock skipped"));
        });
    }
}
