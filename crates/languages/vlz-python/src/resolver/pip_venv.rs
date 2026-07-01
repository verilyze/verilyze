// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Ephemeral venv + pip install + pip freeze fallback (FR-023, explicit opt-in only).

use std::path::{Path, PathBuf};

use vlz_manifest_parser::{ResolveContext, ResolverError};

use super::ephemeral_venv::create_ephemeral_venv_dir;
use super::manifest_dir::{PipInstallStrategy, pip_install_strategy};
use super::pip_freeze::parse_pip_freeze;

/// Build argv for `pip install` inside an ephemeral venv (testable without subprocess).
pub fn build_pip_install_args(
    strategy: PipInstallStrategy,
    manifest_path: &Path,
    project_dir: &Path,
) -> Vec<String> {
    match strategy {
        PipInstallStrategy::InstallRequirementsFile => vec![
            "install".to_string(),
            "--no-cache-dir".to_string(),
            "-r".to_string(),
            manifest_path.to_string_lossy().into_owned(),
        ],
        PipInstallStrategy::InstallProjectDirectory => vec![
            "install".to_string(),
            "--no-cache-dir".to_string(),
            project_dir.to_string_lossy().into_owned(),
        ],
    }
}

fn find_python_binary() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|&cmd| {
        std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn venv_pip_path(venv_dir: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        venv_dir.join("Scripts").join("pip.exe")
    }
    #[cfg(not(windows))]
    {
        venv_dir.join("bin").join("pip")
    }
}

fn pip_env(venv_dir: &Path) -> std::collections::HashMap<String, String> {
    let mut env: std::collections::HashMap<String, String> =
        std::env::vars().collect();
    env.insert("PIP_NO_CACHE_DIR".to_string(), "1".to_string());
    env.insert(
        "VIRTUAL_ENV".to_string(),
        venv_dir.to_string_lossy().into_owned(),
    );
    env.remove("PYTHONUSERBASE");
    env
}

/// Create ephemeral venv, install deps, run `pip freeze` (SEC-023 opt-in only).
pub fn run_pip_venv_freeze(
    manifest_path: &Path,
    project_dir: &Path,
    ctx: &ResolveContext,
) -> Result<Vec<vlz_db::Package>, ResolverError> {
    if !ctx.allow_dependency_code_execution {
        return Err(ResolverError::Resolve(
            "pip install fallback requires allow_dependency_code_execution"
                .to_string(),
        ));
    }
    if ctx.skip_pip_resolution {
        return Err(ResolverError::Resolve("pip venv skipped".to_string()));
    }
    let python = find_python_binary().ok_or_else(|| {
        ResolverError::Resolve(
            "python interpreter not found on PATH".to_string(),
        )
    })?;
    let temp_dir = create_ephemeral_venv_dir().map_err(ResolverError::Io)?;
    let venv_path = temp_dir.path().to_path_buf();
    let venv_status = std::process::Command::new(python)
        .args(["-m", "venv"])
        .arg(&venv_path)
        .status()
        .map_err(ResolverError::Io)?;
    if !venv_status.success() {
        return Err(ResolverError::Resolve(format!(
            "python -m venv failed for {}",
            manifest_path.display()
        )));
    }
    let pip_path = venv_pip_path(&venv_path);
    let strategy = pip_install_strategy(manifest_path);
    let install_args =
        build_pip_install_args(strategy, manifest_path, project_dir);
    let mut install_cmd = std::process::Command::new(&pip_path);
    install_cmd.args(&install_args).envs(pip_env(&venv_path));
    if strategy == PipInstallStrategy::InstallProjectDirectory {
        install_cmd.current_dir(project_dir);
    }
    let install_out = install_cmd.output().map_err(ResolverError::Io)?;
    if !install_out.status.success() {
        return Err(ResolverError::Resolve(format!(
            "pip install failed for {}",
            manifest_path.display()
        )));
    }
    let freeze_out = std::process::Command::new(&pip_path)
        .arg("freeze")
        .envs(pip_env(&venv_path))
        .output()
        .map_err(ResolverError::Io)?;
    if !freeze_out.status.success() {
        return Err(ResolverError::Resolve(format!(
            "pip freeze failed for {}",
            manifest_path.display()
        )));
    }
    let stdout = String::from_utf8_lossy(&freeze_out.stdout);
    let packages = parse_pip_freeze(&stdout)?;
    if packages.is_empty() {
        return Err(ResolverError::Resolve(
            "pip freeze produced no packages".to_string(),
        ));
    }
    if ctx.keep_ephemeral_venv {
        let _kept = temp_dir.keep();
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn build_pip_install_args_requirements_file() {
        let manifest = PathBuf::from("/proj/requirements.txt");
        let project = PathBuf::from("/proj");
        let args = build_pip_install_args(
            PipInstallStrategy::InstallRequirementsFile,
            &manifest,
            &project,
        );
        assert!(args.contains(&"-r".to_string()));
        assert!(args.contains(&"--no-cache-dir".to_string()));
    }

    #[test]
    fn build_pip_install_args_project_directory() {
        let manifest = PathBuf::from("/proj/setup.py");
        let project = PathBuf::from("/proj");
        let args = build_pip_install_args(
            PipInstallStrategy::InstallProjectDirectory,
            &manifest,
            &project,
        );
        assert!(args.iter().any(|a| a.contains("/proj")));
    }
}
