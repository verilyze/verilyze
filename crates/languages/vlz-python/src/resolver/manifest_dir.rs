// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::{Path, PathBuf};

/// How FR-023 pip fallback should install dependencies for a manifest file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipInstallStrategy {
    /// `pip install <project_dir>` (directory containing the manifest).
    InstallProjectDirectory,
    /// `pip install -r <manifest_path>`.
    InstallRequirementsFile,
}

/// Returns the project directory containing the manifest (parent of `manifest_path`).
/// FR-023 uses this as the install target for `setup.py`, `pyproject.toml`, and `setup.cfg`.
pub fn find_manifest_project_dir(manifest_path: &Path) -> Option<PathBuf> {
    manifest_path.parent().map(|p| p.to_path_buf())
}

/// Select the pip install strategy for a manifest path (FR-023 hook; no subprocess here).
pub fn pip_install_strategy(manifest_path: &Path) -> PipInstallStrategy {
    let name = manifest_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    match name {
        "requirements.txt" => PipInstallStrategy::InstallRequirementsFile,
        // Pipfile may need pipenv later; treat as project-directory install for now.
        "setup.py" | "pyproject.toml" | "setup.cfg" | "Pipfile" => {
            PipInstallStrategy::InstallProjectDirectory
        }
        _ => PipInstallStrategy::InstallProjectDirectory,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn find_manifest_project_dir_returns_parent() {
        let path = PathBuf::from("/proj/sub/setup.py");
        let dir = find_manifest_project_dir(&path);
        assert_eq!(dir.as_deref(), Some(Path::new("/proj/sub")));
    }

    #[test]
    fn pip_install_strategy_setup_py_uses_project_directory() {
        let path = PathBuf::from("/proj/setup.py");
        assert_eq!(
            pip_install_strategy(&path),
            PipInstallStrategy::InstallProjectDirectory
        );
    }

    #[test]
    fn pip_install_strategy_pyproject_uses_project_directory() {
        let path = PathBuf::from("/proj/pyproject.toml");
        assert_eq!(
            pip_install_strategy(&path),
            PipInstallStrategy::InstallProjectDirectory
        );
    }

    #[test]
    fn pip_install_strategy_setup_cfg_uses_project_directory() {
        let path = PathBuf::from("/proj/setup.cfg");
        assert_eq!(
            pip_install_strategy(&path),
            PipInstallStrategy::InstallProjectDirectory
        );
    }

    #[test]
    fn pip_install_strategy_pipfile_uses_project_directory() {
        let path = PathBuf::from("/proj/Pipfile");
        assert_eq!(
            pip_install_strategy(&path),
            PipInstallStrategy::InstallProjectDirectory
        );
    }

    #[test]
    fn pip_install_strategy_requirements_txt_uses_requirements_file() {
        let path = PathBuf::from("/proj/requirements.txt");
        assert_eq!(
            pip_install_strategy(&path),
            PipInstallStrategy::InstallRequirementsFile
        );
    }
}
