// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod parser;
mod reachability;
mod resolver;

pub use finder::{PYTHON_MANIFEST_NAMES, PythonManifestFinder};
pub use parser::{
    RequirementsTxtParser, parse_pipfile, parse_pyproject_toml,
    parse_requirements_txt, parse_setup_cfg, parse_setup_py,
};
pub use reachability::PythonTierBAnalyzer;
pub use resolver::{
    DIRECT_ONLY_REASON_EXEC_DISABLED, DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE,
    DIRECT_ONLY_REASON_OFFLINE, DirectOnlyResolver,
    FR_022_TRANSITIVE_ERROR_MESSAGE, PipInstallStrategy, find_lock_file,
    find_manifest_project_dir, parse_lock_file, parse_pip_freeze,
    pip_install_strategy,
};
