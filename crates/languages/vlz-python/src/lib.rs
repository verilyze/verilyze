// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod lock_names;
mod parser;
mod reachability;
mod resolver;

pub use finder::{PYTHON_MANIFEST_NAMES, PythonManifestFinder};
pub use lock_names::{
    PYTHON_LOCK_FILE_NAMES, filter_orphan_locks, is_pylock_variant,
    is_python_lock_file, manifest_is_lock_file,
    orphan_multi_lock_warning_dirs,
};
pub use parser::{
    RequirementsTxtParser, parse_lock_file, parse_pipfile, parse_pylock_toml,
    parse_pyproject_toml, parse_requirements_txt, parse_setup_cfg,
    parse_setup_py,
};
pub use reachability::PythonTierBAnalyzer;
pub use resolver::{
    DIRECT_ONLY_REASON_EXEC_DISABLED, DIRECT_ONLY_REASON_FALLBACK_ON_FAILURE,
    DIRECT_ONLY_REASON_OFFLINE, DirectOnlyResolver,
    FR_022_TRANSITIVE_ERROR_MESSAGE, PipInstallStrategy, find_lock_file,
    find_lock_files, find_manifest_project_dir, parse_pip_freeze,
    pip_install_strategy,
};
