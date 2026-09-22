// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

mod finder;
mod lock_names;
mod parser;
mod reachability;
mod resolver;

pub use finder::{
    DOTNET_PROJECT_EXTENSIONS, DotnetManifestFinder, PACKAGES_CONFIG_NAME,
    is_dotnet_manifest_name, is_packages_config_name,
};
pub use lock_names::{DOTNET_LOCK_FILE_NAMES, is_dotnet_lock_file};
pub use parser::{
    DOTNET_LOCK_MAX_BYTES, DOTNET_MANIFEST_MAX_BYTES, DotnetManifestParser,
    is_nuget_package_name, load_central_package_versions, parse_csproj,
    parse_csproj_with_declarations, parse_deps_json,
    parse_deps_json_with_declarations, parse_directory_packages_props,
    parse_packages_config, parse_packages_config_with_declarations,
    parse_packages_lock, parse_packages_lock_with_declarations,
    parse_project_assets_json, parse_project_assets_json_with_declarations,
};
pub use reachability::DotnetTierBAnalyzer;
pub use resolver::{
    DotnetResolver, dotnet_package_manager_available,
    dotnet_package_manager_hint, find_dotnet_lock_file,
};
pub use vlz_db::NUGET_ECOSYSTEM;

/// Stable crate identity for coverage and plugin diagnostics.
pub fn dotnet_crate_id() -> &'static str {
    "dotnet"
}

#[cfg(test)]
mod tests {
    #[test]
    fn dotnet_crate_id_is_dotnet() {
        assert_eq!(super::dotnet_crate_id(), "dotnet");
    }
}
