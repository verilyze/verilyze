// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

/// Supported NuGet lock file basenames (Appendix A).
pub const DOTNET_LOCK_FILE_NAMES: &[&str] = &["packages.lock.json"];

/// True when `name` is a supported .NET / NuGet lock file basename.
pub fn is_dotnet_lock_file(name: &str) -> bool {
    DOTNET_LOCK_FILE_NAMES
        .iter()
        .any(|lock| name.eq_ignore_ascii_case(lock))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_dotnet_lock_file_matches_packages_lock_json() {
        assert!(is_dotnet_lock_file("packages.lock.json"));
        assert!(is_dotnet_lock_file("Packages.Lock.JSON"));
        assert!(!is_dotnet_lock_file("App.csproj"));
        assert!(!is_dotnet_lock_file("packages.lock.json.fixture"));
    }
}
