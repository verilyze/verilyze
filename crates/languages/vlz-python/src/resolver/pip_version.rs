// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Detect pip version for `pip lock` eligibility (pip >= 25.1, FR-022).

/// Minimum pip major version for `pip lock` support.
pub const PIP_LOCK_MIN_MAJOR: u32 = 25;

/// Minimum pip minor version for `pip lock` support.
pub const PIP_LOCK_MIN_MINOR: u32 = 1;

/// Parse `pip --version` stdout into `(major, minor)`.
/// Example: `pip 25.1.1 from /usr/lib/python3 ...` -> `(25, 1)`.
pub fn parse_pip_version_output(stdout: &str) -> Option<(u32, u32)> {
    let first_line = stdout.lines().next()?.trim();
    let rest = first_line.strip_prefix("pip ")?;
    let version_token = rest.split_whitespace().next()?;
    let mut parts = version_token.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Returns true when pip version is >= 25.1 (supports experimental `pip lock`).
pub fn pip_version_supports_lock(major: u32, minor: u32) -> bool {
    major > PIP_LOCK_MIN_MAJOR
        || (major == PIP_LOCK_MIN_MAJOR && minor >= PIP_LOCK_MIN_MINOR)
}

/// Run `pip3 --version` then `pip --version`; return parsed version if successful.
pub fn detect_pip_version() -> Option<(u32, u32)> {
    for cmd in ["pip3", "pip"] {
        if let Ok(output) =
            std::process::Command::new(cmd).arg("--version").output()
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(v) = parse_pip_version_output(&stdout) {
                return Some(v);
            }
        }
    }
    None
}

/// Returns true if pip on PATH is >= 25.1.
pub fn pip_supports_lock() -> bool {
    detect_pip_version()
        .map(|(maj, min)| pip_version_supports_lock(maj, min))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_pip_version() {
        let out = "pip 25.1.1 from /usr/lib/python3/dist-packages/pip (python 3.12)\n";
        assert_eq!(parse_pip_version_output(out), Some((25, 1)));
    }

    #[test]
    fn parse_pip3_style_version() {
        let out = "pip 24.0 from /usr/local/lib/python3.11/site-packages/pip (python 3.11)\n";
        assert_eq!(parse_pip_version_output(out), Some((24, 0)));
    }

    #[test]
    fn parse_malformed_returns_none() {
        assert!(parse_pip_version_output("not pip output").is_none());
        assert!(parse_pip_version_output("").is_none());
    }

    #[test]
    fn pip_version_supports_lock_boundary() {
        assert!(pip_version_supports_lock(25, 1));
        assert!(pip_version_supports_lock(26, 0));
        assert!(!pip_version_supports_lock(25, 0));
        assert!(!pip_version_supports_lock(24, 99));
    }

    #[test]
    fn detect_pip_version_does_not_panic() {
        let _ = detect_pip_version();
    }
}
