// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse `pip freeze` stdout into packages (FR-023 fallback path).

use vlz_db::PYPI_ECOSYSTEM;
use vlz_manifest_parser::ResolverError;

/// Maximum line length accepted from `pip freeze` output (NFR-020).
pub const PIP_FREEZE_MAX_LINE_LEN: usize = 4096;

/// Maximum number of lines accepted from `pip freeze` output (NFR-020).
pub const PIP_FREEZE_MAX_LINES: usize = 100_000;

/// Parse `pip freeze` stdout into packages (`name==version` lines).
pub fn parse_pip_freeze(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ResolverError> {
    let mut packages = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if i >= PIP_FREEZE_MAX_LINES {
            return Err(ResolverError::Resolve(format!(
                "pip freeze output exceeds maximum of {PIP_FREEZE_MAX_LINES} lines"
            )));
        }
        if line.len() > PIP_FREEZE_MAX_LINE_LEN {
            return Err(ResolverError::Resolve(format!(
                "pip freeze line exceeds maximum length of {PIP_FREEZE_MAX_LINE_LEN} bytes"
            )));
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("-e") || line.starts_with("--") {
            continue;
        }
        if line.contains(" @ file://") || line.contains(" @ git+") {
            continue;
        }
        if let Some((name, version)) = line.split_once("==") {
            let name = name.trim();
            let version = version.trim();
            if !name.is_empty() && !version.is_empty() {
                packages.push(vlz_db::Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
                });
            }
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_name_version_lines() {
        let input = "requests==2.31.0\nurllib3==2.0.7\n";
        let pkgs = parse_pip_freeze(input).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].name, "requests");
        assert_eq!(pkgs[0].version, "2.31.0");
        assert_eq!(pkgs[1].name, "urllib3");
    }

    #[test]
    fn skip_editable_lines() {
        let input = "-e git+https://example.com/pkg.git#egg=pkg\nfoo==1.0\n";
        let pkgs = parse_pip_freeze(input).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "foo");
    }

    #[test]
    fn skip_comments_and_blank_lines() {
        let input = "# comment\n\nfoo==1.0\n";
        let pkgs = parse_pip_freeze(input).unwrap();
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn skip_file_url_lines() {
        let input = "pkg @ file:///tmp/pkg\nbar==2.0\n";
        let pkgs = parse_pip_freeze(input).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "bar");
    }

    #[test]
    fn skip_option_lines() {
        let input = "--index-url https://pypi.org/simple\nbaz==3.0\n";
        let pkgs = parse_pip_freeze(input).unwrap();
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn empty_input_returns_empty_vec() {
        assert!(parse_pip_freeze("").unwrap().is_empty());
    }

    #[test]
    fn malformed_lines_skipped() {
        let input = "not-a-package\nvalid==1.0\n";
        let pkgs = parse_pip_freeze(input).unwrap();
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn max_line_length_exceeded_returns_error() {
        let long = "x".repeat(PIP_FREEZE_MAX_LINE_LEN + 1);
        let err = parse_pip_freeze(&long).unwrap_err();
        assert!(err.to_string().contains("maximum length"));
    }

    #[test]
    fn max_lines_exceeded_returns_error() {
        let lines: String = (0..=PIP_FREEZE_MAX_LINES)
            .map(|i| format!("pkg{i}==1.0"))
            .collect::<Vec<_>>()
            .join("\n");
        let err = parse_pip_freeze(&lines).unwrap_err();
        assert!(err.to_string().contains("maximum"));
    }
}
