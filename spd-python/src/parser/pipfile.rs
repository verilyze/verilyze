// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use spd_manifest_parser::ParserError;

/// Parse Pipfile content into a list of packages (name, version).
/// Supports [packages] and [dev-packages] sections.
/// Public for fuzzing (NFR-020).
pub fn parse_pipfile(content: &str) -> Result<Vec<spd_db::Package>, ParserError> {
    let value: toml::Value = toml::from_str(content).map_err(|e| {
        ParserError::Parse(format!("Pipfile parse error: {}", e))
    })?;

    let mut packages = Vec::new();

    for section in ["packages", "dev-packages"] {
        if let Some(tbl) = value.get(section).and_then(|v| v.as_table()) {
            for (name, val) in tbl {
                if let Some(pkg) = parse_pipfile_dep(name, val) {
                    packages.push(pkg);
                }
            }
        }
    }

    Ok(packages)
}

fn parse_pipfile_dep(name: &str, val: &toml::Value) -> Option<spd_db::Package> {
    if let Some(s) = val.as_str() {
        let version = extract_pipfile_version(s);
        return Some(spd_db::Package {
            name: name.to_string(),
            version,
        });
    }
    if let Some(tbl) = val.as_table() {
        let version = tbl
            .get("version")
            .and_then(|v| v.as_str())
            .map(extract_pipfile_version)
            .unwrap_or_else(|| "any".to_string());
        return Some(spd_db::Package {
            name: name.to_string(),
            version,
        });
    }
    None
}

fn extract_pipfile_version(s: &str) -> String {
    let s = s.trim();
    if s == "*" || s.is_empty() {
        return "any".to_string();
    }
    if let Some((_, v)) = s.split_once("==") {
        return v.trim().to_string();
    }
    for sep in ["~=", ">=", "<=", "!=", ">", "<"] {
        if let Some((_, v)) = s.split_once(sep) {
            let version = v.trim().split(',').next().unwrap_or("").trim().to_string();
            return if version.is_empty() {
                "any".to_string()
            } else {
                version
            };
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pipfile_empty_returns_empty() {
        let content = "[packages]\n\n[dev-packages]\n";
        let packages = parse_pipfile(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_pipfile_invalid_returns_error() {
        let content = "not valid toml";
        let err = parse_pipfile(content).unwrap_err();
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn parse_pipfile_simple_strings() {
        let content = r#"
[packages]
requests = "*"
flask = "==2.0.1"
numpy = ">=1.20.0,<2.0.0"
"#;
        let packages = parse_pipfile(content).unwrap();
        assert_eq!(packages.len(), 3);
        let req = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(req.version, "any");
        let flask = packages.iter().find(|p| p.name == "flask").unwrap();
        assert_eq!(flask.version, "2.0.1");
        let numpy = packages.iter().find(|p| p.name == "numpy").unwrap();
        assert_eq!(numpy.version, "1.20.0");
    }

    #[test]
    fn parse_pipfile_inline_tables() {
        let content = r#"
[packages]
django = {version = ">=3.2", extras = ["bcrypt"]}
sentry-sdk = {version = ">=1.0.0"}
"#;
        let packages = parse_pipfile(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "django");
        assert_eq!(packages[0].version, "3.2");
        assert_eq!(packages[1].name, "sentry-sdk");
        assert_eq!(packages[1].version, "1.0.0");
    }

    #[test]
    fn parse_pipfile_dev_packages() {
        let content = r#"
[packages]
requests = "*"

[dev-packages]
pytest = ">=7.0"
"#;
        let packages = parse_pipfile(content).unwrap();
        assert_eq!(packages.len(), 2);
    }
}
