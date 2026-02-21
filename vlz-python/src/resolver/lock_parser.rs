// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::path::Path;

use vlz_manifest_parser::ParserError;

/// Parse a lock file into packages. Detects format by filename and content.
pub fn parse_lock_file(path: &Path, content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    if name == "Pipfile.lock" || content.trim_start().starts_with('{') {
        return parse_pipfile_lock(content);
    }
    if name == "poetry.lock" {
        return parse_poetry_lock(content);
    }
    if name == "uv.lock" {
        return parse_uv_lock(content);
    }
    if name == "pylock.toml" || (name.starts_with("pylock.") && name.ends_with(".toml")) {
        return parse_pylock_toml(content);
    }
    if content.contains("[[package]]") {
        return parse_poetry_lock(content);
    }
    if content.contains("lock-version") && content.contains("[[packages]]") {
        return parse_pylock_toml(content);
    }

    Err(ParserError::Parse("Unknown lock file format".to_string()))
}

/// Parse pylock.toml (PEP 751) format.
pub fn parse_pylock_toml(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let value: toml::Value = toml::from_str(content)
        .map_err(|e| ParserError::Parse(format!("pylock.toml parse error: {}", e)))?;

    let mut packages = Vec::new();
    if let Some(arr) = value.get("packages").and_then(|p| p.as_array()) {
        for entry in arr {
            if let Some(tbl) = entry.as_table() {
                if let Some(name) = tbl.get("name").and_then(|n| n.as_str()) {
                    let version = tbl
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("any")
                        .to_string();
                    packages.push(vlz_db::Package {
                        name: name.to_string(),
                        version,
                    });
                }
            }
        }
    }
    Ok(packages)
}

/// Parse poetry.lock format.
pub fn parse_poetry_lock(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let value: toml::Value = toml::from_str(content)
        .map_err(|e| ParserError::Parse(format!("poetry.lock parse error: {}", e)))?;

    let mut packages = Vec::new();
    if let Some(arr) = value.get("package").and_then(|p| p.as_array()) {
        for entry in arr {
            if let Some(tbl) = entry.as_table() {
                if let Some(name) = tbl.get("name").and_then(|n| n.as_str()) {
                    let version = tbl
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("any")
                        .to_string();
                    packages.push(vlz_db::Package {
                        name: name.to_string(),
                        version,
                    });
                }
            }
        }
    }
    Ok(packages)
}

/// Parse Pipfile.lock JSON format.
pub fn parse_pipfile_lock(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| ParserError::Parse(format!("Pipfile.lock parse error: {}", e)))?;

    let mut packages = Vec::new();
    for section in ["default", "develop"] {
        if let Some(obj) = value.get(section).and_then(|v| v.as_object()) {
            for (name, pkg) in obj {
                if let Some(obj) = pkg.as_object() {
                    let version = obj
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("any")
                        .trim_matches('=')
                        .to_string();
                    packages.push(vlz_db::Package {
                        name: name.clone(),
                        version,
                    });
                }
            }
        }
    }
    Ok(packages)
}

/// Parse uv.lock TOML format.
pub fn parse_uv_lock(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let value: toml::Value = toml::from_str(content)
        .map_err(|e| ParserError::Parse(format!("uv.lock parse error: {}", e)))?;

    let mut packages = Vec::new();
    if let Some(arr) = value.get("package").and_then(|p| p.as_array()) {
        for entry in arr {
            if let Some(tbl) = entry.as_table() {
                if let Some(name) = tbl.get("name").and_then(|n| n.as_str()) {
                    let version = tbl
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("any")
                        .to_string();
                    packages.push(vlz_db::Package {
                        name: name.to_string(),
                        version,
                    });
                }
            }
        }
    }
    Ok(packages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn parse_pylock_toml_packages() {
        let content = r#"
lock-version = "1.0"
created-by = "test"

[[packages]]
name = "attrs"
version = "25.1.0"

[[packages]]
name = "cattrs"
version = "24.1.2"
"#;
        let packages = parse_pylock_toml(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "attrs");
        assert_eq!(packages[0].version, "25.1.0");
    }

    #[test]
    fn parse_poetry_lock_packages() {
        let content = r#"
[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "httpx"
version = "0.25.0"
"#;
        let packages = parse_poetry_lock(content).unwrap();
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn parse_pipfile_lock_packages() {
        let content = r#"{
  "_meta": {},
  "default": {
    "requests": {"version": "==2.31.0", "hashes": []},
    "httpx": {"version": "==0.25.0"}
  },
  "develop": {
    "pytest": {"version": "==7.0.0"}
  }
}"#;
        let packages = parse_pipfile_lock(content).unwrap();
        assert_eq!(packages.len(), 3);
    }

    #[test]
    fn parse_lock_file_detects_pipfile_lock() {
        let content = r#"{"default": {"foo": {"version": "==1.0"}}}"#;
        let path = PathBuf::from("/x/Pipfile.lock");
        let packages = parse_lock_file(path.as_path(), content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.0");
    }
}
