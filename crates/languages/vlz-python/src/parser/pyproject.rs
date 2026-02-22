// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_manifest_parser::ParserError;

/// Parse pyproject.toml content into a list of packages (name, version).
/// Supports PEP 621 [project].dependencies and [project].optional-dependencies
/// and [tool.poetry.dependencies] for Poetry-style pyproject.toml.
/// Public for fuzzing (NFR-020).
pub fn parse_pyproject_toml(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let value: toml::Value = toml::from_str(content).map_err(|e| {
        ParserError::Parse(format!("pyproject.toml parse error: {}", e))
    })?;

    let mut packages = Vec::new();

    // PEP 621: [project].dependencies
    if let Some(project) = value.get("project") {
        if let Some(deps) = project.get("dependencies").and_then(|d| d.as_array()) {
            for dep in deps {
                if let Some(s) = dep.as_str() {
                    if let Some(pkg) = parse_pep508_dependency(s) {
                        packages.push(pkg);
                    }
                }
            }
        }
        if let Some(opt) = project.get("optional-dependencies") {
            if let Some(tbl) = opt.as_table() {
                for deps in tbl.values() {
                    if let Some(arr) = deps.as_array() {
                        for dep in arr {
                            if let Some(s) = dep.as_str() {
                                if let Some(pkg) = parse_pep508_dependency(s) {
                                    packages.push(pkg);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Poetry: [tool.poetry.dependencies] - key is package name, value is version or table
    if let Some(tool) = value.get("tool") {
        if let Some(poetry) = tool.get("poetry") {
            if let Some(deps) = poetry.get("dependencies").and_then(|d| d.as_table()) {
                for (name, val) in deps {
                    if name == "python" {
                        continue;
                    }
                    if let Some(s) = val.as_str() {
                        let version = extract_version_from_constraint(s);
                        packages.push(vlz_db::Package {
                            name: name.clone(),
                            version,
                        });
                    } else if let Some(tbl) = val.as_table() {
                        if let Some(version) = tbl.get("version").and_then(|v| v.as_str()) {
                            packages.push(vlz_db::Package {
                                name: name.clone(),
                                version: extract_version_from_constraint(version),
                            });
                        } else {
                            packages.push(vlz_db::Package {
                                name: name.clone(),
                                version: "any".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(packages)
}

/// Extract version from Poetry-style constraint (^, ~, >=, etc).
fn extract_version_from_constraint(s: &str) -> String {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('^') {
        return rest.trim().to_string();
    }
    if let Some(rest) = s.strip_prefix('~') {
        return rest.trim().to_string();
    }
    for sep in ["==", ">=", "<=", "!=", ">", "<"] {
        if let Some((_, v)) = s.split_once(sep) {
            return v.trim().split(',').next().unwrap_or("").trim().to_string();
        }
    }
    s.to_string()
}

/// Parse a PEP 508 dependency string into Package (name, version).
fn parse_pep508_dependency(spec: &str) -> Option<vlz_db::Package> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    let spec = if let Some(open) = spec.find('[') {
        let after_close = spec[open..]
            .find(']')
            .map(|c| open + c + 1)
            .unwrap_or(spec.len());
        format!("{}{}", spec[..open].trim(), spec[after_close..].trim())
    } else {
        spec.to_string()
    };
    let (name, version) = parse_name_version(&spec)?;
    if name.is_empty() {
        return None;
    }
    Some(vlz_db::Package { name, version })
}

fn parse_name_version(spec: &str) -> Option<(String, String)> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }
    if let Some((n, v)) = spec.split_once("==") {
        return Some((n.trim().to_string(), v.trim().to_string()));
    }
    for sep in ["~=", ">=", "<=", "!=", ">", "<"] {
        if let Some((n, v)) = spec.split_once(sep) {
            let version = v.trim().split(',').next().unwrap_or("").trim().to_string();
            let version = if version.is_empty() {
                "any".to_string()
            } else {
                version
            };
            return Some((n.trim().to_string(), version));
        }
    }
    Some((spec.to_string(), "any".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pyproject_toml_valid_empty_returns_empty() {
        let content = "[project]\nname = \"foo\"\nversion = \"0.1.0\"\n";
        let packages = parse_pyproject_toml(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_pyproject_toml_invalid_returns_error() {
        let content = "not valid toml {{{";
        let err = parse_pyproject_toml(content).unwrap_err();
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn parse_pyproject_toml_project_dependencies() {
        let content = r#"
[project]
name = "foo"
version = "0.1.0"
dependencies = [
    "httpx>=0.20",
    "requests==2.31.0",
    "django",
]
"#;
        let packages = parse_pyproject_toml(content).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "httpx");
        assert_eq!(packages[0].version, "0.20");
        assert_eq!(packages[1].name, "requests");
        assert_eq!(packages[1].version, "2.31.0");
        assert_eq!(packages[2].name, "django");
        assert_eq!(packages[2].version, "any");
    }

    #[test]
    fn parse_pyproject_toml_optional_dependencies() {
        let content = r#"
[project]
name = "foo"
[project.optional-dependencies]
test = ["pytest>=7.0", "pytest-cov"]
dev = ["black", "mypy>=1.0"]
"#;
        let packages = parse_pyproject_toml(content).unwrap();
        assert_eq!(packages.len(), 4);
    }

    #[test]
    fn parse_pyproject_toml_tool_poetry_dependencies() {
        let content = r#"
[tool.poetry]
name = "foo"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.8"
requests = "^2.28"
httpx = {version = ">=0.20"}
"#;
        let packages = parse_pyproject_toml(content).unwrap();
        assert_eq!(packages.len(), 2);
        let names: std::collections::HashSet<_> =
            packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains("requests"));
        assert!(names.contains("httpx"));
        let pkg_requests = packages.iter().find(|p| p.name == "requests").unwrap();
        assert_eq!(pkg_requests.version, "2.28");
        let pkg_httpx = packages.iter().find(|p| p.name == "httpx").unwrap();
        assert_eq!(pkg_httpx.version, "0.20");
    }
}
