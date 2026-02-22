// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_manifest_parser::ParserError;

/// Parse setup.cfg content into a list of packages (name, version).
/// Supports [options] install_requires and [options.extras_require].
/// Public for fuzzing (NFR-020).
pub fn parse_setup_cfg(content: &str) -> Result<Vec<vlz_db::Package>, ParserError> {
    let mut packages = Vec::new();
    let mut in_options = false;
    let mut in_extras = false;
    let mut in_install_requires = false;

    for line in content.lines() {
        let trimmed = line.trim();
        let is_continuation = !line.is_empty()
            && (line.starts_with(' ') || line.starts_with('\t'))
            && !trimmed.is_empty();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            in_install_requires = false;
            continue;
        }

        if trimmed.starts_with('[') {
            in_options = trimmed == "[options]";
            in_extras = trimmed == "[options.extras_require]";
            in_install_requires = false;
            continue;
        }

        if in_options {
            if !is_continuation {
                if let Some((key, val)) = trimmed.split_once('=') {
                    let key = key.trim();
                    let val = val.trim();
                    if key == "install_requires" {
                        in_install_requires = true;
                        for dep in split_deps(val) {
                            if let Some(pkg) = parse_pep508_dependency(dep) {
                                packages.push(pkg);
                            }
                        }
                        if !val.is_empty() && !val.ends_with(',') {
                            in_install_requires = false;
                        }
                    } else {
                        in_install_requires = false;
                    }
                } else {
                    in_install_requires = false;
                }
            } else if in_install_requires {
                for dep in split_deps(trimmed) {
                    if let Some(pkg) = parse_pep508_dependency(dep) {
                        packages.push(pkg);
                    }
                }
            }
        }

        if in_extras {
            if let Some((_, val)) = trimmed.split_once('=') {
                for dep in split_deps(val.trim()) {
                    if let Some(pkg) = parse_pep508_dependency(dep) {
                        packages.push(pkg);
                    }
                }
            }
        }
    }

    Ok(packages)
}

fn split_deps(s: &str) -> Vec<&str> {
    s.split(',')
        .flat_map(|part| part.split_whitespace())
        .filter(|p| !p.is_empty())
        .collect()
}

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
    Some(vlz_db::Package {
        name,
        version,
        ecosystem: Some("PyPI".to_string()),
    })
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
            let version = v.trim().split(';').next().unwrap_or("").trim();
            let version = version.split(',').next().unwrap_or("").trim().to_string();
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
    fn parse_setup_cfg_empty_returns_empty() {
        let content = "[metadata]\nname = foo\n";
        let packages = parse_setup_cfg(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_setup_cfg_install_requires_multiline() {
        let content = r#"
[options]
install_requires =
    requests>=2.0
    httpx==0.20
    django
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert!(packages.len() >= 2);
    }

    #[test]
    fn parse_setup_cfg_install_requires_comma_sep() {
        let content = r#"
[options]
install_requires = requests>=2.0, httpx==0.20, django
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 3);
    }

    #[test]
    fn parse_setup_cfg_extras_require() {
        let content = r#"
[options.extras_require]
test = pytest>=7.0, pytest-cov
dev = black, mypy>=1.0
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 4);
    }

    #[test]
    fn parse_setup_cfg_section_reset() {
        let content = r#"
[options]
install_requires = a

  b
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "a");
    }

    #[test]
    fn parse_setup_cfg_other_section_ignored() {
        let content = r#"
[metadata]
name = foo

[options]
install_requires = django
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "django");
    }

    #[test]
    fn parse_setup_cfg_key_not_install_requires() {
        let content = r#"
[options]
some_other_key = x
install_requires = requests
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "requests");
    }

    #[test]
    fn parse_setup_cfg_continuation_with_comma() {
        let content = r#"
[options]
install_requires = a,
    b
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].name, "a");
        assert_eq!(packages[1].name, "b");
    }

    #[test]
    fn parse_setup_cfg_line_without_equals() {
        let content = r#"
[options]
bare_key_no_equals
install_requires = foo
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "foo");
    }

    #[test]
    fn parse_setup_cfg_comments_reset_continuation() {
        let content = r#"
[options]
install_requires = a
# comment
    b
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "a");
    }

    #[test]
    fn parse_setup_cfg_pep508_with_extras() {
        let content = r#"
[options]
install_requires = pkg[dev]==1.0
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "pkg");
        assert_eq!(packages[0].version, "1.0");
    }

    #[test]
    fn parse_setup_cfg_pep508_operators() {
        let content = r#"
[options]
install_requires =
    pkg~=1.0
    a>=2.0
    b<=3.0
    c!=4.0
    d>5.0
    e<6.0
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 6);
        assert_eq!(
            packages[0],
            vlz_db::Package {
                name: "pkg".into(),
                version: "1.0".into(),
                ecosystem: Some("PyPI".into())
            }
        );
        assert_eq!(
            packages[1],
            vlz_db::Package {
                name: "a".into(),
                version: "2.0".into(),
                ecosystem: Some("PyPI".into())
            }
        );
        assert_eq!(
            packages[2],
            vlz_db::Package {
                name: "b".into(),
                version: "3.0".into(),
                ecosystem: Some("PyPI".into())
            }
        );
        assert_eq!(
            packages[3],
            vlz_db::Package {
                name: "c".into(),
                version: "4.0".into(),
                ecosystem: Some("PyPI".into())
            }
        );
        assert_eq!(
            packages[4],
            vlz_db::Package {
                name: "d".into(),
                version: "5.0".into(),
                ecosystem: Some("PyPI".into())
            }
        );
        assert_eq!(
            packages[5],
            vlz_db::Package {
                name: "e".into(),
                version: "6.0".into(),
                ecosystem: Some("PyPI".into())
            }
        );
    }

    #[test]
    fn parse_setup_cfg_pep508_env_marker() {
        let content = r#"
[options]
install_requires = foo>=1.0;python_version>='3'
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "foo");
        assert_eq!(packages[0].version, "1.0");
    }

    #[test]
    fn parse_setup_cfg_pep508_version_comma() {
        let content = r#"
[options]
install_requires = foo>=1.0,<2
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].version, "1.0");
    }

    #[test]
    fn parse_setup_cfg_pep508_no_operator() {
        let content = r#"
[options]
install_requires = barepkg
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "barepkg");
        assert_eq!(packages[0].version, "any");
    }

    #[test]
    fn parse_setup_cfg_split_deps_multiple_spaces() {
        let content = r#"
[options]
install_requires = a,,   b    c
"#;
        let packages = parse_setup_cfg(content).unwrap();
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].name, "a");
        assert_eq!(packages[1].name, "b");
        assert_eq!(packages[2].name, "c");
    }
}
