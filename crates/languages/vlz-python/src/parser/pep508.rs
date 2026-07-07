// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_db::PYPI_ECOSYSTEM;

/// Parse a PEP 508 dependency string into Package (name, version).
pub fn parse_pep508_dependency(spec: &str) -> Option<vlz_db::Package> {
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
        ecosystem: Some(PYPI_ECOSYSTEM.to_string()),
    })
}

/// Split a requirement spec (no [extras]) into (name, version).
pub fn parse_name_version(spec: &str) -> Option<(String, String)> {
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
            let version =
                version.split(',').next().unwrap_or("").trim().to_string();
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
    fn parse_pep508_strips_extras() {
        let pkg = parse_pep508_dependency("foo[dev]==1.0").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_pep508_env_marker() {
        let pkg =
            parse_pep508_dependency("foo>=1.0;python_version>='3'").unwrap();
        assert_eq!(pkg.name, "foo");
        assert_eq!(pkg.version, "1.0");
    }

    #[test]
    fn parse_pep508_no_operator() {
        let pkg = parse_pep508_dependency("barepkg").unwrap();
        assert_eq!(pkg.name, "barepkg");
        assert_eq!(pkg.version, "any");
    }
}
