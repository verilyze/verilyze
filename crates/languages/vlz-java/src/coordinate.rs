// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Maven coordinate helpers shared by parsers and resolvers.

use std::collections::HashMap;

/// OSV package name for Maven: `groupId:artifactId`.
pub fn maven_package_name(group: &str, artifact: &str) -> String {
    format!("{group}:{artifact}")
}

/// Parse `group:artifact:version` (Gradle lock / catalog module shorthand).
pub fn parse_gav_triple(s: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() >= 3 {
        Some((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ))
    } else if parts.len() == 2 {
        Some((parts[0].to_string(), parts[1].to_string(), String::new()))
    } else {
        None
    }
}

/// Resolve `${property}` references using same-file properties and project built-ins.
pub fn resolve_maven_property(
    value: &str,
    properties: &HashMap<String, String>,
    project_group: Option<&str>,
    project_artifact: Option<&str>,
    project_version: Option<&str>,
) -> String {
    let mut out = value.to_string();
    for _ in 0..32 {
        if !out.contains("${") {
            break;
        }
        let Some(start) = out.find("${") else { break };
        let Some(end) = out[start..].find('}') else {
            break;
        };
        let key = &out[start + 2..start + end];
        let replacement = match key {
            "project.groupId" => project_group.map(str::to_string),
            "project.artifactId" => project_artifact.map(str::to_string),
            "project.version" => project_version.map(str::to_string),
            "pom.groupId" => project_group.map(str::to_string),
            "pom.artifactId" => project_artifact.map(str::to_string),
            "pom.version" => project_version.map(str::to_string),
            other => properties.get(other).cloned(),
        };
        let Some(repl) = replacement else {
            break;
        };
        out.replace_range(start..start + end + 1, &repl);
    }
    out
}

/// True when artifactId alone is too generic for reachability matching.
pub fn is_generic_artifact_id(artifact: &str) -> bool {
    matches!(
        artifact.to_ascii_lowercase().as_str(),
        "common" | "core" | "util" | "utils" | "api" | "base" | "lib"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maven_package_name_format() {
        assert_eq!(
            maven_package_name("com.example", "foo"),
            "com.example:foo"
        );
    }

    #[test]
    fn parse_gav_triple_full() {
        let (g, a, v) = parse_gav_triple("com.a:b:1.0").unwrap();
        assert_eq!(g, "com.a");
        assert_eq!(a, "b");
        assert_eq!(v, "1.0");
    }

    #[test]
    fn resolve_property_from_map() {
        let mut props = HashMap::new();
        props.insert("junit.version".to_string(), "5.10.0".to_string());
        assert_eq!(
            resolve_maven_property(
                "${junit.version}",
                &props,
                None,
                None,
                None
            ),
            "5.10.0"
        );
    }

    #[test]
    fn resolve_project_builtins() {
        let props = HashMap::new();
        assert_eq!(
            resolve_maven_property(
                "${project.version}",
                &props,
                Some("g"),
                Some("a"),
                Some("1.2.3")
            ),
            "1.2.3"
        );
    }

    #[test]
    fn generic_artifact_ids() {
        assert!(is_generic_artifact_id("common"));
        assert!(!is_generic_artifact_id("guava"));
    }
}
