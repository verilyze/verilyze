// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Lock-less transitive resolution via `cargo metadata` (FR-022, SEC-023).

use std::path::Path;

use vlz_manifest_parser::{ResolverError, fr022_transitive_error_with_cause};

/// Parse `cargo metadata --format-version 1` JSON into packages. Public for fuzzing.
pub fn parse_cargo_metadata_packages(
    json: &str,
) -> Result<Vec<vlz_db::Package>, ResolverError> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| {
            ResolverError::Resolve(format!(
                "cargo metadata JSON parse error: {e}"
            ))
        })?;
    let mut packages = Vec::new();
    if let Some(arr) = value.get("packages").and_then(|p| p.as_array()) {
        for entry in arr {
            if let (Some(name), Some(version)) = (
                entry.get("name").and_then(|n| n.as_str()),
                entry.get("version").and_then(|v| v.as_str()),
            ) {
                packages.push(vlz_db::Package {
                    name: name.to_string(),
                    version: version.to_string(),
                    ecosystem: Some("crates.io".to_string()),
                });
            }
        }
    }
    Ok(packages)
}

/// Run `cargo metadata` for the given manifest (absolute path). Uses spawn_blocking.
pub async fn run_cargo_metadata(
    manifest_path: &Path,
) -> Result<Vec<vlz_db::Package>, ResolverError> {
    let manifest_path = manifest_path.to_path_buf();
    let manifest_str = manifest_path.to_str().ok_or_else(|| {
        ResolverError::Resolve(
            "manifest path is not valid UTF-8 for cargo metadata".to_string(),
        )
    })?;
    let manifest_str = manifest_str.to_string();
    let output = tokio::task::spawn_blocking(move || {
        std::process::Command::new("cargo")
            .args([
                "metadata",
                "--format-version",
                "1",
                "--manifest-path",
                &manifest_str,
            ])
            .output()
    })
    .await
    .map_err(|e| {
        ResolverError::Resolve(format!("cargo metadata task failed: {e}"))
    })?
    .map_err(ResolverError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let snippet = stderr.trim();
        let cause_msg = if snippet.is_empty() {
            format!("cargo metadata exited with {}", output.status)
        } else {
            format!("cargo metadata failed: {snippet}")
        };
        return Err(fr022_transitive_error_with_cause(
            ResolverError::Resolve(cause_msg),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_cargo_metadata_packages(&stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cargo_metadata_packages_happy_path() {
        let json = r#"{
            "packages": [
                {"name": "serde", "version": "1.0.2"},
                {"name": "serde_derive", "version": "1.0.2"}
            ]
        }"#;
        let packages = parse_cargo_metadata_packages(json).unwrap();
        assert_eq!(packages.len(), 2);
        assert!(
            packages
                .iter()
                .any(|p| p.name == "serde" && p.version == "1.0.2")
        );
    }

    #[test]
    fn parse_cargo_metadata_packages_empty_array() {
        let json = r#"{"packages": []}"#;
        let packages = parse_cargo_metadata_packages(json).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn parse_cargo_metadata_packages_malformed_json() {
        let err = parse_cargo_metadata_packages("not json").unwrap_err();
        assert!(err.to_string().contains("parse"));
    }
}
