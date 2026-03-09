// SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::error::Error;
use std::path::PathBuf;

use vlz_manifest_parser::{Parser, Resolver};
use vlz_python::RequirementsTxtParser;

#[tokio::test]
async fn parse_requirements_txt_file() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::create_dir_all(tmp).unwrap();
    let path = tmp.join("requirements.txt");
    std::fs::write(
        &path,
        b"# comment\n\
          foo==1.0.0\n\
          bar>=2.0\n\
          baz\n\
          \n\
          qux~=3.1\n\
          --extra-index-url https://example.com\n\
          pkg[dev]==1.0\n\
          \t # inline with nothing before\n\
          ==1.0\n\
          []\n",
    )
    .unwrap();
    let parser = RequirementsTxtParser::new();
    let graph = parser.parse(&path).await.unwrap();
    assert_eq!(graph.packages.len(), 5);
    let names: Vec<_> =
        graph.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["foo", "bar", "baz", "qux", "pkg"]);
    assert_eq!(graph.packages[0].version, "1.0.0");
    assert_eq!(graph.packages[1].version, "2.0");
    assert_eq!(graph.packages[2].version, "any");
    assert_eq!(graph.packages[3].version, "3.1");
    assert_eq!(graph.packages[4].version, "1.0");
    assert_eq!(graph.manifest_path.as_deref(), Some(path.as_path()));
}

#[tokio::test]
async fn parse_pyproject_toml_returns_packages_and_sets_manifest_path() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::create_dir_all(tmp).unwrap();
    let path = tmp.join("pyproject.toml");
    std::fs::write(
        &path,
        b"[project]\nname = \"test\"\nversion = \"0.1.0\"\n\
          dependencies = [\"httpx>=0.20\", \"requests==2.31.0\"]\n",
    )
    .unwrap();
    let parser = RequirementsTxtParser::new();
    let graph = parser.parse(&path).await.unwrap();
    assert_eq!(graph.packages.len(), 2);
    assert_eq!(graph.manifest_path.as_deref(), Some(path.as_path()));
}

#[tokio::test]
async fn parse_nonexistent_requirements_txt_returns_error() {
    let parser = RequirementsTxtParser::new();
    let path = PathBuf::from("/nonexistent/path/requirements.txt");
    let err = parser.parse(&path).await.unwrap_err();
    let msg = err.to_string();
    let source_msg = err.source().map(|s| s.to_string()).unwrap_or_default();
    assert!(
        msg.contains("IO")
            || msg.contains("manifest")
            || source_msg.contains("No such file")
            || source_msg.contains("not found"),
        "expected file-not-found error, got: {} (source: {})",
        msg,
        source_msg
    );
}

#[tokio::test]
async fn resolve_uses_lock_file_when_present() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::create_dir_all(tmp).unwrap();
    let pyproject = tmp.join("pyproject.toml");
    let poetry_lock = tmp.join("poetry.lock");
    std::fs::write(
        &pyproject,
        b"[project]\nname = \"test\"\ndependencies = [\"requests\"]\n",
    )
    .unwrap();
    std::fs::write(
        &poetry_lock,
        b"[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n\n[[package]]\nname = \"certifi\"\nversion = \"2024.1.0\"\n",
    )
    .unwrap();
    let parser = RequirementsTxtParser::new();
    let resolver = vlz_python::DirectOnlyResolver::new();
    let graph = parser.parse(&pyproject).await.unwrap();
    let resolved = resolver.resolve(&graph).await.unwrap();
    assert_eq!(resolved.len(), 2);
}
