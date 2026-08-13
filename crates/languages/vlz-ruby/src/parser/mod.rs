// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod gemfile;
mod gemfile_lock;
mod gemspec;
mod util;

use async_trait::async_trait;
use std::path::Path;
use vlz_manifest_parser::{DependencyGraph, Parser, ParserError};

pub use gemfile::{parse_gemfile, parse_gemfile_with_declarations};
pub use gemfile_lock::{
    parse_gemfile_lock, parse_gemfile_lock_with_declarations,
};
pub use gemspec::{parse_gemspec, parse_gemspec_with_declarations};

/// Maximum accepted size for executable Ruby manifests (Gemfile / gemspec).
pub const RUBY_MANIFEST_MAX_BYTES: u64 = 1024 * 1024;

/// Maximum accepted size for Bundler lock files.
pub const RUBY_LOCK_MAX_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct RubyManifestParser;

impl RubyManifestParser {
    pub fn new() -> Self {
        Self
    }
}

async fn read_capped(
    path: &Path,
    max_bytes: u64,
) -> Result<String, ParserError> {
    if tokio::fs::metadata(path).await?.len() > max_bytes {
        return Err(ParserError::Parse(format!(
            "Ruby file exceeds {max_bytes} byte limit"
        )));
    }
    Ok(tokio::fs::read_to_string(path).await?)
}

#[async_trait]
impl Parser for RubyManifestParser {
    fn language_name(&self) -> &'static str {
        "ruby"
    }

    async fn parse(
        &self,
        manifest: &Path,
    ) -> Result<DependencyGraph, ParserError> {
        let name = manifest
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        let executable_manifest = matches!(name, "Gemfile" | "gems.rb")
            || name.ends_with(".gemspec");
        let is_lock = matches!(name, "Gemfile.lock" | "gems.locked");
        let content = if executable_manifest {
            read_capped(manifest, RUBY_MANIFEST_MAX_BYTES).await?
        } else if is_lock {
            read_capped(manifest, RUBY_LOCK_MAX_BYTES).await?
        } else {
            tokio::fs::read_to_string(manifest).await?
        };
        let (packages, parsed_dependencies) = match name {
            "Gemfile" | "gems.rb" => {
                parse_gemfile_with_declarations(&content, manifest)?
            }
            "Gemfile.lock" | "gems.locked" => {
                parse_gemfile_lock_with_declarations(&content, manifest)?
            }
            _ if name.ends_with(".gemspec") => {
                parse_gemspec_with_declarations(&content, manifest)?
            }
            _ => (Vec::new(), Vec::new()),
        };
        Ok(DependencyGraph {
            packages,
            parsed_dependencies,
            manifest_path: Some(manifest.to_path_buf()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_oversized_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Gemfile");
        std::fs::write(
            &path,
            vec![b'x'; RUBY_MANIFEST_MAX_BYTES as usize + 1],
        )
        .unwrap();
        assert!(RubyManifestParser::new().parse(&path).await.is_err());
    }

    #[tokio::test]
    async fn rejects_oversized_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Gemfile.lock");
        std::fs::write(&path, vec![b'x'; RUBY_LOCK_MAX_BYTES as usize + 1])
            .unwrap();
        assert!(RubyManifestParser::new().parse(&path).await.is_err());
    }

    #[tokio::test]
    async fn parses_gemfile_and_unknown_names() {
        let dir = tempfile::tempdir().unwrap();
        let gemfile = dir.path().join("Gemfile");
        std::fs::write(&gemfile, "gem 'rack'\n").unwrap();
        let graph = RubyManifestParser::new().parse(&gemfile).await.unwrap();
        assert_eq!(graph.packages.len(), 1);

        let other = dir.path().join("notes.txt");
        std::fs::write(&other, "hello\n").unwrap();
        let empty = RubyManifestParser::new().parse(&other).await.unwrap();
        assert!(empty.packages.is_empty());
    }

    #[test]
    fn language_name_is_stable() {
        assert_eq!(RubyManifestParser::new().language_name(), "ruby");
    }
}
