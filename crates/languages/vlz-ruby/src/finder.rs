// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use async_trait::async_trait;
use std::path::{Path, PathBuf};
use vlz_manifest_finder::{FinderError, ManifestFinder};

use crate::lock_names::is_ruby_lock_file;

/// Built-in Ruby manifest basenames.
pub const RUBY_MANIFEST_NAMES: &[&str] = &["Gemfile", "gems.rb"];

/// Discovers Gemfile, gems.rb, and gemspec manifests.
#[derive(Debug, Default)]
pub struct RubyManifestFinder {
    patterns: Option<Vec<regex::Regex>>,
}

impl RubyManifestFinder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_patterns(patterns: Vec<String>) -> Result<Self, FinderError> {
        let patterns = patterns
            .into_iter()
            .map(|pattern| {
                regex::Regex::new(&pattern)
                    .map_err(|error| FinderError::Regex(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            patterns: Some(patterns),
        })
    }
}

/// True when `name` is a built-in Ruby manifest basename.
pub fn is_ruby_manifest_name(name: &str) -> bool {
    RUBY_MANIFEST_NAMES.contains(&name) || name.ends_with(".gemspec")
}

fn built_in_match(name: &str) -> bool {
    is_ruby_manifest_name(name)
}

fn walk(
    dir: &Path,
    patterns: Option<&[regex::Regex]>,
    manifests: &mut Vec<PathBuf>,
) -> Result<(), FinderError> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            walk(&entry.path(), patterns, manifests)?;
        } else if file_type.is_file()
            && let Some(name) = entry.file_name().to_str()
        {
            let matches = patterns
                .map(|items| items.iter().any(|item| item.is_match(name)))
                .unwrap_or_else(|| built_in_match(name));
            if matches {
                manifests.push(entry.path());
            }
        }
    }
    Ok(())
}

#[async_trait]
impl ManifestFinder for RubyManifestFinder {
    fn language_name(&self) -> &str {
        "ruby"
    }

    fn is_sca_sensitive_basename(&self, name: &str) -> bool {
        is_ruby_manifest_name(name) || is_ruby_lock_file(name)
    }

    async fn find(&self, root: &Path) -> Result<Vec<PathBuf>, FinderError> {
        let mut manifests = Vec::new();
        walk(root, self.patterns.as_deref(), &mut manifests)?;
        manifests.sort();
        Ok(manifests)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_ins_and_patterns() {
        assert!(built_in_match("Gemfile"));
        assert!(built_in_match("gems.rb"));
        assert!(built_in_match("demo.gemspec"));
        assert!(!built_in_match("Gemfile.lock"));
        assert!(RubyManifestFinder::with_patterns(vec!["[".into()]).is_err());
        assert_eq!(RubyManifestFinder::new().language_name(), "ruby");
    }

    #[test]
    fn sca_sensitive_basenames_include_manifests_and_locks() {
        let finder = RubyManifestFinder::new();
        assert!(finder.is_sca_sensitive_basename("Gemfile.lock"));
        assert!(finder.is_sca_sensitive_basename("demo.gemspec"));
        assert!(!finder.is_sca_sensitive_basename("Gemfile.lock.fixture"));
        assert!(!finder.is_sca_sensitive_basename("example.gemspec.fixture"));
    }
}
