// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

/// Strip a Ruby `#` comment that is outside single/double quotes.
pub(crate) fn strip_line_comment(line: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_single || in_double => escaped = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &line[..index],
            _ => {}
        }
    }
    line
}

/// True when a gem/dependency line pins a non-registry source.
///
/// Supports keyword args (`path:`, `git:`, `github:`) and hash-rocket
/// forms (`:path =>`, `:git =>`, `:github =>`).
pub(crate) fn is_non_registry_gem_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    for marker in ["path:", "git:", "github:"] {
        if lower.contains(marker) {
            return true;
        }
    }
    for marker in [":path", ":git", ":github"] {
        if let Some(index) = lower.find(marker) {
            let after = lower[index + marker.len()..].trim_start();
            if after.starts_with("=>") {
                return true;
            }
        }
    }
    false
}

/// True when a Bundler lock parenthesis payload is a requirement, not a version.
pub(crate) fn looks_like_requirement(version: &str) -> bool {
    let trimmed = version.trim();
    trimmed.starts_with('>')
        || trimmed.starts_with('<')
        || trimmed.starts_with('=')
        || trimmed.starts_with('~')
        || trimmed.starts_with('!')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_comment_preserves_hash_inside_quotes() {
        assert_eq!(
            strip_line_comment(r#"gem "foo#bar", "1.0" # trailing"#).trim(),
            r#"gem "foo#bar", "1.0""#
        );
        assert_eq!(strip_line_comment("gem 'x' # comment").trim(), "gem 'x'");
    }

    #[test]
    fn detects_hash_rocket_and_keyword_non_registry() {
        assert!(is_non_registry_gem_line(
            r#"gem "local", :path => "../local""#
        ));
        assert!(is_non_registry_gem_line(
            r#"gem "remote", :git => "https://example.test/x.git""#
        ));
        assert!(is_non_registry_gem_line(
            r#"gem "gh", :github => "org/repo""#
        ));
        assert!(is_non_registry_gem_line(r#"gem "local", path: "../local""#));
        assert!(!is_non_registry_gem_line(r#"gem "rack", "2.2.8""#));
    }

    #[test]
    fn requirement_detector() {
        assert!(looks_like_requirement(">= 0"));
        assert!(looks_like_requirement("~> 1.0"));
        assert!(!looks_like_requirement("2.2.8"));
        assert!(!looks_like_requirement("1.0.0-x86_64-linux"));
    }
}
