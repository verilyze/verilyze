// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Content-addressed cache keys for pip lock resolution within a scan.

use sha2::{Digest, Sha256};
use vlz_manifest_parser::ResolveContext;

/// Cache-key suffix when executable resolution is enabled (pip lock omits `--only-binary`).
pub const CACHE_KEY_EXEC_ENABLED: &str = "exec=1";

/// Cache-key suffix when executable resolution is disabled (secure default).
pub const CACHE_KEY_EXEC_DISABLED: &str = "exec=0";

/// Build a stable cache key from manifest bytes and resolution flags that affect pip lock argv.
pub fn manifest_cache_key(content: &str, ctx: &ResolveContext) -> String {
    let exec_tag = if ctx.allow_dependency_code_execution {
        CACHE_KEY_EXEC_ENABLED
    } else {
        CACHE_KEY_EXEC_DISABLED
    };
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hasher.update(exec_tag.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_cache_key_same_content_same_key() {
        let ctx = ResolveContext::default();
        let a = manifest_cache_key("requests>=2.0\n", &ctx);
        let b = manifest_cache_key("requests>=2.0\n", &ctx);
        assert_eq!(a, b);
    }

    #[test]
    fn manifest_cache_key_differs_by_content() {
        let ctx = ResolveContext::default();
        let a = manifest_cache_key("requests>=2.0\n", &ctx);
        let b = manifest_cache_key("flask>=2.0\n", &ctx);
        assert_ne!(a, b);
    }

    #[test]
    fn manifest_cache_key_differs_by_exec_flag() {
        let content = "requests>=2.0\n";
        let disabled = manifest_cache_key(
            content,
            &ResolveContext {
                allow_dependency_code_execution: false,
                ..Default::default()
            },
        );
        let enabled = manifest_cache_key(
            content,
            &ResolveContext {
                allow_dependency_code_execution: true,
                ..Default::default()
            },
        );
        assert_ne!(disabled, enabled);
    }
}
