// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Rust Tier D: first-party `syn` AST path matching (FR-032).
//!
//! v1 limits: no macro expansion, no inter-procedural call graph, trivial
//! `use` aliases only. Parse failure is a skip (not absence). Bare last
//! idents such as `clone` are not evidence unless crate-qualified.

use std::collections::HashMap;

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{ItemUse, Path as SynPath, UseTree};

/// 1-based line numbers where `symbol` appears as a crate-qualified path.
pub fn symbol_match_lines(content: &str, symbol: &str) -> Vec<u32> {
    if symbol.is_empty() {
        return Vec::new();
    }
    let Ok(file) = syn::parse_file(content) else {
        return Vec::new();
    };
    let mut visitor = PathCollector::default();
    visitor.visit_file(&file);
    let mut lines = Vec::new();
    for (path, line) in visitor.paths {
        let expanded = expand_alias(&path, &visitor.aliases);
        if path_matches_symbol(&path, symbol)
            || path_matches_symbol(&expanded, symbol)
        {
            lines.push(line);
        }
    }
    lines.sort_unstable();
    lines.dedup();
    lines
}

fn normalize_path(path: &str) -> String {
    path.trim().trim_start_matches("::").replace('-', "_")
}

fn path_matches_symbol(path: &str, symbol: &str) -> bool {
    let path = normalize_path(path);
    let symbol = normalize_path(symbol);
    if path.is_empty() || symbol.is_empty() {
        return false;
    }
    if path == symbol {
        return path.contains("::");
    }
    path.ends_with(&format!("::{symbol}"))
}

fn expand_alias(path: &str, aliases: &HashMap<String, String>) -> String {
    let path = path.trim_start_matches("::");
    let Some((head, rest)) = path.split_once("::") else {
        if let Some(full) = aliases.get(path) {
            return full.clone();
        }
        return path.to_string();
    };
    if let Some(full) = aliases.get(head) {
        if rest.is_empty() {
            return full.clone();
        }
        return format!("{full}::{rest}");
    }
    path.to_string()
}

#[derive(Default)]
struct PathCollector {
    paths: Vec<(String, u32)>,
    aliases: HashMap<String, String>,
}

impl PathCollector {
    fn record_path(&mut self, path: &SynPath) {
        let segs: Vec<String> =
            path.segments.iter().map(|s| s.ident.to_string()).collect();
        if segs.is_empty() {
            return;
        }
        let joined = segs.join("::");
        let line = path.span().start().line as u32;
        if line == 0 {
            return;
        }
        self.paths.push((joined, line));
    }

    fn record_use_tree(&mut self, prefix: &str, tree: &UseTree) {
        match tree {
            UseTree::Path(p) => {
                let next = if prefix.is_empty() {
                    p.ident.to_string()
                } else {
                    format!("{prefix}::{}", p.ident)
                };
                self.record_use_tree(&next, &p.tree);
            }
            UseTree::Name(name) => {
                let ident = name.ident.to_string();
                let full = if prefix.is_empty() {
                    ident.clone()
                } else {
                    format!("{prefix}::{ident}")
                };
                self.aliases.insert(ident, full);
            }
            UseTree::Rename(rename) => {
                let ident = rename.ident.to_string();
                let full = if prefix.is_empty() {
                    ident
                } else {
                    format!("{prefix}::{ident}")
                };
                self.aliases.insert(rename.rename.to_string(), full);
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.record_use_tree(prefix, item);
                }
            }
            UseTree::Glob(_) => {}
        }
    }
}

impl<'ast> Visit<'ast> for PathCollector {
    fn visit_item_use(&mut self, item: &'ast ItemUse) {
        self.record_use_tree("", &item.tree);
        syn::visit::visit_item_use(self, item);
    }

    fn visit_path(&mut self, path: &'ast SynPath) {
        self.record_path(path);
        syn::visit::visit_path(self, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_detects_qualified_call() {
        let src = "fn main() { http::a::vuln_fn(); }\n";
        assert!(!symbol_match_lines(src, "http::a::vuln_fn").is_empty());
        assert_eq!(symbol_match_lines(src, "http::a::vuln_fn"), vec![1]);
    }

    #[test]
    fn ast_ignores_comment_and_string() {
        let src = "// http::a::vuln_fn\nfn main() { let s = \"http::a::vuln_fn\"; }\n";
        assert!(symbol_match_lines(src, "http::a::vuln_fn").is_empty());
    }

    #[test]
    fn ast_resolves_trivial_use_alias() {
        let src = "use http::Vuln as V;\nfn main() { V::run(); }\n";
        assert!(!symbol_match_lines(src, "http::Vuln::run").is_empty());
    }

    #[test]
    fn ast_rejects_bare_clone() {
        let src = "fn main() { let x = 1; let _ = x.clone(); }\n";
        assert!(symbol_match_lines(src, "clone").is_empty());
    }

    #[test]
    fn unparseable_is_not_a_match() {
        let src = "fn main() { this is not rust\n";
        assert!(symbol_match_lines(src, "http::a::vuln_fn").is_empty());
    }
}
