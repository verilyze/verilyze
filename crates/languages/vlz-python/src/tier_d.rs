// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Python Tier D reachability refinement using AST name/load nodes (FR-032 stretch).

use ruff_python_ast::{
    Expr, ExprAttribute, ExprCall, ExprName, Stmt, StmtAssign, StmtExpr,
    StmtFunctionDef, StmtIf, StmtReturn, StmtWhile,
};
use ruff_python_parser::parse_module;

/// True when parsed source references `symbol` in a name or attribute node.
pub fn file_references_symbol(content: &str, symbol: &str) -> bool {
    if symbol.is_empty() {
        return false;
    }
    let Ok(parsed) = parse_module(content) else {
        return false;
    };
    let mut found = false;
    walk_stmts(&parsed.syntax().body, symbol, &mut found);
    found
}

fn walk_stmts(stmts: &[Stmt], symbol: &str, found: &mut bool) {
    for stmt in stmts {
        if *found {
            return;
        }
        walk_stmt(stmt, symbol, found);
    }
}

fn walk_stmt(stmt: &Stmt, symbol: &str, found: &mut bool) {
    match stmt {
        Stmt::FunctionDef(StmtFunctionDef { body, .. }) => {
            walk_stmts(body, symbol, found)
        }
        Stmt::ClassDef(def) => {
            for base in def.bases() {
                walk_expr(base, symbol, found);
            }
            walk_stmts(&def.body, symbol, found);
        }
        Stmt::If(StmtIf {
            test,
            body,
            elif_else_clauses,
            ..
        }) => {
            walk_expr(test, symbol, found);
            walk_stmts(body, symbol, found);
            for clause in elif_else_clauses {
                if let Some(test) = &clause.test {
                    walk_expr(test, symbol, found);
                }
                walk_stmts(&clause.body, symbol, found);
            }
        }
        Stmt::While(StmtWhile { test, body, .. }) => {
            walk_expr(test, symbol, found);
            walk_stmts(body, symbol, found);
        }
        Stmt::For(stmt_for) => {
            walk_expr(&stmt_for.iter, symbol, found);
            walk_stmts(&stmt_for.body, symbol, found);
        }
        Stmt::With(stmt_with) => {
            for item in &stmt_with.items {
                walk_expr(&item.context_expr, symbol, found);
            }
            walk_stmts(&stmt_with.body, symbol, found);
        }
        Stmt::Try(stmt_try) => {
            walk_stmts(&stmt_try.body, symbol, found);
            walk_stmts(&stmt_try.orelse, symbol, found);
            walk_stmts(&stmt_try.finalbody, symbol, found);
        }
        Stmt::Expr(StmtExpr { value, .. }) => walk_expr(value, symbol, found),
        Stmt::Assign(StmtAssign { value, .. }) => {
            walk_expr(value, symbol, found)
        }
        Stmt::Return(StmtReturn {
            value: Some(value), ..
        }) => walk_expr(value, symbol, found),
        _ => {}
    }
}

fn walk_expr(expr: &Expr, symbol: &str, found: &mut bool) {
    if *found {
        return;
    }
    if expr_matches_symbol(expr, symbol) {
        *found = true;
        return;
    }
    match expr {
        Expr::Call(ExprCall {
            func, arguments, ..
        }) => {
            walk_expr(func, symbol, found);
            for arg in &arguments.args {
                walk_expr(arg, symbol, found);
            }
            for kw in &arguments.keywords {
                walk_expr(&kw.value, symbol, found);
            }
        }
        Expr::Attribute(attr) => walk_expr(&attr.value, symbol, found),
        Expr::List(list) => {
            for elt in &list.elts {
                walk_expr(elt, symbol, found);
            }
        }
        Expr::Tuple(tuple) => {
            for elt in &tuple.elts {
                walk_expr(elt, symbol, found);
            }
        }
        Expr::Dict(dict) => {
            for item in &dict.items {
                if let Some(key) = &item.key {
                    walk_expr(key, symbol, found);
                }
                walk_expr(&item.value, symbol, found);
            }
        }
        Expr::Subscript(sub) => {
            walk_expr(&sub.value, symbol, found);
            walk_expr(&sub.slice, symbol, found);
        }
        Expr::BinOp(bin) => {
            walk_expr(&bin.left, symbol, found);
            walk_expr(&bin.right, symbol, found);
        }
        Expr::UnaryOp(unary) => walk_expr(&unary.operand, symbol, found),
        Expr::Compare(cmp) => {
            walk_expr(&cmp.left, symbol, found);
            for right in &cmp.comparators {
                walk_expr(right, symbol, found);
            }
        }
        Expr::If(if_expr) => {
            walk_expr(&if_expr.test, symbol, found);
            walk_expr(&if_expr.body, symbol, found);
            walk_expr(&if_expr.orelse, symbol, found);
        }
        Expr::Lambda(lambda) => walk_expr(&lambda.body, symbol, found),
        _ => {}
    }
}

fn expr_matches_symbol(expr: &Expr, symbol: &str) -> bool {
    match expr {
        Expr::Name(ExprName { id, .. }) => id.as_str() == symbol,
        Expr::Attribute(attr) => attribute_matches(attr, symbol),
        _ => false,
    }
}

fn attribute_matches(attr: &ExprAttribute, symbol: &str) -> bool {
    if let Some(qual) = attribute_qualifier(attr) {
        qual == symbol || qual.ends_with(&format!(".{symbol}"))
    } else {
        false
    }
}

fn attribute_qualifier(attr: &ExprAttribute) -> Option<String> {
    let mut parts = Vec::new();
    let mut current: &Expr = &attr.value;
    parts.push(attr.attr.to_string());
    loop {
        match current {
            Expr::Attribute(inner) => {
                parts.push(inner.attr.to_string());
                current = &inner.value;
            }
            Expr::Name(ExprName { id, .. }) => {
                parts.push(id.to_string());
                parts.reverse();
                return Some(parts.join("."));
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_detects_direct_call() {
        let src = "from pkg import vuln_fn\nvuln_fn()\n";
        assert!(file_references_symbol(src, "vuln_fn"));
    }

    #[test]
    fn ast_ignores_comment_only_match() {
        let src = "# vuln_fn is mentioned here\nimport sys\n";
        assert!(!file_references_symbol(src, "vuln_fn"));
    }

    #[test]
    fn ast_detects_qualified_attribute() {
        let src = "import pkg\npkg.submod.vuln_fn()\n";
        assert!(file_references_symbol(src, "pkg.submod.vuln_fn"));
    }
}
