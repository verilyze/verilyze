// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Parse `setup.py` via AST to extract direct dependencies from setuptools `setup()` calls.
//!
//! This is the lock-less, pip-less fallback for CVE scanning. FR-023 pip install from the
//! project directory handles dynamic manifests; do not rely on AST completeness for that path.

use std::collections::HashMap;

use ruff_python_ast::{
    Expr, ExprAttribute, ExprBinOp, ExprCall, ExprList, ExprName,
    ExprStringLiteral, Operator, Stmt, StmtAssign,
};
use ruff_python_parser::{ParseError, parse_module};
use std::path::Path;
use vlz_db::DeclarationKind;
use vlz_manifest_parser::{ParsedDependency, ParserError};

use super::pep508::parse_pep508_dependency;

/// Maximum `setup.py` file size accepted before parsing (1 MiB).
pub const SETUP_PY_MAX_BYTES: usize = 1024 * 1024;

/// Maximum delimiter nesting depth before rejecting input.
/// Maximum delimiter nesting depth accepted before parsing.
/// Kept below `ruff_python_parser`'s default `max_recursion_depth` (202).
pub const SETUP_PY_MAX_NESTING: usize = 200;

const DEP_KEY_INSTALL_REQUIRES: &str = "install_requires";
const DEP_KEY_EXTRAS_REQUIRE: &str = "extras_require";
const DEP_KEY_TESTS_REQUIRE: &str = "tests_require";

/// Parse setup.py with declaration line metadata when AST ranges are available.
pub fn parse_setup_py_with_declarations(
    content: &str,
    path: &Path,
) -> Result<Vec<ParsedDependency>, ParserError> {
    check_setup_py_resource_limits(content)?;
    let parsed = parse_module(content).map_err(map_parse_error)?;
    let module = parsed.syntax();
    let const_map = build_const_map(&module.body);
    let mut packages = Vec::new();
    collect_from_body(&module.body, &const_map, &mut packages);
    let mut parsed_deps = Vec::new();
    collect_declarations_from_body(
        content,
        path,
        &module.body,
        &const_map,
        &mut parsed_deps,
    );
    if parsed_deps.is_empty() {
        parsed_deps = packages
            .into_iter()
            .map(|package| ParsedDependency {
                package,
                path: path.to_path_buf(),
                start_line: 1,
                end_line: None,
                kind: DeclarationKind::Manifest,
            })
            .collect();
    }
    Ok(parsed_deps)
}

/// Parse setup.py content into a list of packages (name, version).
/// Public for fuzzing (NFR-020).
pub fn parse_setup_py(
    content: &str,
) -> Result<Vec<vlz_db::Package>, ParserError> {
    check_setup_py_resource_limits(content)?;
    let parsed = parse_module(content).map_err(map_parse_error)?;
    let module = parsed.syntax();
    let const_map = build_const_map(&module.body);
    let mut packages = Vec::new();
    collect_from_body(&module.body, &const_map, &mut packages);
    Ok(packages)
}

fn map_parse_error(err: ParseError) -> ParserError {
    ParserError::Parse(format!("setup.py parse error: {err}"))
}

fn check_setup_py_resource_limits(content: &str) -> Result<(), ParserError> {
    if content.len() > SETUP_PY_MAX_BYTES {
        return Err(ParserError::Parse(format!(
            "setup.py exceeds maximum size of {SETUP_PY_MAX_BYTES} bytes"
        )));
    }
    if delimiter_nesting_depth(content) > SETUP_PY_MAX_NESTING {
        return Err(ParserError::Parse(format!(
            "setup.py exceeds maximum delimiter nesting depth of {SETUP_PY_MAX_NESTING}"
        )));
    }
    Ok(())
}

/// Count max nesting of `()`, `[]`, and `{}` outside of string literals and comments.
fn delimiter_nesting_depth(content: &str) -> usize {
    let mut max_depth = 0usize;
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_triple_single = false;
    let mut in_triple_double = false;
    let mut in_comment = false;
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
            }
            continue;
        }

        if !in_single
            && !in_double
            && !in_triple_single
            && !in_triple_double
            && ch == '#'
        {
            in_comment = true;
            continue;
        }

        if !in_double && !in_triple_double && ch == '\'' {
            if in_single {
                in_single = false;
            } else if chars.peek() == Some(&'\'') {
                let _ = chars.next();
                if chars.peek() == Some(&'\'') {
                    let _ = chars.next();
                    in_triple_single = !in_triple_single;
                } else {
                    in_single = true;
                }
            } else {
                in_single = !in_single;
            }
            continue;
        }

        if !in_single && !in_triple_single && ch == '"' {
            if in_double {
                in_double = false;
            } else if chars.peek() == Some(&'"') {
                let _ = chars.next();
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                    in_triple_double = !in_triple_double;
                } else {
                    in_double = true;
                }
            } else {
                in_double = !in_double;
            }
            continue;
        }

        if in_single || in_double || in_triple_single || in_triple_double {
            continue;
        }

        match ch {
            '(' | '[' | '{' => {
                depth += 1;
                max_depth = max_depth.max(depth);
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }

    max_depth
}

fn build_const_map(body: &[Stmt]) -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    for stmt in body {
        if let Stmt::Assign(StmtAssign { targets, value, .. }) = stmt
            && targets.len() == 1
            && let Some(name) = target_name(&targets[0])
        {
            let strings = extract_string_list(value, &HashMap::new());
            if !strings.is_empty() {
                map.insert(name, strings);
            }
        }
    }
    map
}

fn target_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(ExprName { id, .. }) => Some(id.to_string()),
        _ => None,
    }
}

fn line_number_for_spec(content: &str, spec: &str) -> u32 {
    for (i, line) in content.lines().enumerate() {
        if line.contains(spec) {
            return (i + 1) as u32;
        }
    }
    1
}

fn collect_declarations_from_body(
    content: &str,
    path: &Path,
    body: &[Stmt],
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<ParsedDependency>,
) {
    for stmt in body {
        if let Stmt::Expr(ruff_python_ast::StmtExpr { value, .. }) = stmt
            && let Expr::Call(call) = value.as_ref()
            && is_setup_call(&call.func)
        {
            extract_setup_call_declarations(
                content, path, call, const_map, out,
            );
        }
    }
}

fn extract_setup_call_declarations(
    content: &str,
    path: &Path,
    call: &ExprCall,
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<ParsedDependency>,
) {
    for kw in &call.arguments.keywords {
        let Some(arg) = kw.arg.as_ref() else {
            continue;
        };
        match arg.id().as_str() {
            DEP_KEY_INSTALL_REQUIRES | DEP_KEY_TESTS_REQUIRE => {
                push_declarations_from_expr(
                    content, path, &kw.value, const_map, out,
                );
            }
            DEP_KEY_EXTRAS_REQUIRE => {
                push_extras_declarations_from_expr(
                    content, path, &kw.value, const_map, out,
                );
            }
            _ => {}
        }
    }
}

fn push_extras_declarations_from_expr(
    content: &str,
    path: &Path,
    expr: &Expr,
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<ParsedDependency>,
) {
    if let Expr::Dict(dict) = expr {
        for item in &dict.items {
            push_declarations_from_expr(
                content,
                path,
                &item.value,
                const_map,
                out,
            );
        }
    }
}

fn push_declarations_from_expr(
    content: &str,
    path: &Path,
    expr: &Expr,
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<ParsedDependency>,
) {
    for spec in extract_string_list(expr, const_map) {
        if let Some(pkg) = parse_pep508_dependency(&spec) {
            out.push(ParsedDependency {
                package: pkg,
                path: path.to_path_buf(),
                start_line: line_number_for_spec(content, &spec),
                end_line: None,
                kind: DeclarationKind::Manifest,
            });
        }
    }
}

fn collect_from_body(
    body: &[Stmt],
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<vlz_db::Package>,
) {
    for stmt in body {
        if let Stmt::Expr(ruff_python_ast::StmtExpr { value, .. }) = stmt
            && let Expr::Call(call) = value.as_ref()
            && is_setup_call(&call.func)
        {
            extract_setup_call_deps(call, const_map, out);
        }
    }
}

fn is_setup_call(func: &Expr) -> bool {
    match func {
        Expr::Name(ExprName { id, .. }) => id.as_str() == "setup",
        Expr::Attribute(ExprAttribute { attr, .. }) => {
            attr.as_str() == "setup"
        }
        _ => false,
    }
}

fn extract_setup_call_deps(
    call: &ExprCall,
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<vlz_db::Package>,
) {
    for kw in &call.arguments.keywords {
        let Some(arg) = kw.arg.as_ref() else {
            continue;
        };
        match arg.id().as_str() {
            DEP_KEY_INSTALL_REQUIRES | DEP_KEY_TESTS_REQUIRE => {
                push_deps_from_expr(&kw.value, const_map, out);
            }
            DEP_KEY_EXTRAS_REQUIRE => {
                push_extras_from_expr(&kw.value, const_map, out);
            }
            _ => {}
        }
    }
}

fn push_extras_from_expr(
    expr: &Expr,
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<vlz_db::Package>,
) {
    if let Expr::Dict(dict) = expr {
        for item in &dict.items {
            push_deps_from_expr(&item.value, const_map, out);
        }
    }
}

fn push_deps_from_expr(
    expr: &Expr,
    const_map: &HashMap<String, Vec<String>>,
    out: &mut Vec<vlz_db::Package>,
) {
    for spec in extract_string_list(expr, const_map) {
        if let Some(pkg) = parse_pep508_dependency(&spec) {
            out.push(pkg);
        }
    }
}

fn extract_string_list(
    expr: &Expr,
    const_map: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    match expr {
        Expr::List(ExprList { elts, .. }) => {
            elts.iter().filter_map(expr_to_string).collect()
        }
        Expr::BinOp(ExprBinOp {
            left,
            op: Operator::Add,
            right,
            ..
        }) => {
            let mut out = extract_string_list(left, const_map);
            out.extend(extract_string_list(right, const_map));
            out
        }
        Expr::Name(ExprName { id, .. }) => {
            const_map.get(id.as_str()).cloned().unwrap_or_default()
        }
        _ => Vec::new(),
    }
}

fn expr_to_string(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            value.iter().next().map(|lit| lit.value.to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct ExpectedFixture {
        package: Vec<vlz_db::Package>,
    }

    fn assert_matches_fixture(
        actual: &[vlz_db::Package],
        expected_toml: &str,
    ) {
        let expected: ExpectedFixture =
            toml::from_str(expected_toml).expect("expected fixture toml");
        let mut actual_sorted: Vec<_> = actual.to_vec();
        let mut expected_sorted = expected.package;
        actual_sorted.sort_by(|a, b| a.name.cmp(&b.name));
        expected_sorted.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(actual_sorted, expected_sorted);
    }

    fn parse_fixture_with_expected(name: &str) {
        let py = match name {
            "classic_import_setup" => include_str!(
                "../../tests/fixtures/setup_py/classic_import_setup.py"
            ),
            "setuptools_module_call" => include_str!(
                "../../tests/fixtures/setup_py/setuptools_module_call.py"
            ),
            "extras_and_tests" => {
                include_str!(
                    "../../tests/fixtures/setup_py/extras_and_tests.py"
                )
            }
            "module_level_constants" => include_str!(
                "../../tests/fixtures/setup_py/module_level_constants.py"
            ),
            "binop_list_concat" => {
                include_str!(
                    "../../tests/fixtures/setup_py/binop_list_concat.py"
                )
            }
            _ => panic!("unknown fixture {name}"),
        };
        let expected = match name {
            "classic_import_setup" => include_str!(
                "../../tests/fixtures/setup_py/classic_import_setup.expected.toml"
            ),
            "setuptools_module_call" => include_str!(
                "../../tests/fixtures/setup_py/setuptools_module_call.expected.toml"
            ),
            "extras_and_tests" => include_str!(
                "../../tests/fixtures/setup_py/extras_and_tests.expected.toml"
            ),
            "module_level_constants" => include_str!(
                "../../tests/fixtures/setup_py/module_level_constants.expected.toml"
            ),
            "binop_list_concat" => include_str!(
                "../../tests/fixtures/setup_py/binop_list_concat.expected.toml"
            ),
            _ => panic!("unknown fixture {name}"),
        };
        let packages = parse_setup_py(py).expect("parse fixture");
        assert!(
            !packages.is_empty(),
            "fixture {name} must not silently return empty when sidecar lists packages"
        );
        assert_matches_fixture(&packages, expected);
    }

    #[test]
    fn classic_import_setup() {
        parse_fixture_with_expected("classic_import_setup");
    }

    #[test]
    fn setuptools_module_call() {
        parse_fixture_with_expected("setuptools_module_call");
    }

    #[test]
    fn extras_and_tests() {
        parse_fixture_with_expected("extras_and_tests");
    }

    #[test]
    fn module_level_constants() {
        parse_fixture_with_expected("module_level_constants");
    }

    #[test]
    fn binop_list_concat() {
        parse_fixture_with_expected("binop_list_concat");
    }

    #[test]
    fn syntax_error() {
        let content =
            include_str!("../../tests/fixtures/setup_py/syntax_error.py");
        let err = parse_setup_py(content).unwrap_err();
        assert!(err.to_string().contains("parse error"));
    }

    #[test]
    fn dynamic_only() {
        let content =
            include_str!("../../tests/fixtures/setup_py/dynamic_only.py");
        let packages = parse_setup_py(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn no_setup_call() {
        let content =
            include_str!("../../tests/fixtures/setup_py/no_setup_call.py");
        let packages = parse_setup_py(content).unwrap();
        assert!(packages.is_empty());
    }

    #[test]
    fn rejects_setup_py_larger_than_limit() {
        let mut content = "x".repeat(SETUP_PY_MAX_BYTES + 1);
        content.push_str("\nfrom setuptools import setup\nsetup()\n");
        let err = parse_setup_py(&content).unwrap_err();
        assert!(err.to_string().contains("maximum size"));
    }

    #[test]
    fn rejects_deeply_nested_delimiters_before_ruff() {
        let open = "[".repeat(SETUP_PY_MAX_NESTING + 1);
        let close = "]".repeat(SETUP_PY_MAX_NESTING + 1);
        let content =
            format!("from setuptools import setup\nsetup({open}1{close})\n");
        let err = parse_setup_py(&content).unwrap_err();
        assert!(err.to_string().contains("nesting depth"));
    }

    #[test]
    fn accepts_nesting_at_limit_boundary() {
        // `setup(` contributes one level; inner parens fill the remaining budget.
        let inner_open = "(".repeat(SETUP_PY_MAX_NESTING - 1);
        let inner_close = ")".repeat(SETUP_PY_MAX_NESTING - 1);
        let content = format!(
            "from setuptools import setup\nsetup({inner_open}{inner_close})\n"
        );
        let packages = parse_setup_py(&content).unwrap();
        assert!(packages.is_empty());
    }

    mod ast_contract {
        use super::*;
        use ruff_python_ast::{Expr, ExprCall, Stmt};
        use ruff_python_parser::parse_module;

        #[test]
        fn classic_fixture_has_setup_call_with_install_requires() {
            let content = include_str!(
                "../../tests/fixtures/setup_py/classic_import_setup.py"
            );
            let parsed = parse_module(content).expect("module parses");
            let body = &parsed.syntax().body;
            let call = find_setup_call(body).expect("setup() call");
            let kw = call
                .arguments
                .keywords
                .iter()
                .find(|k| {
                    k.arg.as_ref().is_some_and(|a| {
                        a.id().as_str() == DEP_KEY_INSTALL_REQUIRES
                    })
                })
                .expect("install_requires keyword");
            assert!(matches!(&kw.value, Expr::List(_)));

            let packages = parse_setup_py(content).unwrap();
            assert!(!packages.is_empty());
        }

        fn find_setup_call(body: &[Stmt]) -> Option<&ExprCall> {
            for stmt in body {
                if let Stmt::Expr(ruff_python_ast::StmtExpr { value, .. }) =
                    stmt
                    && let Expr::Call(call) = value.as_ref()
                    && is_setup_call(&call.func)
                {
                    return Some(call);
                }
            }
            None
        }
    }
}
