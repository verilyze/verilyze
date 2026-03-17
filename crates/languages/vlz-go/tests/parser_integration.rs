// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_go::GoModParser;
use vlz_manifest_parser::Parser;

#[tokio::test]
async fn parse_simple_go_mod() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::create_dir_all(tmp).unwrap();
    std::fs::write(
        tmp.join("go.mod"),
        r#"module example.com/test
go 1.21

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.0
)
"#,
    )
    .unwrap();

    let parser = GoModParser::new();
    let graph = parser.parse(&tmp.join("go.mod")).await.unwrap();
    assert_eq!(graph.packages.len(), 2);
    assert!(
        graph
            .packages
            .iter()
            .any(|p| p.name == "github.com/gin-gonic/gin")
    );
    assert!(
        graph
            .packages
            .iter()
            .any(|p| p.name == "github.com/stretchr/testify")
    );
}
