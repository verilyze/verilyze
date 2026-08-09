// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_javascript::JsManifestParser;
use vlz_manifest_parser::Parser;

#[tokio::test]
async fn parse_simple_package_json() {
    let dir = tempfile::tempdir().unwrap();
    let tmp = dir.path();
    std::fs::write(
        tmp.join("package.json"),
        r#"{
  "name": "demo",
  "dependencies": {
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "typescript": "^5.0.0"
  }
}
"#,
    )
    .unwrap();

    let parser = JsManifestParser::new();
    let graph = parser.parse(&tmp.join("package.json")).await.unwrap();
    assert_eq!(graph.packages.len(), 2);
    assert!(graph.packages.iter().any(|p| p.name == "lodash"));
    assert!(graph.packages.iter().any(|p| p.name == "typescript"));
}
