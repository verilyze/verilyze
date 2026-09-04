// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_lsp::{LspServer, ScanDiagnostic, ScanResult, ScanService};

#[test]
fn initialized_publishes_diagnostic_from_scan_service() {
    let server = LspServer::new(Box::new(FixedScanService));
    let output = server.handle_message(
        r#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#,
    );

    assert!(
        output.contains("textDocument/publishDiagnostics"),
        "initialized should publish diagnostics: {output}"
    );
    assert!(
        output.contains("CVE-2026-1234"),
        "diagnostic should contain the advisory ID: {output}"
    );
}

struct FixedScanService;

impl ScanService for FixedScanService {
    fn scan(&self, _root: Option<&std::path::Path>) -> ScanResult {
        ScanResult {
            diagnostics: vec![ScanDiagnostic {
                uri: "file:///workspace/Cargo.toml".to_string(),
                line: 0,
                code: "CVE-2026-1234".to_string(),
                message: "CVE-2026-1234: update to 1.2.3".to_string(),
            }],
        }
    }
}
