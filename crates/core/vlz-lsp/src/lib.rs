// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

#![deny(unsafe_code)]

//! Stdio Language Server Protocol adapter for verilyze scan diagnostics.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lsp_server::{Connection, Message, Notification, Response};
use lsp_types::{
    CodeActionKind, CodeActionOptions, CodeActionProviderCapability,
    Diagnostic, DiagnosticSeverity, InitializeParams, NumberOrString,
    PublishDiagnosticsParams, ServerCapabilities, TextDocumentSyncCapability,
    TextDocumentSyncKind, WorkspaceFoldersServerCapabilities,
    WorkspaceServerCapabilities,
};
use serde_json::json;
use url::Url;

pub const SERVER_NAME: &str = "vlz";
pub const DIAGNOSTIC_SOURCE: &str = "vlz";
pub const SHOW_UPGRADE_PLAN_COMMAND: &str = "vlz.showUpgradePlan";
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// A diagnostic-ready scan result.
#[derive(Debug, Clone, Default)]
pub struct ScanResult {
    pub diagnostics: Vec<ScanDiagnostic>,
}

/// A vulnerability diagnostic emitted by the scan adapter.
#[derive(Debug, Clone)]
pub struct ScanDiagnostic {
    pub uri: String,
    pub line: u32,
    pub code: String,
    pub message: String,
}

/// Narrow scan boundary supplied by the binary crate.
pub trait ScanService: Send + Sync {
    /// Scan one workspace root without executing dependency code.
    fn scan(&self, root: Option<&Path>) -> ScanResult;
}

/// Stateless message handler used by protocol tests and the stdio server.
pub struct LspServer {
    scan_service: Box<dyn ScanService>,
    published_uris: Mutex<BTreeSet<String>>,
}

impl LspServer {
    pub fn new(scan_service: Box<dyn ScanService>) -> Self {
        Self {
            scan_service,
            published_uris: Mutex::new(BTreeSet::new()),
        }
    }

    /// Handle a JSON-RPC notification and return one notification, if needed.
    ///
    /// The stdio runner parses Content-Length framing through `lsp-server`; this
    /// helper intentionally covers only decoded JSON messages for small tests.
    pub fn handle_message(&self, message: &str) -> String {
        if message.len() > MAX_MESSAGE_BYTES {
            return String::new();
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(message)
        else {
            return String::new();
        };
        if value.get("method").and_then(|v| v.as_str()) != Some("initialized")
        {
            return String::new();
        }
        self.diagnostic_messages(self.scan_service.scan(None), None)
            .into_iter()
            .next()
            .unwrap_or_default()
    }
}

/// Run the blocking stdio protocol loop.
pub fn run_stdio(scan_service: Box<dyn ScanService>) -> anyhow::Result<()> {
    let (connection, io_threads) = Connection::stdio();
    let (initialize_id, initialize_params) = connection.initialize_start()?;
    let params: InitializeParams = serde_json::from_value(initialize_params)?;
    let workspace_root = workspace_root(&params);
    let capabilities = server_capabilities();
    connection.initialize_finish(
        initialize_id,
        json!({
            "capabilities": capabilities,
            "serverInfo": { "name": SERVER_NAME },
        }),
    )?;

    let server = LspServer::new(scan_service);
    send_diagnostics(
        &connection,
        server.diagnostic_messages(
            server.scan_service.scan(workspace_root.as_deref()),
            workspace_root.as_deref(),
        ),
    )?;
    for message in &connection.receiver {
        match message {
            Message::Notification(notification)
                if notification.method == "exit" =>
            {
                break;
            }
            Message::Notification(notification)
                if notification.method == "textDocument/didSave" =>
            {
                send_diagnostics(
                    &connection,
                    server.diagnostic_messages(
                        server.scan_service.scan(workspace_root.as_deref()),
                        workspace_root.as_deref(),
                    ),
                )?;
            }
            Message::Request(request) if request.method == "shutdown" => {
                connection.sender.send(
                    Response::new_ok(
                        request.id.clone(),
                        serde_json::Value::Null,
                    )
                    .into(),
                )?;
            }
            Message::Request(request)
                if request.method == "textDocument/codeAction" =>
            {
                let actions = show_plan_action(&request.params);
                connection.sender.send(
                    Response::new_ok(request.id.clone(), actions).into(),
                )?;
            }
            Message::Request(request)
                if request.method == "workspace/executeCommand" =>
            {
                execute_command(&connection, &request)?;
            }
            Message::Request(request) => {
                connection.sender.send(
                    Response::new_err(
                        request.id.clone(),
                        lsp_server::ErrorCode::MethodNotFound as i32,
                        format!("unsupported LSP request: {}", request.method),
                    )
                    .into(),
                )?;
            }
            _ => {}
        }
    }
    io_threads.join()?;
    Ok(())
}

fn server_capabilities() -> ServerCapabilities {
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(
            TextDocumentSyncKind::FULL,
        )),
        code_action_provider: Some(CodeActionProviderCapability::Options(
            CodeActionOptions {
                code_action_kinds: Some(vec![CodeActionKind::QUICKFIX]),
                resolve_provider: Some(false),
                work_done_progress_options: Default::default(),
            },
        )),
        workspace: Some(WorkspaceServerCapabilities {
            workspace_folders: Some(WorkspaceFoldersServerCapabilities {
                supported: Some(true),
                change_notifications: Some(lsp_types::OneOf::Left(false)),
            }),
            file_operations: None,
        }),
        ..Default::default()
    }
}

fn workspace_root(params: &InitializeParams) -> Option<PathBuf> {
    let uri = params
        .workspace_folders
        .as_ref()
        .and_then(|folders| folders.first())
        .map(|folder| folder.uri.as_str())?;
    local_file_path(uri)
}

fn local_file_path(uri: &str) -> Option<PathBuf> {
    let url = Url::parse(uri).ok()?;
    url.to_file_path().ok()
}

/// Convert an absolute local path to an LSP `file:` URI.
pub fn file_uri_for_path(path: &Path) -> Option<String> {
    Url::from_file_path(path).ok().map(|url| url.into())
}

impl LspServer {
    fn diagnostic_messages(
        &self,
        scan_result: ScanResult,
        workspace_root: Option<&Path>,
    ) -> Vec<String> {
        let mut by_uri: BTreeMap<String, Vec<Diagnostic>> = BTreeMap::new();
        for scan in scan_result.diagnostics {
            if !is_workspace_uri(&scan.uri, workspace_root) {
                continue;
            }
            if let Some(diagnostic) = diagnostic_from_scan(scan.clone()) {
                by_uri.entry(scan.uri).or_default().push(diagnostic);
            }
        }
        let mut published = self
            .published_uris
            .lock()
            .expect("published URI lock poisoned");
        let current_uris: BTreeSet<String> = by_uri.keys().cloned().collect();
        let stale_uris: Vec<String> =
            published.difference(&current_uris).cloned().collect();
        published.clone_from(&current_uris);
        by_uri
            .into_iter()
            .map(|(uri, diagnostics)| serialize_diagnostics(&uri, diagnostics))
            .chain(
                stale_uris
                    .into_iter()
                    .map(|uri| serialize_diagnostics(&uri, Vec::new())),
            )
            .collect()
    }
}

fn is_workspace_uri(uri: &str, workspace_root: Option<&Path>) -> bool {
    let Some(path) = local_file_path(uri) else {
        return false;
    };
    let Some(root) = workspace_root else {
        return true;
    };
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    path.starts_with(root)
}

fn serialize_diagnostics(uri: &str, diagnostics: Vec<Diagnostic>) -> String {
    let Ok(uri) = uri.parse::<lsp_types::Uri>() else {
        return String::new();
    };
    let params = PublishDiagnosticsParams {
        uri,
        diagnostics,
        version: None,
    };
    serde_json::to_string(&Notification::new(
        "textDocument/publishDiagnostics".to_string(),
        serde_json::to_value(params).expect("diagnostics serialize"),
    ))
    .expect("notification serialize")
}

fn send_diagnostics(
    connection: &Connection,
    messages: Vec<String>,
) -> anyhow::Result<()> {
    for message in messages {
        connection
            .sender
            .send(serde_json::from_str::<Message>(&message)?)?;
    }
    Ok(())
}

fn diagnostic_from_scan(scan: ScanDiagnostic) -> Option<Diagnostic> {
    scan.uri.parse::<lsp_types::Uri>().ok()?;
    Some(Diagnostic {
        range: lsp_types::Range {
            start: lsp_types::Position {
                line: scan.line,
                character: 0,
            },
            end: lsp_types::Position {
                line: scan.line,
                character: 0,
            },
        },
        severity: Some(DiagnosticSeverity::WARNING),
        code: Some(NumberOrString::String(scan.code)),
        code_description: None,
        source: Some(DIAGNOSTIC_SOURCE.to_string()),
        message: scan.message,
        related_information: None,
        tags: None,
        data: None,
    })
}

fn show_plan_action(params: &serde_json::Value) -> serde_json::Value {
    let message = params
        .pointer("/context/diagnostics/0/message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("No upgrade plan is available for this diagnostic.");
    json!([{
        "title": "Show upgrade plan",
        "kind": "quickfix",
        "command": {
            "title": "Show upgrade plan",
            "command": SHOW_UPGRADE_PLAN_COMMAND,
            "arguments": [message],
        },
    }])
}

fn execute_command(
    connection: &Connection,
    request: &lsp_server::Request,
) -> anyhow::Result<()> {
    let command = request
        .params
        .get("command")
        .and_then(serde_json::Value::as_str);
    if command != Some(SHOW_UPGRADE_PLAN_COMMAND) {
        connection.sender.send(
            Response::new_err(
                request.id.clone(),
                lsp_server::ErrorCode::MethodNotFound as i32,
                "unsupported LSP command".to_string(),
            )
            .into(),
        )?;
        return Ok(());
    }
    let message = request
        .params
        .pointer("/arguments/0")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("No upgrade plan is available for this diagnostic.");
    connection.sender.send(
        Notification::new(
            "window/showMessage".to_string(),
            json!({ "type": 3, "message": message }),
        )
        .into(),
    )?;
    connection.sender.send(
        Response::new_ok(request.id.clone(), serde_json::Value::Null).into(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        SHOW_UPGRADE_PLAN_COMMAND, server_capabilities, workspace_root,
    };
    use lsp_types::{
        InitializeParams, TextDocumentSyncCapability,
        TextDocumentSyncSaveOptions,
    };
    use serde_json::json;

    #[test]
    fn root_uri_is_used_without_workspace_folders() {
        let params: InitializeParams = serde_json::from_value(json!({
            "processId": null,
            "rootUri": "file:///workspace",
            "capabilities": {},
        }))
        .expect("initialize parameters should deserialize");

        assert_eq!(
            workspace_root(&params).as_deref(),
            Some("/workspace".as_ref())
        );
    }

    #[test]
    fn capabilities_advertise_save_only_sync_and_plan_command() {
        let capabilities = server_capabilities();
        let TextDocumentSyncCapability::Options(sync) = capabilities
            .text_document_sync
            .expect("server should advertise text sync options")
        else {
            panic!("server must not advertise unsupported full document sync");
        };
        assert_eq!(sync.change, None);
        assert!(matches!(
            sync.save,
            Some(TextDocumentSyncSaveOptions::SaveOptions(_))
        ));
        assert_eq!(
            capabilities
                .execute_command_provider
                .expect("server should advertise the plan command")
                .commands,
            vec![SHOW_UPGRADE_PLAN_COMMAND.to_string()]
        );
    }
}
