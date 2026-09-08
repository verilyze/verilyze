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
    Diagnostic, DiagnosticSeverity, ExecuteCommandOptions, InitializeParams,
    NumberOrString, PublishDiagnosticsParams, SaveOptions, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncOptions,
    WorkspaceFoldersServerCapabilities, WorkspaceServerCapabilities,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

pub const SERVER_NAME: &str = "vlz";
pub const DIAGNOSTIC_SOURCE: &str = "vlz";
pub const SHOW_UPGRADE_PLAN_COMMAND: &str = "vlz.showUpgradePlan";
/// Non-writing Code Action: show the CLI dry-run command (FR-042).
///
/// Uses `window/showMessage` (same as show upgrade plan); it does not write
/// the system clipboard.
pub const SHOW_FIX_DRY_RUN_COMMAND: &str = "vlz.showFixDryRun";
/// Code Action title for [`SHOW_FIX_DRY_RUN_COMMAND`].
pub const SHOW_FIX_DRY_RUN_TITLE: &str = "Show vlz fix --dry-run";
pub const FIX_DRY_RUN_CLI: &str = "vlz fix --dry-run";
/// Writing Code Action: apply one upgrade via the Remediator path (FR-043).
pub const APPLY_UPGRADE_COMMAND: &str = "vlz.applyUpgrade";
/// Code Action title for [`APPLY_UPGRADE_COMMAND`].
pub const APPLY_UPGRADE_TITLE: &str = "Apply upgrade";
pub const MAX_MESSAGE_BYTES: usize = 1_048_576;

/// Declaration path carried in Apply upgrade arguments (FR-043).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyDeclaration {
    pub path: String,
    pub start_line: u32,
    pub kind: String,
}

/// Structured apply payload shared by diagnostics and executeCommand (FR-043).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyUpgradeRequest {
    pub package_name: String,
    pub target_version: String,
    pub apply_strategy: String,
    pub dependency_kind: String,
    pub declarations: Vec<ApplyDeclaration>,
}

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
    /// When set, enables Apply upgrade Code Actions under folder trust.
    pub apply: Option<ApplyUpgradeRequest>,
}

/// Narrow scan / apply boundary supplied by the binary crate.
pub trait ScanService: Send + Sync {
    /// Scan one workspace root without executing dependency code.
    ///
    /// `changed` is the saved path when handling `textDocument/didSave`
    /// (NFR-026 incremental). Implementations may skip work when the path is
    /// not a dependency manifest or lock file.
    fn scan(&self, root: Option<&Path>, changed: Option<&Path>) -> ScanResult;

    /// Apply one upgrade plan (FR-043). Default rejects apply.
    fn apply_upgrade(
        &self,
        _root: Option<&Path>,
        _request: &ApplyUpgradeRequest,
    ) -> Result<(), String> {
        Err("Apply upgrade is not available".to_string())
    }
}

/// Basenames that trigger a rescan on save (NFR-026 incremental filter).
pub const DEPENDENCY_SAVE_BASENAMES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "pyproject.toml",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "pylock.toml",
    "setup.cfg",
    "setup.py",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "Gemfile",
    "Gemfile.lock",
    "gems.rb",
    "gems.locked",
];

/// True when a saved path should trigger a dependency rescan.
pub fn is_dependency_save_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| {
            DEPENDENCY_SAVE_BASENAMES.contains(&name)
                || name.ends_with(".cdx.json")
                || name.ends_with(".spdx.json")
                || name.starts_with("pylock.")
                || name.ends_with(".gemspec")
        })
}

/// Stateless message handler used by protocol tests and the stdio server.
pub struct LspServer {
    scan_service: Box<dyn ScanService>,
    published_uris: Mutex<BTreeSet<String>>,
    folder_trust: bool,
    last_result: Mutex<ScanResult>,
}

impl LspServer {
    pub fn new(
        scan_service: Box<dyn ScanService>,
        folder_trust: bool,
    ) -> Self {
        Self {
            scan_service,
            published_uris: Mutex::new(BTreeSet::new()),
            folder_trust,
            last_result: Mutex::new(ScanResult::default()),
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
        let result = self.scan_service.scan(None, None);
        *self.last_result.lock().expect("last result lock poisoned") =
            result.clone();
        self.diagnostic_messages(result, None)
            .into_iter()
            .next()
            .unwrap_or_default()
    }

    fn scan_for_root(
        &self,
        workspace_root: Option<&Path>,
        changed: Option<&Path>,
    ) -> ScanResult {
        if let Some(path) = changed
            && !is_dependency_save_path(path)
        {
            return self
                .last_result
                .lock()
                .expect("last result lock poisoned")
                .clone();
        }
        let result = self.scan_service.scan(workspace_root, changed);
        *self.last_result.lock().expect("last result lock poisoned") =
            result.clone();
        result
    }
}

/// Run the blocking stdio protocol loop.
pub fn run_stdio(
    scan_service: Box<dyn ScanService>,
    folder_trust: bool,
) -> anyhow::Result<()> {
    let (connection, io_threads) = Connection::stdio();
    run_connection(connection, scan_service, folder_trust)?;
    io_threads.join()?;
    Ok(())
}

/// Run the LSP lifecycle for a connection.
fn run_connection(
    connection: Connection,
    scan_service: Box<dyn ScanService>,
    folder_trust: bool,
) -> anyhow::Result<()> {
    let (initialize_id, initialize_params) = connection.initialize_start()?;
    let params: InitializeParams = serde_json::from_value(initialize_params)?;
    let workspace_root = workspace_root(&params);
    let capabilities = server_capabilities(folder_trust);
    connection.initialize_finish(
        initialize_id,
        json!({
            "capabilities": capabilities,
            "serverInfo": { "name": SERVER_NAME },
        }),
    )?;

    let server = LspServer::new(scan_service, folder_trust);
    send_diagnostics(
        &connection,
        server.diagnostic_messages(
            server.scan_for_root(workspace_root.as_deref(), None),
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
                let changed = notification
                    .params
                    .pointer("/textDocument/uri")
                    .and_then(serde_json::Value::as_str)
                    .and_then(local_file_path);
                send_diagnostics(
                    &connection,
                    server.diagnostic_messages(
                        server.scan_for_root(
                            workspace_root.as_deref(),
                            changed.as_deref(),
                        ),
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
                let actions =
                    code_actions(&request.params, server.folder_trust);
                connection.sender.send(
                    Response::new_ok(request.id.clone(), actions).into(),
                )?;
            }
            Message::Request(request)
                if request.method == "workspace/executeCommand" =>
            {
                execute_command(
                    &connection,
                    &request,
                    &server,
                    workspace_root.as_deref(),
                )?;
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
    let Connection { sender, receiver } = connection;
    drop(sender);
    drop(receiver);
    Ok(())
}

fn server_capabilities(folder_trust: bool) -> ServerCapabilities {
    let mut commands = vec![
        SHOW_UPGRADE_PLAN_COMMAND.to_string(),
        SHOW_FIX_DRY_RUN_COMMAND.to_string(),
    ];
    if folder_trust {
        commands.push(APPLY_UPGRADE_COMMAND.to_string());
    }
    ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Options(
            TextDocumentSyncOptions {
                save: Some(
                    SaveOptions {
                        include_text: Some(false),
                    }
                    .into(),
                ),
                ..Default::default()
            },
        )),
        code_action_provider: Some(CodeActionProviderCapability::Options(
            CodeActionOptions {
                code_action_kinds: Some(vec![CodeActionKind::QUICKFIX]),
                resolve_provider: Some(false),
                work_done_progress_options: Default::default(),
            },
        )),
        execute_command_provider: Some(ExecuteCommandOptions {
            commands,
            work_done_progress_options: Default::default(),
        }),
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
    let workspace_folder_uri = params
        .workspace_folders
        .as_ref()
        .and_then(|folders| folders.first())
        .map(|folder| folder.uri.as_str());
    if let Some(uri) = workspace_folder_uri {
        return local_file_path(uri);
    }
    #[allow(deprecated)]
    let root_uri = params.root_uri.as_ref()?;
    local_file_path(root_uri.as_str())
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
    let data = scan
        .apply
        .as_ref()
        .and_then(|apply| serde_json::to_value(apply).ok());
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
        data,
    })
}

fn code_actions(
    params: &serde_json::Value,
    folder_trust: bool,
) -> serde_json::Value {
    let message = params
        .pointer("/context/diagnostics/0/message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("No upgrade plan is available for this diagnostic.");
    let mut actions = vec![
        json!({
            "title": "Show upgrade plan",
            "kind": "quickfix",
            "command": {
                "title": "Show upgrade plan",
                "command": SHOW_UPGRADE_PLAN_COMMAND,
                "arguments": [message],
            },
        }),
        json!({
            "title": SHOW_FIX_DRY_RUN_TITLE,
            "kind": "quickfix",
            "command": {
                "title": SHOW_FIX_DRY_RUN_TITLE,
                "command": SHOW_FIX_DRY_RUN_COMMAND,
                "arguments": [FIX_DRY_RUN_CLI],
            },
        }),
    ];
    if folder_trust
        && let Some(data) = params.pointer("/context/diagnostics/0/data")
        && data.get("package_name").is_some()
        && data.get("apply_strategy").and_then(|v| v.as_str())
            != Some("unavailable")
    {
        actions.push(json!({
            "title": APPLY_UPGRADE_TITLE,
            "kind": "quickfix",
            "command": {
                "title": APPLY_UPGRADE_TITLE,
                "command": APPLY_UPGRADE_COMMAND,
                "arguments": [data],
            },
        }));
    }
    json!(actions)
}

fn execute_command(
    connection: &Connection,
    request: &lsp_server::Request,
    server: &LspServer,
    workspace_root: Option<&Path>,
) -> anyhow::Result<()> {
    let command = request
        .params
        .get("command")
        .and_then(serde_json::Value::as_str);
    match command {
        Some(SHOW_UPGRADE_PLAN_COMMAND) => {
            let message = request
                .params
                .pointer("/arguments/0")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(
                    "No upgrade plan is available for this diagnostic.",
                );
            show_message(connection, message)?;
            connection.sender.send(
                Response::new_ok(request.id.clone(), serde_json::Value::Null)
                    .into(),
            )?;
        }
        Some(SHOW_FIX_DRY_RUN_COMMAND) => {
            let message = request
                .params
                .pointer("/arguments/0")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(FIX_DRY_RUN_CLI);
            show_message(connection, message)?;
            connection.sender.send(
                Response::new_ok(request.id.clone(), serde_json::Value::Null)
                    .into(),
            )?;
        }
        Some(APPLY_UPGRADE_COMMAND) => {
            if !server.folder_trust {
                connection.sender.send(
                    Response::new_err(
                        request.id.clone(),
                        lsp_server::ErrorCode::InvalidRequest as i32,
                        "Apply upgrade requires folder trust (FR-043)"
                            .to_string(),
                    )
                    .into(),
                )?;
                return Ok(());
            }
            let Some(arg) = request.params.pointer("/arguments/0") else {
                connection.sender.send(
                    Response::new_err(
                        request.id.clone(),
                        lsp_server::ErrorCode::InvalidParams as i32,
                        "Apply upgrade requires structured arguments"
                            .to_string(),
                    )
                    .into(),
                )?;
                return Ok(());
            };
            let request_payload: ApplyUpgradeRequest =
                match serde_json::from_value(arg.clone()) {
                    Ok(v) => v,
                    Err(err) => {
                        connection.sender.send(
                            Response::new_err(
                                request.id.clone(),
                                lsp_server::ErrorCode::InvalidParams as i32,
                                format!(
                                    "invalid Apply upgrade arguments: {err}"
                                ),
                            )
                            .into(),
                        )?;
                        return Ok(());
                    }
                };
            match server
                .scan_service
                .apply_upgrade(workspace_root, &request_payload)
            {
                Ok(()) => {
                    show_message(
                        connection,
                        &format!(
                            "Applied upgrade for {} to {}",
                            request_payload.package_name,
                            request_payload.target_version
                        ),
                    )?;
                    send_diagnostics(
                        connection,
                        server.diagnostic_messages(
                            server.scan_for_root(workspace_root, None),
                            workspace_root,
                        ),
                    )?;
                    connection.sender.send(
                        Response::new_ok(
                            request.id.clone(),
                            serde_json::Value::Null,
                        )
                        .into(),
                    )?;
                }
                Err(err) => {
                    connection.sender.send(
                        Response::new_err(
                            request.id.clone(),
                            lsp_server::ErrorCode::InternalError as i32,
                            err,
                        )
                        .into(),
                    )?;
                }
            }
        }
        _ => {
            connection.sender.send(
                Response::new_err(
                    request.id.clone(),
                    lsp_server::ErrorCode::MethodNotFound as i32,
                    "unsupported LSP command".to_string(),
                )
                .into(),
            )?;
        }
    }
    Ok(())
}

fn show_message(connection: &Connection, message: &str) -> anyhow::Result<()> {
    connection.sender.send(
        Notification::new(
            "window/showMessage".to_string(),
            json!({ "type": 3, "message": message }),
        )
        .into(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        APPLY_UPGRADE_COMMAND, APPLY_UPGRADE_TITLE, ApplyDeclaration,
        ApplyUpgradeRequest, DIAGNOSTIC_SOURCE, FIX_DRY_RUN_CLI, LspServer,
        MAX_MESSAGE_BYTES, SHOW_FIX_DRY_RUN_COMMAND, SHOW_FIX_DRY_RUN_TITLE,
        SHOW_UPGRADE_PLAN_COMMAND, ScanDiagnostic, ScanResult, ScanService,
        file_uri_for_path, is_dependency_save_path, run_connection,
        server_capabilities, workspace_root,
    };
    use lsp_server::{Connection, Message, Notification, Request, RequestId};
    use lsp_types::{
        InitializeParams, TextDocumentSyncCapability,
        TextDocumentSyncSaveOptions,
    };
    use serde_json::json;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

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
    fn workspace_folders_take_precedence_over_root_uri() {
        let params: InitializeParams = serde_json::from_value(json!({
            "processId": null,
            "rootUri": "file:///ignored",
            "workspaceFolders": [{
                "uri": "file:///workspace",
                "name": "workspace"
            }],
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
        let capabilities = server_capabilities(false);
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
            vec![
                SHOW_UPGRADE_PLAN_COMMAND.to_string(),
                SHOW_FIX_DRY_RUN_COMMAND.to_string(),
            ]
        );
    }

    #[test]
    fn capabilities_include_apply_when_folder_trusted() {
        let capabilities = server_capabilities(true);
        assert_eq!(
            capabilities
                .execute_command_provider
                .expect("commands")
                .commands,
            vec![
                SHOW_UPGRADE_PLAN_COMMAND.to_string(),
                SHOW_FIX_DRY_RUN_COMMAND.to_string(),
                APPLY_UPGRADE_COMMAND.to_string(),
            ]
        );
    }

    #[test]
    fn initialized_publishes_diagnostic_from_scan_service() {
        let server = LspServer::new(
            Box::new(FixedScanService {
                uri: "file:///tmp/vlz-lsp-fixture/Cargo.toml".to_string(),
            }),
            false,
        );
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
        assert!(
            output.contains(DIAGNOSTIC_SOURCE),
            "diagnostic should identify vlz as the source: {output}"
        );
    }

    #[test]
    fn handle_message_ignores_oversized_invalid_and_other_methods() {
        let server = LspServer::new(Box::new(EmptyScanService), false);
        let oversized = format!(
            r#"{{"jsonrpc":"2.0","method":"initialized","params":{{"pad":"{}"}}}}"#,
            "x".repeat(MAX_MESSAGE_BYTES)
        );
        assert!(server.handle_message(&oversized).is_empty());
        assert!(server.handle_message("not-json").is_empty());
        assert!(
            server
                .handle_message(r#"{"jsonrpc":"2.0","method":"exit"}"#)
                .is_empty()
        );
    }

    #[test]
    fn file_uri_for_path_round_trips_absolute_paths() {
        let path = Path::new("/tmp/vlz-lsp-fixture/Cargo.toml");
        let uri =
            file_uri_for_path(path).expect("absolute path should encode");
        assert!(uri.starts_with("file://"));
        assert!(uri.contains("Cargo.toml"));
        assert_eq!(file_uri_for_path(Path::new("relative.toml")), None);
    }

    #[test]
    fn exit_returns_after_initialization() {
        let root = tempfile_workspace();
        let messages = drive_connection(
            &root,
            Box::new(EmptyScanService),
            false,
            vec![Message::Notification(Notification::new(
                "exit".to_string(),
                json!(null),
            ))],
        );
        assert!(
            messages
                .iter()
                .any(|message| { matches!(message, Message::Response(_)) })
        );
    }

    #[test]
    fn did_save_republishes_diagnostics() {
        let root = tempfile_workspace();
        let manifest = root.join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname=\"demo\"\n")
            .expect("fixture manifest");
        let uri =
            file_uri_for_path(&manifest).expect("manifest URI should encode");
        let scans = Arc::new(Mutex::new(0_u32));
        let messages = drive_connection(
            &root,
            Box::new(CountingScanService {
                count: Arc::clone(&scans),
                uri: uri.clone(),
            }),
            false,
            vec![
                Message::Notification(Notification::new(
                    "textDocument/didSave".to_string(),
                    json!({ "textDocument": { "uri": uri } }),
                )),
                Message::Notification(Notification::new(
                    "exit".to_string(),
                    json!(null),
                )),
            ],
        );
        assert!(*scans.lock().expect("scan count lock") >= 2);
        assert!(messages.iter().any(is_publish_diagnostics));
    }

    #[test]
    fn did_save_skips_rescan_for_non_dependency_files() {
        let root = tempfile_workspace();
        let readme = root.join("README.md");
        std::fs::write(&readme, "docs\n").expect("readme");
        let uri = file_uri_for_path(&readme).expect("uri");
        let scans = Arc::new(Mutex::new(0_u32));
        let _messages = drive_connection(
            &root,
            Box::new(CountingScanService {
                count: Arc::clone(&scans),
                uri: uri.clone(),
            }),
            false,
            vec![
                Message::Notification(Notification::new(
                    "textDocument/didSave".to_string(),
                    json!({ "textDocument": { "uri": uri } }),
                )),
                Message::Notification(Notification::new(
                    "exit".to_string(),
                    json!(null),
                )),
            ],
        );
        // initialized scan once; README save must not rescan
        assert_eq!(*scans.lock().expect("scan count lock"), 1);
    }

    #[test]
    fn is_dependency_save_path_recognizes_manifests() {
        assert!(is_dependency_save_path(Path::new("/x/Cargo.toml")));
        assert!(is_dependency_save_path(Path::new("/x/package-lock.json")));
        assert!(!is_dependency_save_path(Path::new("/x/README.md")));
        assert!(!is_dependency_save_path(Path::new("/x/src/main.rs")));
    }

    #[test]
    fn shutdown_code_action_and_execute_command_are_handled() {
        let root = tempfile_workspace();
        let manifest = root.join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname=\"demo\"\n")
            .expect("fixture manifest");
        let uri =
            file_uri_for_path(&manifest).expect("manifest URI should encode");
        let messages = drive_connection(
            &root,
            Box::new(FixedScanService { uri: uri.clone() }),
            false,
            vec![
                Message::Request(Request::new(
                    RequestId::from(2),
                    "shutdown".to_string(),
                    json!(null),
                )),
                Message::Request(Request::new(
                    RequestId::from(3),
                    "textDocument/codeAction".to_string(),
                    json!({
                        "textDocument": { "uri": uri },
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 0}
                        },
                        "context": {
                            "diagnostics": [{
                                "message": "CVE-2026-1234: upgrade to 1.2.3"
                            }]
                        }
                    }),
                )),
                Message::Request(Request::new(
                    RequestId::from(4),
                    "workspace/executeCommand".to_string(),
                    json!({
                        "command": SHOW_UPGRADE_PLAN_COMMAND,
                        "arguments": ["CVE-2026-1234: upgrade to 1.2.3"]
                    }),
                )),
                Message::Request(Request::new(
                    RequestId::from(5),
                    "workspace/executeCommand".to_string(),
                    json!({
                        "command": SHOW_FIX_DRY_RUN_COMMAND,
                        "arguments": [FIX_DRY_RUN_CLI]
                    }),
                )),
                Message::Request(Request::new(
                    RequestId::from(6),
                    "workspace/executeCommand".to_string(),
                    json!({ "command": "vlz.unknown" }),
                )),
                Message::Request(Request::new(
                    RequestId::from(7),
                    "textDocument/hover".to_string(),
                    json!({}),
                )),
                Message::Request(Request::new(
                    RequestId::from(8),
                    "workspace/executeCommand".to_string(),
                    json!({
                        "command": APPLY_UPGRADE_COMMAND,
                        "arguments": [sample_apply_request()]
                    }),
                )),
                Message::Notification(Notification::new(
                    "exit".to_string(),
                    json!(null),
                )),
            ],
        );

        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(2)
                    && response
                        .response_result
                        .as_ref()
                        .is_ok_and(|value| value == &json!(null))
        )));
        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(3)
                    && response.response_result.as_ref().is_ok_and(|value| {
                        let text = value.to_string();
                        text.contains("Show upgrade plan")
                            && text.contains(SHOW_FIX_DRY_RUN_TITLE)
                            && text.contains(SHOW_FIX_DRY_RUN_COMMAND)
                            && !text.contains(APPLY_UPGRADE_TITLE)
                    })
        )));
        assert!(messages.iter().any(|message| {
            matches!(
                message,
                Message::Notification(notification)
                    if notification.method == "window/showMessage"
                        && notification.params.to_string().contains(
                            "CVE-2026-1234"
                        )
            )
        }));
        assert!(messages.iter().any(|message| {
            matches!(
                message,
                Message::Notification(notification)
                    if notification.method == "window/showMessage"
                        && notification
                            .params
                            .to_string()
                            .contains(FIX_DRY_RUN_CLI)
            )
        }));
        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(6)
                    && response.response_result.is_err()
        )));
        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(7)
                    && response.response_result.is_err()
        )));
        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(8)
                    && response.response_result.is_err()
        )));
    }

    #[test]
    fn trusted_apply_upgrade_invokes_scan_service() {
        let root = tempfile_workspace();
        let manifest = root.join("Cargo.toml");
        std::fs::write(&manifest, "[package]\nname=\"demo\"\n")
            .expect("fixture manifest");
        let uri =
            file_uri_for_path(&manifest).expect("manifest URI should encode");
        let applied = Arc::new(Mutex::new(None));
        let messages = drive_connection(
            &root,
            Box::new(ApplyRecordingScanService {
                uri: uri.clone(),
                applied: Arc::clone(&applied),
            }),
            true,
            vec![
                Message::Request(Request::new(
                    RequestId::from(3),
                    "textDocument/codeAction".to_string(),
                    json!({
                        "textDocument": { "uri": uri },
                        "range": {
                            "start": {"line": 0, "character": 0},
                            "end": {"line": 0, "character": 0}
                        },
                        "context": {
                            "diagnostics": [{
                                "message": "CVE-2026-1234: upgrade to 1.2.3 (cargo)",
                                "data": sample_apply_request()
                            }]
                        }
                    }),
                )),
                Message::Request(Request::new(
                    RequestId::from(4),
                    "workspace/executeCommand".to_string(),
                    json!({
                        "command": APPLY_UPGRADE_COMMAND,
                        "arguments": [sample_apply_request()]
                    }),
                )),
                Message::Notification(Notification::new(
                    "exit".to_string(),
                    json!(null),
                )),
            ],
        );
        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(3)
                    && response.response_result.as_ref().is_ok_and(|value| {
                        value.to_string().contains(APPLY_UPGRADE_TITLE)
                    })
        )));
        assert!(messages.iter().any(|message| matches!(
            message,
            Message::Response(response)
                if response.id == RequestId::from(4)
                    && response.response_result.as_ref().is_ok()
        )));
        let recorded = applied.lock().expect("applied lock").clone();
        assert_eq!(recorded.map(|r| r.package_name), Some("demo".to_string()));
    }

    #[test]
    fn diagnostic_messages_clear_stale_uris_and_filter_workspace() {
        let root = tempfile_workspace();
        let inside = root.join("Cargo.toml");
        std::fs::write(&inside, "[package]\nname=\"demo\"\n")
            .expect("fixture file");
        let inside_uri =
            file_uri_for_path(&inside).expect("inside path should encode");
        let outside_uri = "file:///tmp/outside-vlz-lsp/Cargo.toml".to_string();
        let service = SequenceScanService {
            results: Mutex::new(vec![
                ScanResult {
                    diagnostics: vec![
                        ScanDiagnostic {
                            uri: inside_uri.clone(),
                            line: 0,
                            code: "CVE-2026-1".to_string(),
                            message: "first".to_string(),
                            apply: None,
                        },
                        ScanDiagnostic {
                            uri: outside_uri,
                            line: 0,
                            code: "CVE-2026-2".to_string(),
                            message: "outside".to_string(),
                            apply: None,
                        },
                    ],
                },
                ScanResult::default(),
            ]),
        };
        let server = LspServer::new(Box::new(service), false);
        let first = server.diagnostic_messages(
            server.scan_service.scan(Some(root.as_path()), None),
            Some(root.as_path()),
        );
        assert_eq!(first.len(), 1);
        assert!(first[0].contains("CVE-2026-1"));
        assert!(!first[0].contains("CVE-2026-2"));

        let second = server.diagnostic_messages(
            server.scan_service.scan(Some(root.as_path()), None),
            Some(root.as_path()),
        );
        assert_eq!(second.len(), 1);
        assert!(second[0].contains("\"diagnostics\":[]"));
    }

    #[test]
    fn show_plan_action_falls_back_when_diagnostic_missing() {
        let actions = super::code_actions(&json!({ "context": {} }), false);
        let text = actions.to_string();
        assert!(text.contains("No upgrade plan is available"));
        assert!(text.contains(SHOW_FIX_DRY_RUN_TITLE));
        assert!(text.contains(FIX_DRY_RUN_CLI));
        assert!(text.contains(SHOW_FIX_DRY_RUN_COMMAND));
        assert!(!text.contains(APPLY_UPGRADE_TITLE));
    }

    fn sample_apply_request() -> serde_json::Value {
        serde_json::to_value(ApplyUpgradeRequest {
            package_name: "demo".to_string(),
            target_version: "1.2.3".to_string(),
            apply_strategy: "cargo".to_string(),
            dependency_kind: "direct".to_string(),
            declarations: vec![ApplyDeclaration {
                path: "Cargo.toml".to_string(),
                start_line: 1,
                kind: "manifest".to_string(),
            }],
        })
        .expect("serialize apply request")
    }

    fn drive_connection(
        workspace_root: &Path,
        scan_service: Box<dyn ScanService>,
        folder_trust: bool,
        client_messages: Vec<Message>,
    ) -> Vec<Message> {
        let root_uri = file_uri_for_path(workspace_root)
            .expect("workspace root URI should encode");
        let (server, client) = Connection::memory();
        client
            .sender
            .send(
                Request::new(
                    RequestId::from(1),
                    "initialize".to_string(),
                    json!({
                        "processId": null,
                        "rootUri": root_uri,
                        "capabilities": {},
                    }),
                )
                .into(),
            )
            .expect("client should initialize server");
        let server = std::thread::spawn(move || {
            run_connection(server, scan_service, folder_trust)
        });
        let mut messages = Vec::new();
        messages.push(
            client
                .receiver
                .recv()
                .expect("server should respond to initialize"),
        );
        client
            .sender
            .send(
                Notification::new("initialized".to_string(), json!({})).into(),
            )
            .expect("client should complete initialization");
        for message in client_messages {
            client
                .sender
                .send(message)
                .expect("client should send lifecycle message");
        }
        server
            .join()
            .expect("server thread should not panic")
            .expect("server should exit cleanly");
        while let Ok(message) = client.receiver.try_recv() {
            messages.push(message);
        }
        messages
    }

    fn is_publish_diagnostics(message: &Message) -> bool {
        matches!(
            message,
            Message::Notification(notification)
                if notification.method == "textDocument/publishDiagnostics"
        )
    }

    fn tempfile_workspace() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "vlz-lsp-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp workspace");
        root
    }

    #[derive(Default)]
    struct EmptyScanService;

    impl ScanService for EmptyScanService {
        fn scan(
            &self,
            _root: Option<&Path>,
            _changed: Option<&Path>,
        ) -> ScanResult {
            ScanResult::default()
        }
    }

    struct FixedScanService {
        uri: String,
    }

    impl ScanService for FixedScanService {
        fn scan(
            &self,
            _root: Option<&Path>,
            _changed: Option<&Path>,
        ) -> ScanResult {
            ScanResult {
                diagnostics: vec![ScanDiagnostic {
                    uri: self.uri.clone(),
                    line: 0,
                    code: "CVE-2026-1234".to_string(),
                    message: "CVE-2026-1234: update to 1.2.3".to_string(),
                    apply: None,
                }],
            }
        }
    }

    struct CountingScanService {
        count: Arc<Mutex<u32>>,
        uri: String,
    }

    impl ScanService for CountingScanService {
        fn scan(
            &self,
            _root: Option<&Path>,
            _changed: Option<&Path>,
        ) -> ScanResult {
            *self.count.lock().expect("count lock") += 1;
            FixedScanService {
                uri: self.uri.clone(),
            }
            .scan(None, None)
        }
    }

    struct SequenceScanService {
        results: Mutex<Vec<ScanResult>>,
    }

    impl ScanService for SequenceScanService {
        fn scan(
            &self,
            _root: Option<&Path>,
            _changed: Option<&Path>,
        ) -> ScanResult {
            let mut results = self.results.lock().expect("results lock");
            if results.is_empty() {
                return ScanResult::default();
            }
            results.remove(0)
        }
    }

    struct ApplyRecordingScanService {
        uri: String,
        applied: Arc<Mutex<Option<ApplyUpgradeRequest>>>,
    }

    impl ScanService for ApplyRecordingScanService {
        fn scan(
            &self,
            _root: Option<&Path>,
            _changed: Option<&Path>,
        ) -> ScanResult {
            FixedScanService {
                uri: self.uri.clone(),
            }
            .scan(None, None)
        }

        fn apply_upgrade(
            &self,
            _root: Option<&Path>,
            request: &ApplyUpgradeRequest,
        ) -> Result<(), String> {
            *self.applied.lock().expect("applied lock") =
                Some(request.clone());
            Ok(())
        }
    }
}
