// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Remediation application via package-manager argv (FR-041 / MOD-011).
//!
//! Supported apply strategies (SEC-025):
//! - npm via `package-lock.json` / `npm-shrinkwrap.json`
//! - Cargo via `Cargo.lock`
//!
//! SEC-023 for Phase-2 argv is scripts-only: npm defaults to
//! `--ignore-scripts` unless `allow_dependency_code_execution` is set.
//! Cargo `update` does not run dependency lifecycle scripts.
//!
//! Apply is fail-fast (first remediator error stops the batch). Earlier
//! successful writes are not rolled back.

use std::path::Path;
use std::process::Command;

use thiserror::Error;
use vlz_db::{
    CRATES_IO_ECOSYSTEM, DeclarationKind, NPM_ECOSYSTEM, Package,
    PackageDeclarationLocation,
};

use crate::{
    ApplyStrategy, ApplyStrategy::Cargo, ApplyStrategy::Npm, DependencyKind,
    MIN_FIXED_VERSION_UNKNOWN,
};

/// npm lockfile basename (`package-lock.json`).
pub const NPM_LOCKFILE_PACKAGE_LOCK_JSON: &str = "package-lock.json";
/// npm lockfile basename (`npm-shrinkwrap.json`).
pub const NPM_LOCKFILE_NPM_SHRINKWRAP_JSON: &str = "npm-shrinkwrap.json";
/// Cargo lockfile basename.
pub const CARGO_LOCK_FILE_NAME: &str = "Cargo.lock";
/// Sibling npm manifest required next to the lockfile (SEC-025).
pub const NPM_MANIFEST_FILE_NAME: &str = "package.json";
/// Sibling Cargo manifest required next to the lockfile (SEC-025).
pub const CARGO_MANIFEST_FILE_NAME: &str = "Cargo.toml";
/// Allowlisted npm binary name (SEC-025).
pub const NPM_BIN_NAME: &str = "npm";
/// Allowlisted cargo binary name (SEC-025).
pub const CARGO_BIN_NAME: &str = "cargo";
/// npm flag that skips lifecycle scripts (SEC-023 scripts-only gate).
pub const NPM_IGNORE_SCRIPTS_FLAG: &str = "--ignore-scripts";
/// npm flag that updates the lockfile without a full install tree.
pub const NPM_PACKAGE_LOCK_ONLY_FLAG: &str = "--package-lock-only";
/// npm flag that avoids writing `package.json` for transitive upgrades.
pub const NPM_NO_SAVE_FLAG: &str = "--no-save";

/// Resolve a lockfile declaration to a working directory under `scan_root`.
///
/// Absolute declaration paths replace `scan_root` under [`Path::join`]; this
/// helper canonicalizes and rejects any lock path (or parent) outside the
/// scan root (SEC-025).
fn resolve_lock_workdir_under_root(
    scan_root: &Path,
    declaration_path: &str,
) -> Option<std::path::PathBuf> {
    let root = std::fs::canonicalize(scan_root).ok()?;
    let joined = {
        let decl = Path::new(declaration_path);
        if decl.is_absolute() {
            decl.to_path_buf()
        } else {
            scan_root.join(decl)
        }
    };
    let file_abs = std::fs::canonicalize(&joined).ok()?;
    if !file_abs.starts_with(&root) {
        return None;
    }
    let dir = file_abs.parent()?.to_path_buf();
    if !dir.starts_with(&root) {
        return None;
    }
    Some(dir)
}

fn require_sibling_manifest(
    lock_dir: &Path,
    file_name: &str,
) -> Result<(), RemediationError> {
    let manifest = lock_dir.join(file_name);
    if manifest.is_file() {
        Ok(())
    } else {
        Err(RemediationError::UnsupportedLockLayout(format!(
            "missing sibling {file_name} next to lockfile"
        )))
    }
}

/// Allowlisted npm package name (optionally scoped) for argv operands.
fn is_allowlisted_npm_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 214 {
        return false;
    }
    let (scope, pkg) = if let Some(rest) = name.strip_prefix('@') {
        match rest.split_once('/') {
            Some((scope, pkg)) => (Some(scope), pkg),
            None => return false,
        }
    } else {
        (None, name)
    };
    let ok_part = |s: &str| {
        !s.is_empty()
            && !s.starts_with('.')
            && !s.starts_with('-')
            && s.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')
            })
    };
    scope.is_none_or(ok_part) && ok_part(pkg)
}

/// Allowlisted crates.io package name for `cargo update --package`.
fn is_allowlisted_cargo_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 || name.starts_with('-') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// Allowlisted version operand (no leading dash / whitespace / shell metachars).
fn is_allowlisted_version_operand(version: &str) -> bool {
    if version.is_empty()
        || version.len() > 128
        || version.starts_with('-')
        || version.contains([' ', '\t', '\n', '\r', ';', '|', '&', '$', '`'])
    {
        return false;
    }
    version.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+')
    })
}

fn require_allowlisted_npm_operands(
    package_name: &str,
    target_version: &str,
) -> Result<(), RemediationError> {
    if is_allowlisted_npm_package_name(package_name)
        && is_allowlisted_version_operand(target_version)
    {
        Ok(())
    } else {
        Err(RemediationError::InvalidOperand(format!(
            "npm package/version not allowlisted: {package_name}@{target_version}"
        )))
    }
}

fn require_allowlisted_cargo_operands(
    package_name: &str,
    target_version: &str,
) -> Result<(), RemediationError> {
    if is_allowlisted_cargo_package_name(package_name)
        && is_allowlisted_version_operand(target_version)
    {
        Ok(())
    } else {
        Err(RemediationError::InvalidOperand(format!(
            "cargo package/version not allowlisted: {package_name}@{target_version}"
        )))
    }
}

/// Where remediation can be applied.
///
/// This intentionally depends on both:
/// - the vulnerability ecosystem (`package.ecosystem`), and
/// - which lock file was used for resolution (declarations).
///
/// That lets Phase 2 apply only the first remediator implementations:
/// - npm via `package-lock.json` and `npm-shrinkwrap.json`
/// - Cargo via `Cargo.lock`
pub fn remediation_apply_strategy_for_finding(
    package: &Package,
    minimal_fixed_version: &str,
    declarations: &[PackageDeclarationLocation],
) -> ApplyStrategy {
    if minimal_fixed_version == MIN_FIXED_VERSION_UNKNOWN {
        return ApplyStrategy::Unavailable;
    }

    match package.ecosystem.as_deref() {
        Some(e) if e.eq_ignore_ascii_case(NPM_ECOSYSTEM) => {
            let has_supported_npm_lock = declarations.iter().any(|d| {
                d.kind == DeclarationKind::Lockfile
                    && is_supported_npm_lockfile(d.path.as_str())
            });
            if has_supported_npm_lock {
                Npm
            } else {
                ApplyStrategy::Unavailable
            }
        }
        Some(e) if e.eq_ignore_ascii_case(CRATES_IO_ECOSYSTEM) => {
            let has_cargo_lock = declarations.iter().any(|d| {
                d.kind == DeclarationKind::Lockfile
                    && Path::new(d.path.as_str())
                        .file_name()
                        .is_some_and(|n| n == CARGO_LOCK_FILE_NAME)
            });
            if has_cargo_lock {
                Cargo
            } else {
                ApplyStrategy::Unavailable
            }
        }
        _ => ApplyStrategy::Unavailable,
    }
}

fn is_supported_npm_lockfile(path: &str) -> bool {
    Path::new(path).file_name().is_some_and(|n| {
        n == NPM_LOCKFILE_PACKAGE_LOCK_JSON
            || n == NPM_LOCKFILE_NPM_SHRINKWRAP_JSON
    })
}

#[derive(Debug, Error)]
pub enum RemediationError {
    #[error("remediation requires a supported target version (not unknown)")]
    TargetVersionUnknown,

    #[error(
        "offline mode blocks remediation application (needs package manager network access)"
    )]
    OfflineBlocked,

    #[error("required package manager '{0}' is not available on PATH")]
    MissingPackageManager(String),

    #[error("remediation not supported for lock/manifest layout: {0}")]
    UnsupportedLockLayout(String),

    #[error("remediation package or version is not allowlisted: {0}")]
    InvalidOperand(String),

    #[error("remediation command failed ({strategy}): {message}")]
    CommandFailed { strategy: String, message: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Inputs required to preview or apply one planned remediation.
#[derive(Debug, Clone)]
pub struct RemediationContext<'a> {
    pub scan_root: &'a Path,
    pub declarations: &'a [PackageDeclarationLocation],
    pub package_name: &'a str,
    pub target_version: &'a str,
    pub dependency_kind: DependencyKind,
    /// When false, npm apply/preview uses [`NPM_IGNORE_SCRIPTS_FLAG`]
    /// (SEC-023 scripts-only gate for Phase-2 argv). Cargo `update` does
    /// not run dependency lifecycle scripts, so this flag does not change
    /// Cargo argv.
    pub allow_dependency_code_execution: bool,
    pub offline: bool,
}

/// Dry-run preview of files and argv a remediator would use (FR-041 / MOD-011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemediationPreview {
    pub strategy: ApplyStrategy,
    /// Absolute working directory for the allowlisted package-manager command.
    pub workdir: std::path::PathBuf,
    /// Absolute paths the remediator intends to change.
    pub files: Vec<std::path::PathBuf>,
    /// Full argv including the program name as `argv[0]` (NFR-024 shared
    /// with apply).
    pub argv: Vec<String>,
}

/// Build allowlisted npm install argv shared by preview and apply (NFR-024).
pub fn npm_install_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
    dependency_kind: DependencyKind,
    allow_dependency_code_execution: bool,
) -> Vec<String> {
    let mut argv = vec![bin.to_string(), "install".to_string()];
    if !allow_dependency_code_execution {
        argv.push(NPM_IGNORE_SCRIPTS_FLAG.to_string());
    }
    argv.push(NPM_PACKAGE_LOCK_ONLY_FLAG.to_string());
    if matches!(dependency_kind, DependencyKind::Transitive) {
        argv.push(NPM_NO_SAVE_FLAG.to_string());
    }
    argv.push("--".to_string());
    argv.push(format!("{package_name}@{target_version}"));
    argv
}

/// Build allowlisted cargo update argv shared by preview and apply (NFR-024).
pub fn cargo_update_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
) -> Vec<String> {
    vec![
        bin.to_string(),
        "update".to_string(),
        "--package".to_string(),
        package_name.to_string(),
        "--precise".to_string(),
        target_version.to_string(),
    ]
}

/// Language remediator: preview intended writes, then apply under SEC-025.
pub trait Remediator: Send + Sync {
    /// Apply strategy this remediator handles.
    fn strategy(&self) -> ApplyStrategy;

    /// Return intended file paths and argv without writing (FR-041).
    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError>;

    /// Apply the remediation (may write lock/manifest files).
    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError>;
}

fn run_allowlisted_argv(
    argv: &[String],
    workdir: &Path,
    strategy_name: &str,
) -> Result<(), RemediationError> {
    let (program, args) =
        argv.split_first()
            .ok_or_else(|| RemediationError::CommandFailed {
                strategy: strategy_name.to_string(),
                message: "empty argv".to_string(),
            })?;
    let out = Command::new(program)
        .args(args)
        .current_dir(workdir)
        .output()?;
    if out.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(RemediationError::CommandFailed {
            strategy: strategy_name.to_string(),
            message: stderr.trim().to_string(),
        })
    }
}

/// Apply npm remediation by invoking:
/// `npm install --ignore-scripts --package-lock-only -- <name>@<version>`
#[derive(Debug, Clone)]
pub struct NpmRemediator {
    bin: String,
}

impl Default for NpmRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmRemediator {
    pub fn new() -> Self {
        Self {
            bin: NPM_BIN_NAME.to_string(),
        }
    }

    /// Override the npm executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }

    fn npm_available(&self) -> bool {
        Command::new(&self.bin)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn select_npm_lock_dir(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Option<std::path::PathBuf> {
        ctx.declarations.iter().find_map(|d| {
            if d.kind != DeclarationKind::Lockfile
                || !is_supported_npm_lockfile(d.path.as_str())
            {
                return None;
            }
            resolve_lock_workdir_under_root(ctx.scan_root, d.path.as_str())
        })
    }
}

impl Remediator for NpmRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Npm
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        require_allowlisted_npm_operands(
            ctx.package_name,
            ctx.target_version,
        )?;
        let lock_dir = self.select_npm_lock_dir(ctx).ok_or_else(|| {
            RemediationError::UnsupportedLockLayout(
                "supported npm lockfile not found under scan root (need package-lock.json or npm-shrinkwrap.json)".to_string(),
            )
        })?;
        require_sibling_manifest(&lock_dir, NPM_MANIFEST_FILE_NAME)?;
        let lock_path = ctx
            .declarations
            .iter()
            .find(|d| {
                d.kind == DeclarationKind::Lockfile
                    && is_supported_npm_lockfile(d.path.as_str())
            })
            .and_then(|d| {
                resolve_lock_workdir_under_root(ctx.scan_root, d.path.as_str())
                    .map(|dir| {
                        let name = Path::new(d.path.as_str())
                            .file_name()
                            .map(|n| n.to_owned());
                        match name {
                            Some(n) => dir.join(n),
                            None => dir.join(NPM_LOCKFILE_PACKAGE_LOCK_JSON),
                        }
                    })
            })
            .unwrap_or_else(|| lock_dir.join(NPM_LOCKFILE_PACKAGE_LOCK_JSON));
        let mut files = vec![lock_path];
        if matches!(ctx.dependency_kind, DependencyKind::Direct) {
            files.push(lock_dir.join(NPM_MANIFEST_FILE_NAME));
        }
        Ok(RemediationPreview {
            strategy: Npm,
            workdir: lock_dir,
            files,
            argv: npm_install_argv(
                &self.bin,
                ctx.package_name,
                ctx.target_version,
                ctx.dependency_kind,
                ctx.allow_dependency_code_execution,
            ),
        })
    }

    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        if !self.npm_available() {
            return Err(RemediationError::MissingPackageManager(
                NPM_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, NPM_BIN_NAME)
    }
}

/// Apply Cargo remediation by invoking:
/// `cargo update --package <name> --precise <version>`
#[derive(Debug, Clone)]
pub struct CargoRemediator {
    bin: String,
}

impl Default for CargoRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl CargoRemediator {
    pub fn new() -> Self {
        Self {
            bin: CARGO_BIN_NAME.to_string(),
        }
    }

    /// Override the cargo executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }

    fn cargo_available(&self) -> bool {
        Command::new(&self.bin)
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn select_cargo_lock_dir(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Option<std::path::PathBuf> {
        ctx.declarations.iter().find_map(|d| {
            if d.kind != DeclarationKind::Lockfile {
                return None;
            }
            let file = Path::new(d.path.as_str());
            if !file.file_name().is_some_and(|n| n == CARGO_LOCK_FILE_NAME) {
                return None;
            }
            resolve_lock_workdir_under_root(ctx.scan_root, d.path.as_str())
        })
    }
}

impl Remediator for CargoRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Cargo
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        require_allowlisted_cargo_operands(
            ctx.package_name,
            ctx.target_version,
        )?;
        let lock_dir = self.select_cargo_lock_dir(ctx).ok_or_else(|| {
            RemediationError::UnsupportedLockLayout(
                "Cargo.lock not found under scan root".to_string(),
            )
        })?;
        require_sibling_manifest(&lock_dir, CARGO_MANIFEST_FILE_NAME)?;
        Ok(RemediationPreview {
            strategy: Cargo,
            workdir: lock_dir.clone(),
            files: vec![lock_dir.join(CARGO_LOCK_FILE_NAME)],
            argv: cargo_update_argv(
                &self.bin,
                ctx.package_name,
                ctx.target_version,
            ),
        })
    }

    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        if !self.cargo_available() {
            return Err(RemediationError::MissingPackageManager(
                CARGO_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, CARGO_BIN_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use vlz_db::{CRATES_IO_ECOSYSTEM, NPM_ECOSYSTEM};

    fn lock_decl(path: &str) -> PackageDeclarationLocation {
        PackageDeclarationLocation {
            path: path.to_string(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Lockfile,
        }
    }

    fn manifest_decl(path: &str) -> PackageDeclarationLocation {
        PackageDeclarationLocation {
            path: path.to_string(),
            start_line: 1,
            end_line: None,
            kind: DeclarationKind::Manifest,
        }
    }

    fn pkg(ecosystem: &str, name: &str) -> Package {
        Package {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            ecosystem: Some(ecosystem.to_string()),
        }
    }

    fn write_exec(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, PermissionsExt::from_mode(0o755)).unwrap();
    }

    fn write_npm_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        fs::write(root.join("package.json"), "{\"name\":\"app\"}\n").unwrap();
    }

    fn write_cargo_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("Cargo.lock"), "# lock\n").unwrap();
        fs::write(root.join("Cargo.toml"), "[package]\nname=\"app\"\n")
            .unwrap();
    }

    #[test]
    fn strategy_selects_npm_for_package_lock_and_shrinkwrap() {
        let package = pkg(NPM_ECOSYSTEM, "left-pad");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.0.0",
                &[lock_decl("package-lock.json")],
            ),
            ApplyStrategy::Npm
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.0.0",
                &[lock_decl("nested/npm-shrinkwrap.json")],
            ),
            ApplyStrategy::Npm
        );
    }

    #[test]
    fn strategy_selects_cargo_for_cargo_lock() {
        let package = pkg(CRATES_IO_ECOSYSTEM, "serde");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "1.0.200",
                &[lock_decl("Cargo.lock")],
            ),
            ApplyStrategy::Cargo
        );
    }

    #[test]
    fn strategy_unavailable_without_supported_lock_or_unknown_fixed() {
        let npm = pkg(NPM_ECOSYSTEM, "left-pad");
        let cargo = pkg(CRATES_IO_ECOSYSTEM, "serde");
        let other = pkg("pypi", "requests");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &npm,
                MIN_FIXED_VERSION_UNKNOWN,
                &[lock_decl("package-lock.json")],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &npm,
                "2.0.0",
                &[lock_decl("yarn.lock")],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &npm,
                "2.0.0",
                &[manifest_decl("package.json")],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &cargo,
                "1.0.0",
                &[lock_decl("Cargo.toml")],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &other,
                "2.0.0",
                &[lock_decl("package-lock.json")],
            ),
            ApplyStrategy::Unavailable
        );
    }

    #[test]
    fn npm_apply_rejects_unknown_offline_missing_bin_and_lock() {
        let root = std::env::temp_dir()
            .join(format!("vlz-npm-rej-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let decls = [lock_decl("package-lock.json")];
        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = NpmRemediator::with_bin(ok_bin.to_string_lossy());

        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: MIN_FIXED_VERSION_UNKNOWN,
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::TargetVersionUnknown));

        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));

        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &[manifest_decl("package.json")],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let missing = NpmRemediator::with_bin(
            root.join("no-such-npm").to_string_lossy(),
        );
        let err = missing
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cargo_apply_rejects_unknown_offline_missing_bin_and_lock() {
        let root = std::env::temp_dir()
            .join(format!("vlz-cargo-rej-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let decls = [lock_decl("Cargo.lock")];
        let ok_bin = root.join("cargo-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = CargoRemediator::with_bin(ok_bin.to_string_lossy());

        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "serde",
                target_version: MIN_FIXED_VERSION_UNKNOWN,
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::TargetVersionUnknown));

        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));

        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &[manifest_decl("Cargo.toml")],
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let missing = CargoRemediator::with_bin(
            root.join("no-such-cargo").to_string_lossy(),
        );
        let err = missing
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_apply_stub_bin_success_and_command_failed() {
        let root = std::env::temp_dir()
            .join(format!("vlz-npm-stub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_npm_tree(&root);
        let decls = [lock_decl("package-lock.json")];

        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        NpmRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Transitive,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap();

        let fail_bin = root.join("npm-fail");
        write_exec(
            &fail_bin,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then exit 0; fi\necho boom >&2\nexit 1\n",
        );
        let err = NpmRemediator::with_bin(fail_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        match err {
            RemediationError::CommandFailed { strategy, message } => {
                assert_eq!(strategy, NPM_BIN_NAME);
                assert!(message.contains("boom"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cargo_apply_stub_bin_success_and_command_failed() {
        let root = std::env::temp_dir()
            .join(format!("vlz-cargo-stub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_cargo_tree(&root);
        let decls = [lock_decl("Cargo.lock")];

        let ok_bin = root.join("cargo-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        CargoRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap();

        let fail_bin = root.join("cargo-fail");
        write_exec(
            &fail_bin,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then exit 0; fi\necho cargo-fail >&2\nexit 1\n",
        );
        let err = CargoRemediator::with_bin(fail_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        match err {
            RemediationError::CommandFailed { strategy, message } => {
                assert_eq!(strategy, CARGO_BIN_NAME);
                assert!(message.contains("cargo-fail"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_apply_rejects_lock_path_outside_scan_root() {
        let pid = std::process::id();
        let root =
            std::env::temp_dir().join(format!("vlz-npm-esc-root-{pid}"));
        let outside =
            std::env::temp_dir().join(format!("vlz-npm-esc-out-{pid}"));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
        write_npm_tree(&root);
        write_npm_tree(&outside);
        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = NpmRemediator::with_bin(ok_bin.to_string_lossy());

        let abs = outside
            .join("package-lock.json")
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &[lock_decl(&abs)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let rel = format!("../vlz-npm-esc-out-{pid}/package-lock.json");
        let err = rem
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &[lock_decl(&rel)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn npm_apply_rejects_missing_sibling_manifest() {
        let root = std::env::temp_dir()
            .join(format!("vlz-npm-nosib-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let err = NpmRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &[lock_decl("package-lock.json")],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_and_cargo_apply_reject_invalid_operands() {
        let root = std::env::temp_dir()
            .join(format!("vlz-operand-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_npm_tree(&root);
        let cargo_root = root.join("cargo-tree");
        write_cargo_tree(&cargo_root);
        let npm_bin = root.join("npm-ok");
        let cargo_bin = root.join("cargo-ok");
        write_exec(&npm_bin, "#!/bin/sh\nexit 0\n");
        write_exec(&cargo_bin, "#!/bin/sh\nexit 0\n");

        let err = NpmRemediator::with_bin(npm_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &root,
                declarations: &[lock_decl("package-lock.json")],
                package_name: "-evil",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::InvalidOperand(_)));

        let err = CargoRemediator::with_bin(cargo_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &cargo_root,
                declarations: &[lock_decl("Cargo.lock")],
                package_name: "-evil",
                target_version: "1.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::InvalidOperand(_)));

        let err = CargoRemediator::with_bin(cargo_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: &cargo_root,
                declarations: &[lock_decl("Cargo.lock")],
                package_name: "serde",
                target_version: "--precise",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::InvalidOperand(_)));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn allowlist_helpers_accept_scoped_npm_and_reject_bad_versions() {
        assert!(is_allowlisted_npm_package_name("@scope/pkg"));
        assert!(!is_allowlisted_npm_package_name("@scope"));
        assert!(!is_allowlisted_npm_package_name(""));
        assert!(is_allowlisted_cargo_package_name("serde_json"));
        assert!(!is_allowlisted_cargo_package_name("-x"));
        assert!(is_allowlisted_version_operand("1.2.3-beta+meta"));
        assert!(!is_allowlisted_version_operand("-1"));
        assert!(!is_allowlisted_version_operand("1;rm"));
    }

    #[test]
    fn default_constructors_use_standard_bin_names() {
        assert_eq!(NpmRemediator::new().bin, NPM_BIN_NAME);
        assert_eq!(NpmRemediator::default().bin, NPM_BIN_NAME);
        assert_eq!(CargoRemediator::new().bin, CARGO_BIN_NAME);
        assert_eq!(CargoRemediator::default().bin, CARGO_BIN_NAME);
    }

    #[test]
    fn npm_preview_matches_allowlisted_argv_and_ignore_scripts_gate() {
        let root = std::env::temp_dir()
            .join(format!("vlz-npm-preview-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_npm_tree(&root);
        let decls = [lock_decl("package-lock.json")];
        let rem = NpmRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Npm);

        let preview = rem
            .preview(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Transitive,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("preview");
        assert_eq!(preview.strategy, ApplyStrategy::Npm);
        assert_eq!(
            preview.argv,
            npm_install_argv(
                NPM_BIN_NAME,
                "left-pad",
                "2.0.0",
                DependencyKind::Transitive,
                false,
            )
        );
        assert!(
            preview.argv.iter().any(|a| a == NPM_IGNORE_SCRIPTS_FLAG),
            "SEC-023 scripts-only gate must add --ignore-scripts"
        );
        assert!(
            preview.argv.contains(&NPM_NO_SAVE_FLAG.to_string()),
            "transitive must use --no-save"
        );
        assert_eq!(
            preview.files,
            vec![root.join(NPM_LOCKFILE_PACKAGE_LOCK_JSON)]
        );

        let with_scripts = rem
            .preview(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: true,
            })
            .expect("offline preview still works");
        assert!(
            !with_scripts
                .argv
                .iter()
                .any(|a| a == NPM_IGNORE_SCRIPTS_FLAG)
        );
        assert!(
            with_scripts
                .files
                .contains(&root.join(NPM_MANIFEST_FILE_NAME))
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cargo_preview_matches_allowlisted_argv() {
        let root = std::env::temp_dir()
            .join(format!("vlz-cargo-preview-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        write_cargo_tree(&root);
        let decls = [lock_decl("Cargo.lock")];
        let rem = CargoRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Cargo);
        let preview = rem
            .preview(&RemediationContext {
                scan_root: &root,
                declarations: &decls,
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("preview");
        assert_eq!(
            preview.argv,
            cargo_update_argv(CARGO_BIN_NAME, "serde", "1.0.200")
        );
        assert_eq!(preview.files, vec![root.join(CARGO_LOCK_FILE_NAME)]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_install_argv_builder_is_stable() {
        assert_eq!(
            npm_install_argv(
                NPM_BIN_NAME,
                "left-pad",
                "2.0.0",
                DependencyKind::Direct,
                false,
            ),
            vec![
                NPM_BIN_NAME.to_string(),
                "install".to_string(),
                NPM_IGNORE_SCRIPTS_FLAG.to_string(),
                NPM_PACKAGE_LOCK_ONLY_FLAG.to_string(),
                "--".to_string(),
                "left-pad@2.0.0".to_string(),
            ]
        );
    }
}
