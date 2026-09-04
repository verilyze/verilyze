// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Remediation application via package-manager argv.
//!
//! Phase 1 computes upgrade plans only (apply strategy "unavailable").
//! Phase 2 applies supported remediations via lock/manifest mutation.

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

const NPM_LOCKFILE_PACKAGE_LOCK_JSON: &str = "package-lock.json";
const NPM_LOCKFILE_NPM_SHRINKWRAP_JSON: &str = "npm-shrinkwrap.json";
const CARGO_LOCK_FILE_NAME: &str = "Cargo.lock";

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

    #[error("remediation command failed ({strategy}): {message}")]
    CommandFailed { strategy: String, message: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Inputs required to apply one planned remediation.
#[derive(Debug, Clone)]
pub struct RemediationContext<'a> {
    pub scan_root: &'a Path,
    pub declarations: &'a [PackageDeclarationLocation],
    pub package_name: &'a str,
    pub target_version: &'a str,
    pub dependency_kind: DependencyKind,
    pub allow_dependency_code_execution: bool,
    pub offline: bool,
}

pub trait Remediator {
    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError>;
}

/// Apply npm remediation by invoking:
/// `npm install --ignore-scripts --package-lock-only <name>@<version>`
pub struct NpmRemediator;

impl NpmRemediator {
    fn npm_available(&self) -> bool {
        Command::new("npm")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn select_npm_lock_dir<'a>(
        &self,
        ctx: &'a RemediationContext<'a>,
    ) -> Option<std::path::PathBuf> {
        ctx.declarations.iter().find_map(|d| {
            if d.kind != DeclarationKind::Lockfile
                || !is_supported_npm_lockfile(d.path.as_str())
            {
                return None;
            }
            let rel = Path::new(d.path.as_str());
            let file_abs = ctx.scan_root.join(rel);
            Some(file_abs.parent().unwrap_or(ctx.scan_root).to_path_buf())
        })
    }
}

impl Remediator for NpmRemediator {
    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        if !self.npm_available() {
            return Err(RemediationError::MissingPackageManager(
                "npm".to_string(),
            ));
        }
        let lock_dir = self
            .select_npm_lock_dir(ctx)
            .ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "supported npm lockfile not found (need package-lock.json or npm-shrinkwrap.json)".to_string()
                )
            })?;

        let mut cmd = Command::new("npm");
        cmd.current_dir(lock_dir);
        cmd.arg("install");
        if !ctx.allow_dependency_code_execution {
            cmd.arg("--ignore-scripts");
        }
        cmd.arg("--package-lock-only");
        if matches!(ctx.dependency_kind, DependencyKind::Transitive) {
            // For transitive remediation, avoid mutating package.json.
            cmd.arg("--no-save");
        }
        cmd.arg(format!("{}@{}", ctx.package_name, ctx.target_version));

        let out = cmd.output()?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(RemediationError::CommandFailed {
                strategy: "npm".to_string(),
                message: stderr.trim().to_string(),
            })
        }
    }
}

/// Apply Cargo remediation by invoking:
/// `cargo update -p <name> --precise <version>`
pub struct CargoRemediator;

impl CargoRemediator {
    fn cargo_available(&self) -> bool {
        Command::new("cargo")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
    }

    fn select_cargo_lock_dir<'a>(
        &self,
        ctx: &'a RemediationContext<'a>,
    ) -> Option<std::path::PathBuf> {
        ctx.declarations.iter().find_map(|d| {
            if d.kind != DeclarationKind::Lockfile {
                return None;
            }
            let file = Path::new(d.path.as_str());
            if !file.file_name().is_some_and(|n| n == CARGO_LOCK_FILE_NAME) {
                return None;
            }
            let file_abs = ctx.scan_root.join(file);
            Some(file_abs.parent().unwrap_or(ctx.scan_root).to_path_buf())
        })
    }
}

impl Remediator for CargoRemediator {
    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        if !self.cargo_available() {
            return Err(RemediationError::MissingPackageManager(
                "cargo".to_string(),
            ));
        }
        let lock_dir = self.select_cargo_lock_dir(ctx).ok_or_else(|| {
            RemediationError::UnsupportedLockLayout(
                "Cargo.lock not found in declarations".to_string(),
            )
        })?;

        let mut cmd = Command::new("cargo");
        cmd.current_dir(lock_dir);
        cmd.arg("update");
        cmd.arg("-p");
        cmd.arg(ctx.package_name);
        cmd.arg("--precise");
        cmd.arg(ctx.target_version);

        let out = cmd.output()?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(RemediationError::CommandFailed {
                strategy: "cargo".to_string(),
                message: stderr.trim().to_string(),
            })
        }
    }
}
