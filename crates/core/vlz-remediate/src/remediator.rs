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

const NPM_BIN_NAME: &str = "npm";
const CARGO_BIN_NAME: &str = "cargo";

/// Apply npm remediation by invoking:
/// `npm install --ignore-scripts --package-lock-only <name>@<version>`
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
                NPM_BIN_NAME.to_string(),
            ));
        }
        let lock_dir = self
            .select_npm_lock_dir(ctx)
            .ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "supported npm lockfile not found (need package-lock.json or npm-shrinkwrap.json)".to_string()
                )
            })?;

        let mut cmd = Command::new(&self.bin);
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
                strategy: NPM_BIN_NAME.to_string(),
                message: stderr.trim().to_string(),
            })
        }
    }
}

/// Apply Cargo remediation by invoking:
/// `cargo update -p <name> --precise <version>`
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
                CARGO_BIN_NAME.to_string(),
            ));
        }
        let lock_dir = self.select_cargo_lock_dir(ctx).ok_or_else(|| {
            RemediationError::UnsupportedLockLayout(
                "Cargo.lock not found in declarations".to_string(),
            )
        })?;

        let mut cmd = Command::new(&self.bin);
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
                strategy: CARGO_BIN_NAME.to_string(),
                message: stderr.trim().to_string(),
            })
        }
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
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
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
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("Cargo.lock"), "# lock\n").unwrap();
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
    fn default_constructors_use_standard_bin_names() {
        assert_eq!(NpmRemediator::new().bin, NPM_BIN_NAME);
        assert_eq!(NpmRemediator::default().bin, NPM_BIN_NAME);
        assert_eq!(CargoRemediator::new().bin, CARGO_BIN_NAME);
        assert_eq!(CargoRemediator::default().bin, CARGO_BIN_NAME);
    }
}
