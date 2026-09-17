// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Remediation application via package-manager argv (FR-041 / MOD-011).
//!
//! Supported apply strategies (SEC-025):
//! - npm via `package-lock.json` / `npm-shrinkwrap.json`
//! - Yarn via `yarn.lock` (Classic and Berry basename)
//! - pnpm via `pnpm-lock.yaml`
//! - bun via `bun.lock`
//! - Cargo via `Cargo.lock`
//! - Python (PyPI) via `poetry.lock` (`poetry`) or `uv.lock` (`uv`)
//! - Go via `go.mod` (`go get`; `go.sum` is co-modified, not a selector)
//! - RubyGems via `Gemfile.lock` / `gems.locked` (`bundle add --skip-install`)
//! - Gradle via `gradle.lockfile` / `buildscript-gradle.lockfile`
//!   (`gradle dependencies --write-locks --update-locks <group:artifact>`)
//! - Maven via in-place `pom.xml` version bump (no subprocess; empty argv)
//!
//! Strategy selection for the npm ecosystem prefers npm locks, then yarn,
//! pnpm, then bun. PyPI apply strategies require `poetry.lock` or `uv.lock`;
//! `pylock.toml` / `pylock.*.toml` stay plan-only (`unavailable`) until an
//! apply path exists. Go findings select on `go.mod` manifest declarations
//! (Go emits no lockfile-kind declarations). Maven-ecosystem findings prefer a
//! Gradle lock (`Gradle` strategy) over a bare `pom.xml` (`Maven` strategy).
//!
//! SEC-023 for argv that can run lifecycle scripts: npm and bun default to
//! `--ignore-scripts` unless `allow_dependency_code_execution` is set. Yarn
//! Berry defaults to `--mode=skip-build`; Yarn Classic defaults to
//! `--ignore-scripts`. Cargo `update`, pnpm `--lockfile-only`, poetry
//! `--lock`, and uv `--no-sync` do not run dependency lifecycle installs.
//! RubyGems (`bundle`) and Gradle evaluate project code (`Gemfile` Ruby,
//! build scripts), so their previews fail closed without
//! `allow_dependency_code_execution` and apply stays `unavailable` with the
//! FR-041 stderr warning. Maven performs a local file edit only, so it needs
//! no gate and works offline. `go get` does not run dependency lifecycle
//! scripts, so the gate does not change Go argv.
//!
//! Transitive findings: npm uses `--no-save`; Cargo `update --precise` is
//! lock-safe; Gradle `--update-locks` regenerates the lock entry without
//! touching manifests. Yarn / pnpm / bun / poetry / uv refuse transitive apply so
//! they do not promote a transitive pin into a direct manifest dependency.
//! RubyGems `bundle add` edits the `Gemfile`, so it also refuses transitive
//! apply. Go `go get` records an explicit `require` directive, so transitive
//! apply is allowed and documented as promoting the module to a direct
//! requirement (the idiomatic `go get` behavior).
//!
//! Apply is fail-fast (first remediator error stops the batch). Earlier
//! successful writes are not rolled back.

use std::path::Path;
use std::process::Command;

use thiserror::Error;
use vlz_db::{
    CRATES_IO_ECOSYSTEM, DeclarationKind, GO_ECOSYSTEM, MAVEN_ECOSYSTEM,
    NPM_ECOSYSTEM, PYPI_ECOSYSTEM, Package, PackageDeclarationLocation,
    RUBYGEMS_ECOSYSTEM,
};

use crate::{
    ApplyStrategy, ApplyStrategy::Bun, ApplyStrategy::Cargo,
    ApplyStrategy::Go, ApplyStrategy::Gradle, ApplyStrategy::Maven,
    ApplyStrategy::Npm, ApplyStrategy::Pnpm, ApplyStrategy::Python,
    ApplyStrategy::RubyGems, ApplyStrategy::Yarn, DependencyKind,
    MIN_FIXED_VERSION_UNKNOWN,
};

/// npm lockfile basename (`package-lock.json`).
pub const NPM_LOCKFILE_PACKAGE_LOCK_JSON: &str = "package-lock.json";
/// npm lockfile basename (`npm-shrinkwrap.json`).
pub const NPM_LOCKFILE_NPM_SHRINKWRAP_JSON: &str = "npm-shrinkwrap.json";
/// Yarn lockfile basename (Classic and Berry).
pub const YARN_LOCK_FILE_NAME: &str = "yarn.lock";
/// pnpm lockfile basename.
pub const PNPM_LOCK_FILE_NAME: &str = "pnpm-lock.yaml";
/// bun lockfile basename (text `bun.lock`; `bun.lockb` out of scope).
pub const BUN_LOCK_FILE_NAME: &str = "bun.lock";
/// Cargo lockfile basename.
pub const CARGO_LOCK_FILE_NAME: &str = "Cargo.lock";
/// Poetry lockfile basename.
pub const POETRY_LOCK_FILE_NAME: &str = "poetry.lock";
/// uv lockfile basename.
pub const UV_LOCK_FILE_NAME: &str = "uv.lock";
/// PEP 751 pylock basename (`pylock.toml`).
pub const PYLOCK_TOML_FILE_NAME: &str = "pylock.toml";
/// Sibling npm / Yarn / pnpm / bun manifest required next to the lockfile (SEC-025).
pub const NPM_MANIFEST_FILE_NAME: &str = "package.json";
/// Sibling Cargo manifest required next to the lockfile (SEC-025).
pub const CARGO_MANIFEST_FILE_NAME: &str = "Cargo.toml";
/// Sibling Python manifest required next to poetry/uv lockfiles (SEC-025).
pub const PYTHON_MANIFEST_FILE_NAME: &str = "pyproject.toml";
/// Allowlisted npm binary name (SEC-025).
pub const NPM_BIN_NAME: &str = "npm";
/// Allowlisted yarn binary name (SEC-025).
pub const YARN_BIN_NAME: &str = "yarn";
/// Allowlisted pnpm binary name (SEC-025).
pub const PNPM_BIN_NAME: &str = "pnpm";
/// Allowlisted bun binary name (SEC-025).
pub const BUN_BIN_NAME: &str = "bun";
/// Allowlisted cargo binary name (SEC-025).
pub const CARGO_BIN_NAME: &str = "cargo";
/// Allowlisted poetry binary name (SEC-025).
pub const POETRY_BIN_NAME: &str = "poetry";
/// Allowlisted uv binary name (SEC-025).
pub const UV_BIN_NAME: &str = "uv";
/// npm flag that skips lifecycle scripts (SEC-023 scripts-only gate).
pub const NPM_IGNORE_SCRIPTS_FLAG: &str = "--ignore-scripts";
/// bun flag that skips lifecycle scripts (SEC-023 scripts-only gate).
pub const BUN_IGNORE_SCRIPTS_FLAG: &str = "--ignore-scripts";
/// Yarn Classic flag that skips lifecycle scripts (SEC-023).
pub const YARN_CLASSIC_IGNORE_SCRIPTS_FLAG: &str = "--ignore-scripts";
/// Yarn Berry mode that skips build / lifecycle scripts (SEC-023).
pub const YARN_BERRY_SKIP_BUILD_FLAG: &str = "--mode=skip-build";
/// Yarn Classic upgrade subcommand.
pub const YARN_CLASSIC_UPGRADE_SUBCOMMAND: &str = "upgrade";
/// Yarn Berry up subcommand.
pub const YARN_BERRY_UP_SUBCOMMAND: &str = "up";
/// Marker substring in Classic `yarn.lock` files (`# yarn lockfile v1`).
pub const YARN_CLASSIC_LOCKFILE_MARKER: &str = "yarn lockfile v1";
/// npm flag that updates the lockfile without a full install tree.
pub const NPM_PACKAGE_LOCK_ONLY_FLAG: &str = "--package-lock-only";
/// npm flag that avoids writing `package.json` for transitive upgrades.
pub const NPM_NO_SAVE_FLAG: &str = "--no-save";
/// pnpm flag that updates the lockfile without installing.
pub const PNPM_LOCKFILE_ONLY_FLAG: &str = "--lockfile-only";
/// poetry flag that updates the lockfile without installing.
pub const POETRY_LOCK_FLAG: &str = "--lock";
/// uv flag that updates the lock/manifest without syncing the env.
pub const UV_NO_SYNC_FLAG: &str = "--no-sync";
/// Go manifest basename (also the version selector; Go emits manifest-kind
/// declarations for `go.mod` and no lockfile-kind declarations).
pub const GO_MANIFEST_FILE_NAME: &str = "go.mod";
/// Go checksum basename (co-modified by `go get`, not a version selector).
pub const GO_SUM_FILE_NAME: &str = "go.sum";
/// Allowlisted go binary name (SEC-025).
pub const GO_BIN_NAME: &str = "go";
/// Ruby manifest basenames.
pub const RUBY_MANIFEST_GEMFILE_FILE_NAME: &str = "Gemfile";
pub const RUBY_MANIFEST_GEMS_RB_FILE_NAME: &str = "gems.rb";
/// Ruby lock basenames (pair-matched: `Gemfile` pairs `Gemfile.lock`,
/// `gems.rb` pairs `gems.locked`; mirrors `vlz-ruby` lock rules).
pub const RUBY_LOCK_GEMFILE_LOCK_FILE_NAME: &str = "Gemfile.lock";
pub const RUBY_LOCK_GEMS_LOCKED_FILE_NAME: &str = "gems.locked";
/// Allowlisted bundler binary name (SEC-025).
pub const BUNDLE_BIN_NAME: &str = "bundle";
/// Bundler flag that rewrites `Gemfile` and the lock without installing.
pub const BUNDLE_SKIP_INSTALL_FLAG: &str = "--skip-install";
/// Gradle lock basenames.
pub const GRADLE_LOCK_FILE_NAME: &str = "gradle.lockfile";
pub const GRADLE_BUILDSCRIPT_LOCK_FILE_NAME: &str =
    "buildscript-gradle.lockfile";
/// Gradle manifest basenames accepted as SEC-025 siblings next to the lock.
pub const GRADLE_MANIFEST_BUILD_FILE_NAME: &str = "build.gradle";
pub const GRADLE_MANIFEST_BUILD_KTS_FILE_NAME: &str = "build.gradle.kts";
/// Gradle version catalog basename (matched by file name; lives under
/// `gradle/`).
pub const GRADLE_VERSION_CATALOG_FILE_NAME: &str = "libs.versions.toml";
/// Gradle settings basenames (multi-module root markers).
pub const GRADLE_SETTINGS_FILE_NAME: &str = "settings.gradle";
pub const GRADLE_SETTINGS_KTS_FILE_NAME: &str = "settings.gradle.kts";
/// Allowlisted Gradle binary name (SEC-025; project wrappers stay a
/// follow-up).
pub const GRADLE_BIN_NAME: &str = "gradle";
/// Maven manifest basename (edited in place; Maven has no standard lock).
pub const MAVEN_MANIFEST_FILE_NAME: &str = "pom.xml";
/// Maximum `pom.xml` size read for in-place edits (1 MiB, SEC-017).
pub const MAVEN_POM_MAX_BYTES: usize = 1024 * 1024;

/// Yarn lockfile dialect (Classic v1 vs Berry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum YarnLockFlavor {
    Classic,
    Berry,
}

/// Detect Classic vs Berry from lockfile contents (SEC-025 / FR-041).
pub fn detect_yarn_lock_flavor(
    lock_path: &Path,
) -> Result<YarnLockFlavor, RemediationError> {
    let text = std::fs::read_to_string(lock_path).map_err(|err| {
        RemediationError::UnsupportedLockLayout(format!(
            "unable to read yarn.lock for dialect detection: {err}"
        ))
    })?;
    if text.contains(YARN_CLASSIC_LOCKFILE_MARKER) {
        Ok(YarnLockFlavor::Classic)
    } else {
        Ok(YarnLockFlavor::Berry)
    }
}

fn refuse_transitive_manifest_mutation(
    ctx: &RemediationContext<'_>,
    strategy: &str,
) -> Result<(), RemediationError> {
    if matches!(ctx.dependency_kind, DependencyKind::Transitive) {
        return Err(RemediationError::UnsupportedLockLayout(format!(
            "{strategy} cannot apply transitive upgrades without promoting the package to a direct dependency"
        )));
    }
    Ok(())
}

/// Resolve a lockfile declaration to a working directory under `scan_root`.
///
/// Path-form invariant: `declaration_path` must be absolute or relative to
/// `scan_root` (not relative to process CWD). Scan entry points normalize the
/// root to absolute/canonical form so discovery emits absolute declaration
/// paths; this helper must not re-resolve relative decls against CWD.
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

fn require_allowlisted_pypi_operands(
    package_name: &str,
    target_version: &str,
) -> Result<(), RemediationError> {
    if is_allowlisted_pypi_package_name(package_name)
        && is_allowlisted_version_operand(target_version)
    {
        Ok(())
    } else {
        Err(RemediationError::InvalidOperand(format!(
            "PyPI package/version not allowlisted: {package_name}@{target_version}"
        )))
    }
}

/// Allowlisted PyPI package name (PEP 503-ish: alnum, `-`, `_`, `.`).
fn is_allowlisted_pypi_package_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 128
        || name.starts_with('-')
        || name.starts_with('.')
    {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn lock_basename_eq(path: &str, expected: &str) -> bool {
    Path::new(path).file_name().is_some_and(|n| n == expected)
}

/// True for `pylock.toml` or `pylock.*.toml` (PEP 751).
fn is_applyable_python_lockfile(path: &str) -> bool {
    lock_basename_eq(path, POETRY_LOCK_FILE_NAME)
        || lock_basename_eq(path, UV_LOCK_FILE_NAME)
}

fn declaration_has_lock(
    declarations: &[PackageDeclarationLocation],
    pred: impl Fn(&str) -> bool,
) -> bool {
    declarations
        .iter()
        .any(|d| d.kind == DeclarationKind::Lockfile && pred(d.path.as_str()))
}

/// Where remediation can be applied.
///
/// This intentionally depends on both:
/// - the vulnerability ecosystem (`package.ecosystem`), and
/// - which lock file was used for resolution (declarations).
///
/// npm-ecosystem preference: supported npm locks, else yarn.lock, else
/// pnpm-lock.yaml, else bun.lock. PyPI: poetry.lock / uv.lock only
/// (pylock remains `unavailable` for apply until supported).
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
            if declaration_has_lock(declarations, is_supported_npm_lockfile) {
                Npm
            } else if declaration_has_lock(declarations, |p| {
                lock_basename_eq(p, YARN_LOCK_FILE_NAME)
            }) {
                Yarn
            } else if declaration_has_lock(declarations, |p| {
                lock_basename_eq(p, PNPM_LOCK_FILE_NAME)
            }) {
                Pnpm
            } else if declaration_has_lock(declarations, |p| {
                lock_basename_eq(p, BUN_LOCK_FILE_NAME)
            }) {
                Bun
            } else {
                ApplyStrategy::Unavailable
            }
        }
        Some(e) if e.eq_ignore_ascii_case(CRATES_IO_ECOSYSTEM) => {
            if declaration_has_lock(declarations, |p| {
                lock_basename_eq(p, CARGO_LOCK_FILE_NAME)
            }) {
                Cargo
            } else {
                ApplyStrategy::Unavailable
            }
        }
        Some(e) if e.eq_ignore_ascii_case(PYPI_ECOSYSTEM) => {
            if declaration_has_lock(declarations, is_applyable_python_lockfile)
            {
                Python
            } else {
                ApplyStrategy::Unavailable
            }
        }
        Some(e) if e.eq_ignore_ascii_case(GO_ECOSYSTEM) => {
            // Go emits manifest-kind declarations for `go.mod` (no
            // lockfile-kind declarations); `go.sum` is hashes only.
            if declarations.iter().any(|d| {
                d.kind == DeclarationKind::Manifest
                    && lock_basename_eq(d.path.as_str(), GO_MANIFEST_FILE_NAME)
            }) {
                Go
            } else {
                ApplyStrategy::Unavailable
            }
        }
        Some(e) if e.eq_ignore_ascii_case(RUBYGEMS_ECOSYSTEM) => {
            if declaration_has_lock(declarations, |p| {
                lock_basename_eq(p, RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)
                    || lock_basename_eq(p, RUBY_LOCK_GEMS_LOCKED_FILE_NAME)
            }) {
                RubyGems
            } else {
                ApplyStrategy::Unavailable
            }
        }
        Some(e) if e.eq_ignore_ascii_case(MAVEN_ECOSYSTEM) => {
            // Maven ecosystem covers both build systems: a Gradle lock
            // selects Gradle regeneration, otherwise a `pom.xml` manifest
            // selects the no-exec pom editor.
            if declaration_has_lock(declarations, |p| {
                lock_basename_eq(p, GRADLE_LOCK_FILE_NAME)
                    || lock_basename_eq(p, GRADLE_BUILDSCRIPT_LOCK_FILE_NAME)
            }) {
                Gradle
            } else if declarations.iter().any(|d| {
                d.kind == DeclarationKind::Manifest
                    && lock_basename_eq(
                        d.path.as_str(),
                        MAVEN_MANIFEST_FILE_NAME,
                    )
            }) {
                Maven
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
    /// When false, strategies that can run lifecycle scripts add skip flags
    /// (SEC-023): npm/bun `--ignore-scripts`, Yarn Classic `--ignore-scripts`,
    /// Yarn Berry `--mode=skip-build`. Cargo / pnpm lockfile-only / poetry
    /// `--lock` / uv `--no-sync` do not change argv for this flag.
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
    /// with apply). Empty for file-edit strategies that run no subprocess
    /// (e.g. Maven); apply then performs the previewed file edit directly.
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

/// Build allowlisted poetry add argv shared by preview and apply (NFR-024).
pub fn poetry_add_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
) -> Vec<String> {
    vec![
        bin.to_string(),
        "add".to_string(),
        format!("{package_name}@{target_version}"),
        POETRY_LOCK_FLAG.to_string(),
    ]
}

/// Build allowlisted uv add argv shared by preview and apply (NFR-024).
///
/// Uses `--no-sync` so only the lock/manifest update runs (no env install).
pub fn uv_add_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
) -> Vec<String> {
    vec![
        bin.to_string(),
        "add".to_string(),
        format!("{package_name}=={target_version}"),
        UV_NO_SYNC_FLAG.to_string(),
    ]
}

/// Build allowlisted Yarn argv shared by preview and apply (NFR-024 / SEC-023).
pub fn yarn_remediate_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
    flavor: YarnLockFlavor,
    allow_dependency_code_execution: bool,
) -> Vec<String> {
    let subcommand = match flavor {
        YarnLockFlavor::Classic => YARN_CLASSIC_UPGRADE_SUBCOMMAND,
        YarnLockFlavor::Berry => YARN_BERRY_UP_SUBCOMMAND,
    };
    let mut argv = vec![
        bin.to_string(),
        subcommand.to_string(),
        format!("{package_name}@{target_version}"),
    ];
    if !allow_dependency_code_execution {
        match flavor {
            YarnLockFlavor::Classic => {
                argv.push(YARN_CLASSIC_IGNORE_SCRIPTS_FLAG.to_string());
            }
            YarnLockFlavor::Berry => {
                argv.push(YARN_BERRY_SKIP_BUILD_FLAG.to_string());
            }
        }
    }
    argv
}

/// Berry `yarn up` argv helper (NFR-024). Prefer [`yarn_remediate_argv`].
pub fn yarn_up_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
    allow_dependency_code_execution: bool,
) -> Vec<String> {
    yarn_remediate_argv(
        bin,
        package_name,
        target_version,
        YarnLockFlavor::Berry,
        allow_dependency_code_execution,
    )
}

/// Build allowlisted pnpm update argv shared by preview and apply (NFR-024).
pub fn pnpm_update_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
) -> Vec<String> {
    vec![
        bin.to_string(),
        "update".to_string(),
        format!("{package_name}@{target_version}"),
        PNPM_LOCKFILE_ONLY_FLAG.to_string(),
    ]
}

/// Build allowlisted bun update argv shared by preview and apply (NFR-024).
pub fn bun_update_argv(
    bin: &str,
    package_name: &str,
    target_version: &str,
    allow_dependency_code_execution: bool,
) -> Vec<String> {
    let mut argv = vec![
        bin.to_string(),
        "update".to_string(),
        format!("{package_name}@{target_version}"),
    ];
    if !allow_dependency_code_execution {
        argv.push(BUN_IGNORE_SCRIPTS_FLAG.to_string());
    }
    argv
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
    pub(crate) bin: String,
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
    pub(crate) bin: String,
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

fn select_lock_dir_by_basename(
    ctx: &RemediationContext<'_>,
    lock_name: &str,
) -> Option<std::path::PathBuf> {
    ctx.declarations.iter().find_map(|d| {
        if d.kind != DeclarationKind::Lockfile {
            return None;
        }
        if !lock_basename_eq(d.path.as_str(), lock_name) {
            return None;
        }
        resolve_lock_workdir_under_root(ctx.scan_root, d.path.as_str())
    })
}

fn bin_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn js_lock_preview_files(
    lock_dir: &std::path::Path,
    lock_name: &str,
    dependency_kind: DependencyKind,
) -> Vec<std::path::PathBuf> {
    let mut files = vec![lock_dir.join(lock_name)];
    if matches!(dependency_kind, DependencyKind::Direct) {
        files.push(lock_dir.join(NPM_MANIFEST_FILE_NAME));
    }
    files
}

/// Apply Python remediation via poetry (`poetry.lock`) or uv (`uv.lock`).
#[derive(Debug, Clone)]
pub struct PythonRemediator {
    pub(crate) poetry_bin: String,
    pub(crate) uv_bin: String,
}

impl Default for PythonRemediator {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PythonLockTool {
    Poetry,
    Uv,
}

impl PythonRemediator {
    pub fn new() -> Self {
        Self {
            poetry_bin: POETRY_BIN_NAME.to_string(),
            uv_bin: UV_BIN_NAME.to_string(),
        }
    }

    /// Override the poetry executable path (tests inject a stub binary).
    pub fn with_poetry_bin(bin: impl Into<String>) -> Self {
        Self {
            poetry_bin: bin.into(),
            uv_bin: UV_BIN_NAME.to_string(),
        }
    }

    /// Override the uv executable path (tests inject a stub binary).
    pub fn with_uv_bin(bin: impl Into<String>) -> Self {
        Self {
            poetry_bin: POETRY_BIN_NAME.to_string(),
            uv_bin: bin.into(),
        }
    }

    fn select_python_lock(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Option<(PythonLockTool, std::path::PathBuf, &'static str)> {
        ctx.declarations.iter().find_map(|d| {
            if d.kind != DeclarationKind::Lockfile
                || !is_applyable_python_lockfile(d.path.as_str())
            {
                return None;
            }
            let dir = resolve_lock_workdir_under_root(
                ctx.scan_root,
                d.path.as_str(),
            )?;
            if lock_basename_eq(d.path.as_str(), POETRY_LOCK_FILE_NAME) {
                Some((PythonLockTool::Poetry, dir, POETRY_LOCK_FILE_NAME))
            } else {
                Some((PythonLockTool::Uv, dir, UV_LOCK_FILE_NAME))
            }
        })
    }
}

impl Remediator for PythonRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Python
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        require_allowlisted_pypi_operands(
            ctx.package_name,
            ctx.target_version,
        )?;
        refuse_transitive_manifest_mutation(ctx, "python")?;
        let (tool, lock_dir, lock_name) =
            self.select_python_lock(ctx).ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "supported Python lockfile not found under scan root (need poetry.lock or uv.lock)".to_string(),
                )
            })?;
        require_sibling_manifest(&lock_dir, PYTHON_MANIFEST_FILE_NAME)?;
        let mut files = vec![lock_dir.join(lock_name)];
        if matches!(ctx.dependency_kind, DependencyKind::Direct) {
            files.push(lock_dir.join(PYTHON_MANIFEST_FILE_NAME));
        }
        let argv = match tool {
            PythonLockTool::Poetry => poetry_add_argv(
                &self.poetry_bin,
                ctx.package_name,
                ctx.target_version,
            ),
            PythonLockTool::Uv => {
                uv_add_argv(&self.uv_bin, ctx.package_name, ctx.target_version)
            }
        };
        Ok(RemediationPreview {
            strategy: Python,
            workdir: lock_dir,
            files,
            argv,
        })
    }

    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        let (tool, _, _) =
            self.select_python_lock(ctx).ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "supported Python lockfile not found under scan root (need poetry.lock or uv.lock)".to_string(),
                )
            })?;
        let (bin_path, bin_name) = match tool {
            PythonLockTool::Poetry => {
                (self.poetry_bin.as_str(), POETRY_BIN_NAME)
            }
            PythonLockTool::Uv => (self.uv_bin.as_str(), UV_BIN_NAME),
        };
        if !bin_available(bin_path) {
            return Err(RemediationError::MissingPackageManager(
                bin_name.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, bin_name)
    }
}

/// Apply Yarn remediation by invoking: `yarn up <name>@<version>`.
#[derive(Debug, Clone)]
pub struct YarnRemediator {
    pub(crate) bin: String,
}

impl Default for YarnRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl YarnRemediator {
    pub fn new() -> Self {
        Self {
            bin: YARN_BIN_NAME.to_string(),
        }
    }

    /// Override the yarn executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }
}

impl Remediator for YarnRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Yarn
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
        refuse_transitive_manifest_mutation(ctx, "yarn")?;
        let lock_dir = select_lock_dir_by_basename(ctx, YARN_LOCK_FILE_NAME)
            .ok_or_else(|| {
            RemediationError::UnsupportedLockLayout(
                "yarn.lock not found under scan root".to_string(),
            )
        })?;
        require_sibling_manifest(&lock_dir, NPM_MANIFEST_FILE_NAME)?;
        let lock_path = lock_dir.join(YARN_LOCK_FILE_NAME);
        let flavor = detect_yarn_lock_flavor(&lock_path)?;
        Ok(RemediationPreview {
            strategy: Yarn,
            files: js_lock_preview_files(
                &lock_dir,
                YARN_LOCK_FILE_NAME,
                ctx.dependency_kind,
            ),
            workdir: lock_dir,
            argv: yarn_remediate_argv(
                &self.bin,
                ctx.package_name,
                ctx.target_version,
                flavor,
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
        if !bin_available(&self.bin) {
            return Err(RemediationError::MissingPackageManager(
                YARN_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, YARN_BIN_NAME)
    }
}

/// Apply pnpm remediation by invoking:
/// `pnpm update <name>@<version> --lockfile-only`.
#[derive(Debug, Clone)]
pub struct PnpmRemediator {
    pub(crate) bin: String,
}

impl Default for PnpmRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl PnpmRemediator {
    pub fn new() -> Self {
        Self {
            bin: PNPM_BIN_NAME.to_string(),
        }
    }

    /// Override the pnpm executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }
}

impl Remediator for PnpmRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Pnpm
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
        refuse_transitive_manifest_mutation(ctx, "pnpm")?;
        let lock_dir = select_lock_dir_by_basename(ctx, PNPM_LOCK_FILE_NAME)
            .ok_or_else(|| {
            RemediationError::UnsupportedLockLayout(
                "pnpm-lock.yaml not found under scan root".to_string(),
            )
        })?;
        require_sibling_manifest(&lock_dir, NPM_MANIFEST_FILE_NAME)?;
        Ok(RemediationPreview {
            strategy: Pnpm,
            files: js_lock_preview_files(
                &lock_dir,
                PNPM_LOCK_FILE_NAME,
                ctx.dependency_kind,
            ),
            workdir: lock_dir,
            argv: pnpm_update_argv(
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
        if !bin_available(&self.bin) {
            return Err(RemediationError::MissingPackageManager(
                PNPM_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, PNPM_BIN_NAME)
    }
}

/// Apply bun remediation by invoking: `bun update <name>@<version>`.
#[derive(Debug, Clone)]
pub struct BunRemediator {
    pub(crate) bin: String,
}

impl Default for BunRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl BunRemediator {
    pub fn new() -> Self {
        Self {
            bin: BUN_BIN_NAME.to_string(),
        }
    }

    /// Override the bun executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }
}

impl Remediator for BunRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Bun
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
        refuse_transitive_manifest_mutation(ctx, "bun")?;
        let lock_dir = select_lock_dir_by_basename(ctx, BUN_LOCK_FILE_NAME)
            .ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "bun.lock not found under scan root".to_string(),
                )
            })?;
        require_sibling_manifest(&lock_dir, NPM_MANIFEST_FILE_NAME)?;
        Ok(RemediationPreview {
            strategy: Bun,
            files: js_lock_preview_files(
                &lock_dir,
                BUN_LOCK_FILE_NAME,
                ctx.dependency_kind,
            ),
            workdir: lock_dir,
            argv: bun_update_argv(
                &self.bin,
                ctx.package_name,
                ctx.target_version,
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
        if !bin_available(&self.bin) {
            return Err(RemediationError::MissingPackageManager(
                BUN_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, BUN_BIN_NAME)
    }
}

// ---------------------------------------------------------------------
// Go / RubyGems / Gradle / Maven remediators (Wave 1 expansion).
// TDD red phase: builders, validators, and preview/apply are stubs until
// the failing tests below are confirmed red, then implemented slice by
// slice (Go, RubyGems, Gradle, Maven).
// ---------------------------------------------------------------------

/// Allowlisted Go module path for `go get` operands.
///
/// Segments of alnum plus `.`, `-`, `_`, `~` joined by `/`; rejects `!`
/// (uppercase escape), empty segments, and `..`.
fn is_allowlisted_go_module(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    if !name.chars().all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '~' | '/')
    }) {
        return false;
    }
    if name.starts_with('-') || name.starts_with('.') || name.starts_with('/')
    {
        return false;
    }
    for segment in name.split('/') {
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.starts_with('-')
        {
            return false;
        }
    }
    true
}

/// Allowlisted Maven coordinate (`groupId:artifactId`, exactly one colon).
fn is_allowlisted_maven_coordinate(coord: &str) -> bool {
    if coord.is_empty() || coord.len() > 256 {
        return false;
    }
    let Some((group, artifact)) = coord.split_once(':') else {
        return false;
    };
    if artifact.contains(':') {
        return false;
    }
    for part in [group, artifact] {
        if part.is_empty() {
            return false;
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            return false;
        }
        if part.starts_with('-') || part.starts_with('.') {
            return false;
        }
    }
    true
}

fn require_allowlisted_go_operands(
    module: &str,
    version: &str,
) -> Result<(), RemediationError> {
    if is_allowlisted_go_module(module)
        && is_allowlisted_version_operand(version)
    {
        Ok(())
    } else {
        Err(RemediationError::InvalidOperand(format!(
            "go module/version not allowlisted: {module}@{version}"
        )))
    }
}

fn require_allowlisted_maven_operands(
    coordinate: &str,
    version: &str,
) -> Result<(), RemediationError> {
    if is_allowlisted_maven_coordinate(coordinate)
        && is_allowlisted_version_operand(version)
    {
        Ok(())
    } else {
        Err(RemediationError::InvalidOperand(format!(
            "Maven coordinate/version not allowlisted: {coordinate}@{version}"
        )))
    }
}

/// Build allowlisted `go get` argv shared by preview and apply (NFR-024).
///
/// `version` must already carry the `v` prefix when required (the remediator
/// normalizes `minimal_fixed_version` before calling).
pub fn go_get_argv(bin: &str, module: &str, version: &str) -> Vec<String> {
    vec![
        bin.to_string(),
        "get".to_string(),
        format!("{module}@{version}"),
    ]
}

/// Build allowlisted `bundle add` argv shared by preview and apply (NFR-024).
///
/// Uses `--skip-install` so only `Gemfile` and the lock update (no install).
pub fn bundle_add_argv(bin: &str, gem: &str, version: &str) -> Vec<String> {
    vec![
        bin.to_string(),
        "add".to_string(),
        gem.to_string(),
        format!("--version={version}"),
        BUNDLE_SKIP_INSTALL_FLAG.to_string(),
    ]
}

/// Build allowlisted Gradle lock-regeneration argv shared by preview and
/// apply (NFR-024).
///
/// Scopes regeneration to one `group:artifact` coordinate; Gradle resolves
/// the entry to the latest version allowed by declared constraints.
pub fn gradle_update_argv(bin: &str, coordinate: &str) -> Vec<String> {
    vec![
        bin.to_string(),
        "dependencies".to_string(),
        "--write-locks".to_string(),
        "--update-locks".to_string(),
        coordinate.to_string(),
    ]
}

/// Distinct scan-root-confined directories for same-kind declarations.
///
/// Refusing multi-tree findings instead of fixing only the first tree:
/// a partial fix would leave sibling modules vulnerable with no message
/// explaining why (Wave 1 review finding).
fn distinct_decl_dirs(
    ctx: &RemediationContext<'_>,
    kind: DeclarationKind,
    matches: impl Fn(&str) -> bool,
) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    for d in ctx
        .declarations
        .iter()
        .filter(|d| d.kind == kind && matches(d.path.as_str()))
    {
        if let Some(dir) =
            resolve_lock_workdir_under_root(ctx.scan_root, d.path.as_str())
            && !dirs.contains(&dir)
        {
            dirs.push(dir);
        }
    }
    dirs
}

fn require_single_decl_dir(
    ctx: &RemediationContext<'_>,
    kind: DeclarationKind,
    matches: impl Fn(&str) -> bool,
    missing_msg: &str,
    multi_msg: &str,
) -> Result<std::path::PathBuf, RemediationError> {
    let dirs = distinct_decl_dirs(ctx, kind, matches);
    match dirs.as_slice() {
        [dir] => Ok(dir.clone()),
        [] => Err(RemediationError::UnsupportedLockLayout(
            missing_msg.to_string(),
        )),
        _ => Err(RemediationError::UnsupportedLockLayout(
            multi_msg.to_string(),
        )),
    }
}

fn require_gradle_sibling_manifest(
    lock_dir: &Path,
) -> Result<(), RemediationError> {
    for name in [
        GRADLE_MANIFEST_BUILD_FILE_NAME,
        GRADLE_MANIFEST_BUILD_KTS_FILE_NAME,
        GRADLE_VERSION_CATALOG_FILE_NAME,
        GRADLE_SETTINGS_FILE_NAME,
        GRADLE_SETTINGS_KTS_FILE_NAME,
    ] {
        if lock_dir.join(name).is_file() {
            return Ok(());
        }
    }
    Err(RemediationError::UnsupportedLockLayout(
        "Gradle lockfile without a sibling build manifest (build.gradle, build.gradle.kts, gradle/libs.versions.toml, or settings.gradle*)"
            .to_string(),
    ))
}

/// Compute the edited `pom.xml` text for a strict single-match version bump.
///
/// Matches one `<dependency>` block for `groupId:artifactId` outside
/// `<profiles>`; bumps a direct `<version>` or the single same-file
/// `<properties>` entry it references. Refuses zero/multiple matches,
/// ranges, inherited (missing) versions, and properties defined outside the
/// same file.
fn compute_pom_version_edit(
    pom_text: &str,
    group: &str,
    artifact: &str,
    new_version: &str,
) -> Result<String, RemediationError> {
    if pom_text.len() > MAVEN_POM_MAX_BYTES {
        return Err(RemediationError::UnsupportedLockLayout(format!(
            "pom.xml exceeds size limit ({} bytes)",
            MAVEN_POM_MAX_BYTES
        )));
    }
    let unsupported =
        |msg: String| RemediationError::UnsupportedLockLayout(msg);

    // Non-nested `<tag>...</tag>` region spans in `text`.
    fn region_spans(text: &str, tag: &str) -> Vec<(usize, usize)> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut spans = Vec::new();
        let mut cursor = 0;
        while let Some(found) = text[cursor..].find(open.as_str()) {
            let start = cursor + found;
            let after_open = start + open.len();
            let Some(rel) = text[after_open..].find(close.as_str()) else {
                break;
            };
            let end = after_open + rel + close.len();
            spans.push((start, end));
            cursor = end;
        }
        spans
    }

    // First `<tag>text</tag>` whose start is outside `skip`, with inner
    // offsets relative to `block`. Refuses nested markup inside the value.
    fn element_text_outside(
        block: &str,
        tag: &str,
        skip: &[(usize, usize)],
    ) -> Option<(usize, usize, String)> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let mut cursor = 0;
        while let Some(found) = block[cursor..].find(open.as_str()) {
            let tag_start = cursor + found;
            if skip.iter().any(|(s, e)| tag_start >= *s && tag_start < *e) {
                cursor = tag_start + 1;
                continue;
            }
            let inner_start = tag_start + open.len();
            let rel = block[inner_start..].find(close.as_str())?;
            let inner_end = inner_start + rel;
            let inner = &block[inner_start..inner_end];
            if inner.contains('<') || inner.contains('>') {
                return None;
            }
            return Some((inner_start, inner_end, inner.trim().to_string()));
        }
        None
    }

    fn is_range_version(text: &str) -> bool {
        text.contains(['[', ']', '(', ')', ','])
    }

    let profiles = region_spans(pom_text, "profiles");
    let in_profiles =
        |off: usize| profiles.iter().any(|(s, e)| off >= *s && off < *e);

    // All `<dependency>` blocks with absolute offsets.
    let mut blocks = Vec::new();
    {
        let mut cursor = 0;
        while let Some(found) = pom_text[cursor..].find("<dependency>") {
            let start = cursor + found;
            let after_open = start + "<dependency>".len();
            let Some(rel) = pom_text[after_open..].find("</dependency>")
            else {
                break;
            };
            let end = after_open + rel + "</dependency>".len();
            blocks.push((start, end));
            cursor = end;
        }
    }

    // Candidate blocks: outside profiles with matching coordinates
    // (exclusion coordinates never match).
    let mut candidates = Vec::new();
    for (block_start, block_end) in &blocks {
        if in_profiles(*block_start) {
            continue;
        }
        let body = &pom_text[*block_start..*block_end];
        let exclusions = region_spans(body, "exclusions");
        let matched = matches!(
            (
                element_text_outside(body, "groupId", &exclusions),
                element_text_outside(body, "artifactId", &exclusions),
            ),
            (Some((_, _, g)), Some((_, _, a)))
                if g == group && a == artifact
        );
        if matched {
            let version = element_text_outside(body, "version", &exclusions);
            candidates.push((*block_start, *block_end, version));
        }
    }
    if candidates.is_empty() {
        return Err(unsupported(format!(
            "no updatable dependency {group}:{artifact} in pom.xml (missing, inherited, or profile-scoped)"
        )));
    }
    if candidates.len() > 1 {
        return Err(unsupported(format!(
            "multiple dependencies match {group}:{artifact}; refusing ambiguous pom.xml edit"
        )));
    }
    let (block_start, _, version) = &candidates[0];
    let Some((ver_start, ver_end, ver_text)) = version else {
        return Err(unsupported(format!(
            "dependency {group}:{artifact} has no direct version (inherited); refusing pom.xml edit"
        )));
    };
    if ver_text.is_empty() || is_range_version(ver_text) {
        return Err(unsupported(format!(
            "dependency {group}:{artifact} version is a range or empty; refusing pom.xml edit"
        )));
    }

    // Resolve the absolute replacement span: direct version text, or the
    // single same-file property it references.
    let (abs_start, abs_end) = if let Some(prop) = ver_text
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
    {
        if prop.is_empty()
            || !prop.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')
            })
        {
            return Err(unsupported(format!(
                "dependency {group}:{artifact} references an unsupported property; refusing pom.xml edit"
            )));
        }
        let mut defs = Vec::new();
        let mut cursor = 0;
        while let Some(found) =
            pom_text[cursor..].find(format!("<{prop}>").as_str())
        {
            let tag_start = cursor + found;
            if !in_profiles(tag_start)
                && let Some((inner_start, inner_end, text)) =
                    element_text_outside(&pom_text[tag_start..], prop, &[])
            {
                defs.push((
                    tag_start + inner_start,
                    tag_start + inner_end,
                    text,
                ));
            }
            cursor = tag_start + 1;
        }
        if defs.len() != 1 {
            return Err(unsupported(format!(
                "property {prop} is defined {} times; refusing pom.xml edit",
                defs.len()
            )));
        }
        let (def_start, def_end, def_text) = &defs[0];
        if def_text.is_empty() || is_range_version(def_text) {
            return Err(unsupported(format!(
                "property {prop} value is a range or empty; refusing pom.xml edit"
            )));
        }
        (*def_start, *def_end)
    } else {
        (block_start + ver_start, block_start + ver_end)
    };

    let mut edited = pom_text.to_string();
    edited.replace_range(abs_start..abs_end, new_version);
    Ok(edited)
}

/// Apply Go remediation by invoking: `go get <module>@<version>`.
#[derive(Debug, Clone)]
pub struct GoRemediator {
    pub(crate) bin: String,
}

impl Default for GoRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl GoRemediator {
    pub fn new() -> Self {
        Self {
            bin: GO_BIN_NAME.to_string(),
        }
    }

    /// Override the go executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }
}

impl Remediator for GoRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Go
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        // `go get` records an explicit `require` directive, so transitive
        // findings are allowed (the promotion is idiomatic `go get`
        // behavior, unlike manifest-promoting Yarn/pnpm/bun edits).
        let version = if ctx.target_version.starts_with('v') {
            ctx.target_version.to_string()
        } else {
            format!("v{}", ctx.target_version)
        };
        require_allowlisted_go_operands(ctx.package_name, &version)?;
        let manifest_dir = require_single_decl_dir(
            ctx,
            DeclarationKind::Manifest,
            |p| lock_basename_eq(p, GO_MANIFEST_FILE_NAME),
            "go.mod not found under scan root",
            "multiple go.mod directories declare this module; refusing ambiguous remediation (fix each module separately)",
        )?;
        require_sibling_manifest(&manifest_dir, GO_MANIFEST_FILE_NAME)?;
        Ok(RemediationPreview {
            strategy: Go,
            workdir: manifest_dir.clone(),
            files: vec![
                manifest_dir.join(GO_MANIFEST_FILE_NAME),
                manifest_dir.join(GO_SUM_FILE_NAME),
            ],
            argv: go_get_argv(&self.bin, ctx.package_name, &version),
        })
    }

    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        if !bin_available(&self.bin) {
            return Err(RemediationError::MissingPackageManager(
                GO_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, GO_BIN_NAME)
    }
}

/// Apply RubyGems remediation by invoking:
/// `bundle add <gem> --version=<version> --skip-install`.
#[derive(Debug, Clone)]
pub struct RubyGemsRemediator {
    pub(crate) bin: String,
}

impl Default for RubyGemsRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl RubyGemsRemediator {
    pub fn new() -> Self {
        Self {
            bin: BUNDLE_BIN_NAME.to_string(),
        }
    }

    /// Override the bundle executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }
}

impl Remediator for RubyGemsRemediator {
    fn strategy(&self) -> ApplyStrategy {
        RubyGems
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        require_allowlisted_pypi_operands(
            ctx.package_name,
            ctx.target_version,
        )?;
        refuse_transitive_manifest_mutation(ctx, "rubygems")?;
        // `bundle` evaluates `Gemfile` Ruby (project code, SEC-023):
        // fail closed without the gate.
        if !ctx.allow_dependency_code_execution {
            return Err(RemediationError::UnsupportedLockLayout(
                "RubyGems remediation requires allow_dependency_code_execution (bundle evaluates Gemfile Ruby)"
                    .to_string(),
            ));
        }
        let (lock_dir, lock_name, manifest_name) =
            select_ruby_lock(ctx).ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "supported RubyGems lockfile not found under scan root (need Gemfile.lock with Gemfile, or gems.locked with gems.rb)"
                        .to_string(),
                )
            })?;
        // One tree only: a finding spanning several lock directories must
        // not fix just the first one.
        require_single_decl_dir(
            ctx,
            DeclarationKind::Lockfile,
            |p| {
                lock_basename_eq(p, RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)
                    || lock_basename_eq(p, RUBY_LOCK_GEMS_LOCKED_FILE_NAME)
            },
            "supported RubyGems lockfile not found under scan root",
            "multiple RubyGems lock directories declare this gem; refusing ambiguous remediation (fix each tree separately)",
        )?;
        require_sibling_manifest(&lock_dir, manifest_name)?;
        Ok(RemediationPreview {
            strategy: RubyGems,
            workdir: lock_dir.clone(),
            files: vec![
                lock_dir.join(lock_name),
                lock_dir.join(manifest_name),
            ],
            argv: bundle_add_argv(
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
        if !bin_available(&self.bin) {
            return Err(RemediationError::MissingPackageManager(
                BUNDLE_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(&preview.argv, &preview.workdir, BUNDLE_BIN_NAME)
    }
}

/// Pair-matched RubyGems lock selection.
///
/// Returns the lock directory, lock basename, and required sibling manifest
/// basename. `Gemfile` pairs `Gemfile.lock`; `gems.rb` pairs `gems.locked`;
/// mismatched pairs are refused (mirrors `vlz-ruby` lock rules without
/// depending on the language crate).
fn select_ruby_lock(
    ctx: &RemediationContext<'_>,
) -> Option<(std::path::PathBuf, &'static str, &'static str)> {
    ctx.declarations.iter().find_map(|d| {
        if d.kind != DeclarationKind::Lockfile {
            return None;
        }
        let (lock_name, manifest_name) = if lock_basename_eq(
            d.path.as_str(),
            RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
        ) {
            (
                RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
                RUBY_MANIFEST_GEMFILE_FILE_NAME,
            )
        } else if lock_basename_eq(
            d.path.as_str(),
            RUBY_LOCK_GEMS_LOCKED_FILE_NAME,
        ) {
            (
                RUBY_LOCK_GEMS_LOCKED_FILE_NAME,
                RUBY_MANIFEST_GEMS_RB_FILE_NAME,
            )
        } else {
            return None;
        };
        let dir =
            resolve_lock_workdir_under_root(ctx.scan_root, d.path.as_str())?;
        // The sibling manifest itself must be the paired one: a lock dir
        // containing the wrong manifest (e.g. `gems.locked` next to a
        // `Gemfile`) is a mismatched pair.
        if !dir.join(manifest_name).is_file() {
            return None;
        }
        Some((dir, lock_name, manifest_name))
    })
}

/// Apply Gradle remediation by invoking:
/// `gradle dependencies --write-locks --update-locks <group:artifact>`.
#[derive(Debug, Clone)]
pub struct GradleRemediator {
    pub(crate) bin: String,
}

impl Default for GradleRemediator {
    fn default() -> Self {
        Self::new()
    }
}

impl GradleRemediator {
    pub fn new() -> Self {
        Self {
            bin: GRADLE_BIN_NAME.to_string(),
        }
    }

    /// Override the gradle executable path (tests inject a stub binary).
    pub fn with_bin(bin: impl Into<String>) -> Self {
        Self { bin: bin.into() }
    }
}

impl Remediator for GradleRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Gradle
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        require_allowlisted_maven_operands(
            ctx.package_name,
            ctx.target_version,
        )?;
        // Gradle executes build scripts (project code, SEC-023): fail closed
        // without the gate.
        if !ctx.allow_dependency_code_execution {
            return Err(RemediationError::UnsupportedLockLayout(
                "Gradle remediation requires allow_dependency_code_execution (Gradle executes build scripts)"
                    .to_string(),
            ));
        }
        // Lock regeneration touches only the lock entry, so transitive
        // findings are allowed (no manifest promotion).
        let (lock_dir, lock_name) =
            select_gradle_lock(ctx).ok_or_else(|| {
                RemediationError::UnsupportedLockLayout(
                    "supported Gradle lockfile not found under scan root (need gradle.lockfile or buildscript-gradle.lockfile)"
                        .to_string(),
                )
            })?;
        // One tree only: a finding spanning several lock directories must
        // not regenerate just the first one.
        require_single_decl_dir(
            ctx,
            DeclarationKind::Lockfile,
            |p| {
                lock_basename_eq(p, GRADLE_LOCK_FILE_NAME)
                    || lock_basename_eq(p, GRADLE_BUILDSCRIPT_LOCK_FILE_NAME)
            },
            "supported Gradle lockfile not found under scan root",
            "multiple Gradle lock directories declare this dependency; refusing ambiguous remediation (fix each module separately)",
        )?;
        require_gradle_sibling_manifest(&lock_dir)?;
        Ok(RemediationPreview {
            strategy: Gradle,
            workdir: lock_dir.clone(),
            files: vec![lock_dir.join(lock_name)],
            argv: gradle_update_argv(&self.bin, ctx.package_name),
        })
    }

    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        if ctx.offline {
            return Err(RemediationError::OfflineBlocked);
        }
        if !bin_available(&self.bin) {
            return Err(RemediationError::MissingPackageManager(
                GRADLE_BIN_NAME.to_string(),
            ));
        }
        let preview = self.preview(ctx)?;
        run_allowlisted_argv(
            &preview.argv,
            &preview.workdir,
            GRADLE_BIN_NAME,
        )?;
        // Regeneration is not an exact pin: verify the lock entry advanced
        // instead of silently no-opping (e.g. a catalog pin Gradle refuses
        // to override).
        let [lock_path] = preview.files.as_slice() else {
            return Err(RemediationError::UnsupportedLockLayout(
                "Gradle preview must reference exactly one lockfile"
                    .to_string(),
            ));
        };
        let lock_text = std::fs::read_to_string(lock_path).map_err(|err| {
            RemediationError::CommandFailed {
                strategy: GRADLE_BIN_NAME.to_string(),
                message: format!(
                    "unable to re-read {} after regeneration: {err}",
                    lock_path.display()
                ),
            }
        })?;
        if !gradle_lock_satisfies_target(
            &lock_text,
            ctx.package_name,
            ctx.target_version,
        ) {
            return Err(RemediationError::CommandFailed {
                strategy: GRADLE_BIN_NAME.to_string(),
                message: format!(
                    "lock entry for {} did not advance to {} after regeneration; check version constraints (the catalog or build file may pin the vulnerable version)",
                    ctx.package_name, ctx.target_version
                ),
            });
        }
        Ok(())
    }
}

/// Gradle lock selection (prefers `gradle.lockfile` over the buildscript
/// lock when both are declared).
fn select_gradle_lock(
    ctx: &RemediationContext<'_>,
) -> Option<(std::path::PathBuf, &'static str)> {
    for lock_name in [GRADLE_LOCK_FILE_NAME, GRADLE_BUILDSCRIPT_LOCK_FILE_NAME]
    {
        if let Some(dir) = select_lock_dir_by_basename(ctx, lock_name) {
            return Some((dir, lock_name));
        }
    }
    None
}

/// Locked versions for one `group:artifact` coordinate in `gradle.lockfile`
/// text (`group:artifact:version=configuration` lines; comments and `empty=`
/// markers skipped).
fn gradle_lock_versions_for(lock_text: &str, coordinate: &str) -> Vec<String> {
    let prefix = format!("{coordinate}:");
    lock_text
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with('#')
                || trimmed.starts_with("empty=")
            {
                return None;
            }
            let entry = trimmed.split('=').next().unwrap_or(trimmed);
            let version = entry.strip_prefix(prefix.as_str())?;
            if version.is_empty() || version.contains(':') {
                return None;
            }
            Some(version.to_string())
        })
        .collect()
}

/// True when the lock already records `coordinate` at `target` (or newer
/// when both parse as strict semver).
fn gradle_lock_satisfies_target(
    lock_text: &str,
    coordinate: &str,
    target: &str,
) -> bool {
    let versions = gradle_lock_versions_for(lock_text, coordinate);
    if versions.iter().any(|v| v == target) {
        return true;
    }
    let Ok(want) = semver::Version::parse(target) else {
        return false;
    };
    versions
        .iter()
        .any(|v| semver::Version::parse(v).is_ok_and(|have| have >= want))
}

/// Apply Maven remediation with a no-exec in-place `pom.xml` version bump.
///
/// Preview carries an empty `argv` (no subprocess) and `files: [pom.xml]`;
/// apply rewrites the single matched `<version>` element.
#[derive(Debug, Clone, Default)]
pub struct MavenRemediator;

impl MavenRemediator {
    pub fn new() -> Self {
        Self
    }
}

impl Remediator for MavenRemediator {
    fn strategy(&self) -> ApplyStrategy {
        Maven
    }

    fn preview(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<RemediationPreview, RemediationError> {
        if ctx.target_version == MIN_FIXED_VERSION_UNKNOWN {
            return Err(RemediationError::TargetVersionUnknown);
        }
        require_allowlisted_maven_operands(
            ctx.package_name,
            ctx.target_version,
        )?;
        let pom_dir = require_single_decl_dir(
            ctx,
            DeclarationKind::Manifest,
            |p| lock_basename_eq(p, MAVEN_MANIFEST_FILE_NAME),
            "pom.xml not found under scan root",
            "multiple pom.xml directories declare this dependency; refusing ambiguous remediation (fix each module separately)",
        )?;
        let pom_path = pom_dir.join(MAVEN_MANIFEST_FILE_NAME);
        let pom_text = std::fs::read_to_string(&pom_path).map_err(|err| {
            RemediationError::UnsupportedLockLayout(format!(
                "unable to read pom.xml for edit preview: {err}"
            ))
        })?;
        let (group, artifact) =
            ctx.package_name.split_once(':').ok_or_else(|| {
                RemediationError::InvalidOperand(format!(
                    "Maven coordinate is not group:artifact: {}",
                    ctx.package_name
                ))
            })?;
        // Validate the edit applies before advertising it (FR-041 dry-run
        // fidelity); the same computation runs again on apply.
        compute_pom_version_edit(
            &pom_text,
            group,
            artifact,
            ctx.target_version,
        )?;
        Ok(RemediationPreview {
            strategy: Maven,
            workdir: pom_dir.clone(),
            files: vec![pom_path],
            // No subprocess for file-edit strategies (see trait docs).
            argv: Vec::new(),
        })
    }

    fn apply(
        &self,
        ctx: &RemediationContext<'_>,
    ) -> Result<(), RemediationError> {
        // No offline block: the edit is local and needs no network.
        // No package-manager availability check: no subprocess runs.
        let preview = self.preview(ctx)?;
        let [pom_path] = preview.files.as_slice() else {
            return Err(RemediationError::UnsupportedLockLayout(
                "Maven preview must reference exactly one pom.xml".to_string(),
            ));
        };
        let pom_text = std::fs::read_to_string(pom_path).map_err(|err| {
            RemediationError::UnsupportedLockLayout(format!(
                "unable to read pom.xml for edit: {err}"
            ))
        })?;
        let (group, artifact) =
            ctx.package_name.split_once(':').ok_or_else(|| {
                RemediationError::InvalidOperand(format!(
                    "Maven coordinate is not group:artifact: {}",
                    ctx.package_name
                ))
            })?;
        let edited = compute_pom_version_edit(
            &pom_text,
            group,
            artifact,
            ctx.target_version,
        )?;
        std::fs::write(pom_path, edited)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use vlz_db::{CRATES_IO_ECOSYSTEM, NPM_ECOSYSTEM, PYPI_ECOSYSTEM};

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

    /// Stable base for test tempdirs (ignores process `TMPDIR`).
    ///
    /// Intentionally mirrors the `vlz` config test helper: there is no shared
    /// test crate, and this crate cannot depend on `vlz`.
    fn stable_test_temp_base() -> &'static Path {
        Path::new("/tmp")
    }

    fn test_tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("vlz-remediate-")
            .tempdir_in(stable_test_temp_base())
            .expect("create isolated remediator test tempdir")
    }

    /// Write an executable stub via rename-before-exec (avoids Linux ETXTBSY
    /// when the final path is still open for write). Does not probe readiness.
    fn write_stub_script(path: &Path, body: &str) {
        let tmp = path.with_extension("write-tmp");
        fs::write(&tmp, body).unwrap();
        fs::set_permissions(&tmp, PermissionsExt::from_mode(0o755)).unwrap();
        fs::rename(&tmp, path).unwrap();
    }

    /// Retry until the stub can be exec'd (exit status is ignored).
    fn wait_stub_exec_ready(path: &Path) {
        let mut last_err = None;
        for _ in 0..8 {
            match Command::new(path).arg("--version").status() {
                Ok(_) => return,
                Err(e)
                    if e.kind() == std::io::ErrorKind::ExecutableFileBusy
                        || e.raw_os_error() == Some(26) =>
                {
                    last_err = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(e) => panic!("exec {} --version: {e}", path.display()),
            }
        }
        panic!(
            "exec {} --version still busy after retries: {last_err:?}",
            path.display()
        );
    }

    /// Write a stub and wait until it can be executed.
    fn write_exec(path: &Path, body: &str) {
        write_stub_script(path, body);
        wait_stub_exec_ready(path);
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

    fn write_js_lock_tree(root: &Path, lock_name: &str) {
        fs::create_dir_all(root).unwrap();
        let contents = if lock_name == YARN_LOCK_FILE_NAME {
            "# yarn berry fixture\n__metadata:\n  version: 6\n"
        } else {
            "# lock\n"
        };
        fs::write(root.join(lock_name), contents).unwrap();
        fs::write(root.join("package.json"), "{\"name\":\"app\"}\n").unwrap();
    }

    fn write_yarn_classic_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join(YARN_LOCK_FILE_NAME),
            "# yarn lockfile v1\n\nleft-pad@1.0.0:\n  version \"1.0.0\"\n",
        )
        .unwrap();
        fs::write(root.join("package.json"), "{\"name\":\"app\"}\n").unwrap();
    }

    fn write_poetry_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(POETRY_LOCK_FILE_NAME), "[[package]]\n").unwrap();
        fs::write(
            root.join(PYTHON_MANIFEST_FILE_NAME),
            "[project]\nname=\"app\"\n",
        )
        .unwrap();
    }

    fn write_uv_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(UV_LOCK_FILE_NAME), "version = 1\n").unwrap();
        fs::write(
            root.join(PYTHON_MANIFEST_FILE_NAME),
            "[project]\nname=\"app\"\n",
        )
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
    fn strategy_selects_yarn_pnpm_bun_when_no_npm_lock() {
        let package = pkg(NPM_ECOSYSTEM, "left-pad");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.0.0",
                &[lock_decl(YARN_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Yarn
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.0.0",
                &[lock_decl(PNPM_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Pnpm
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.0.0",
                &[lock_decl(BUN_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Bun
        );
        // npm lock wins over yarn when both are declared.
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.0.0",
                &[
                    lock_decl(YARN_LOCK_FILE_NAME),
                    lock_decl("package-lock.json"),
                ],
            ),
            ApplyStrategy::Npm
        );
    }

    #[test]
    fn strategy_selects_python_for_poetry_uv_pylock_unavailable() {
        let package = pkg(PYPI_ECOSYSTEM, "requests");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.32.0",
                &[lock_decl(POETRY_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Python
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.32.0",
                &[lock_decl(UV_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Python
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.32.0",
                &[lock_decl(PYLOCK_TOML_FILE_NAME)],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &package,
                "2.32.0",
                &[lock_decl("pylock.dev.toml")],
            ),
            ApplyStrategy::Unavailable
        );
    }

    #[test]
    fn strategy_selects_go_rubygems_gradle_maven() {
        use vlz_db::{GO_ECOSYSTEM, MAVEN_ECOSYSTEM, RUBYGEMS_ECOSYSTEM};

        // Go selects on the `go.mod` manifest declaration (Go emits no
        // lockfile-kind declarations); `go.sum` alone never selects.
        let go_pkg = pkg(GO_ECOSYSTEM, "github.com/example/mod");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &go_pkg,
                "1.2.4",
                &[manifest_decl(GO_MANIFEST_FILE_NAME)],
            ),
            ApplyStrategy::Go
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &go_pkg,
                "1.2.4",
                &[lock_decl(GO_MANIFEST_FILE_NAME)],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &go_pkg,
                "1.2.4",
                &[lock_decl(GO_SUM_FILE_NAME)],
            ),
            ApplyStrategy::Unavailable
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &go_pkg,
                MIN_FIXED_VERSION_UNKNOWN,
                &[manifest_decl(GO_MANIFEST_FILE_NAME)],
            ),
            ApplyStrategy::Unavailable
        );

        // RubyGems selects on either pair-matched lock basename.
        let gem_pkg = pkg(RUBYGEMS_ECOSYSTEM, "rails");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &gem_pkg,
                "7.0.8",
                &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::RubyGems
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &gem_pkg,
                "7.0.8",
                &[lock_decl(RUBY_LOCK_GEMS_LOCKED_FILE_NAME)],
            ),
            ApplyStrategy::RubyGems
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &gem_pkg,
                "7.0.8",
                &[manifest_decl(RUBY_MANIFEST_GEMFILE_FILE_NAME)],
            ),
            ApplyStrategy::Unavailable
        );

        // Maven ecosystem prefers a Gradle lock over a bare `pom.xml`.
        let java_pkg = pkg(MAVEN_ECOSYSTEM, "com.example:lib");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &java_pkg,
                "2.0.1",
                &[lock_decl(GRADLE_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Gradle
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &java_pkg,
                "2.0.1",
                &[lock_decl(GRADLE_BUILDSCRIPT_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Gradle
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &java_pkg,
                "2.0.1",
                &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
            ),
            ApplyStrategy::Maven
        );
        // Gradle lock wins when both are declared (mixed tree).
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &java_pkg,
                "2.0.1",
                &[
                    manifest_decl(MAVEN_MANIFEST_FILE_NAME),
                    lock_decl(GRADLE_LOCK_FILE_NAME),
                ],
            ),
            ApplyStrategy::Gradle
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &java_pkg,
                MIN_FIXED_VERSION_UNKNOWN,
                &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
            ),
            ApplyStrategy::Unavailable
        );
    }

    fn write_go_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(GO_MANIFEST_FILE_NAME), "module example\n")
            .unwrap();
        fs::write(root.join(GO_SUM_FILE_NAME), "").unwrap();
    }

    fn write_ruby_tree(root: &Path, manifest: &str, lock: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(lock), "GEM\n").unwrap();
        fs::write(root.join(manifest), "source rubygems\n").unwrap();
    }

    fn write_gradle_tree(root: &Path) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(GRADLE_LOCK_FILE_NAME), "empty=\n").unwrap();
        fs::write(root.join(GRADLE_MANIFEST_BUILD_FILE_NAME), "plugins {}\n")
            .unwrap();
    }

    #[test]
    fn go_get_argv_builder_is_stable() {
        assert_eq!(
            go_get_argv(GO_BIN_NAME, "github.com/example/mod", "v1.2.4"),
            vec![
                GO_BIN_NAME.to_string(),
                "get".to_string(),
                "github.com/example/mod@v1.2.4".to_string(),
            ]
        );
    }

    #[test]
    fn allowlist_helpers_cover_go_modules_and_maven_coordinates() {
        assert!(is_allowlisted_go_module("github.com/example/mod"));
        assert!(is_allowlisted_go_module("golang.org/x/text"));
        assert!(is_allowlisted_go_module("example.com/foo-bar_baz~1"));
        assert!(!is_allowlisted_go_module(""));
        assert!(!is_allowlisted_go_module("-x"));
        assert!(!is_allowlisted_go_module(".x"));
        assert!(!is_allowlisted_go_module("/x"));
        assert!(!is_allowlisted_go_module("a//b"));
        assert!(!is_allowlisted_go_module("a/../b"));
        assert!(!is_allowlisted_go_module("github.com/!BurntSushi/toml"));
        assert!(!is_allowlisted_go_module("a b"));
        assert!(!is_allowlisted_go_module("a;b"));
        assert!(is_allowlisted_maven_coordinate("com.example:lib"));
        assert!(is_allowlisted_maven_coordinate(
            "org.apache.logging.log4j:log4j-core"
        ));
        assert!(!is_allowlisted_maven_coordinate("lib"));
        assert!(!is_allowlisted_maven_coordinate("a:b:c"));
        assert!(!is_allowlisted_maven_coordinate(":b"));
        assert!(!is_allowlisted_maven_coordinate("a:"));
        assert!(!is_allowlisted_maven_coordinate("-a:b"));
        assert!(!is_allowlisted_maven_coordinate("a:b;c"));
    }

    #[test]
    fn go_preview_readds_v_prefix_and_allows_transitive() {
        let dir = test_tempdir();
        let root = dir.path();
        write_go_tree(root);
        let rem = GoRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Go);
        for (target, expected) in [("1.2.4", "v1.2.4"), ("v1.2.4", "v1.2.4")] {
            for kind in [DependencyKind::Direct, DependencyKind::Transitive] {
                let preview = rem
                    .preview(&RemediationContext {
                        scan_root: root,
                        declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                        package_name: "github.com/example/mod",
                        target_version: target,
                        dependency_kind: kind,
                        allow_dependency_code_execution: false,
                        offline: false,
                    })
                    .expect("go preview");
                assert_eq!(preview.strategy, ApplyStrategy::Go);
                assert_eq!(
                    preview.argv,
                    go_get_argv(
                        GO_BIN_NAME,
                        "github.com/example/mod",
                        expected,
                    )
                );
                assert_eq!(
                    preview.files,
                    vec![
                        root.join(GO_MANIFEST_FILE_NAME),
                        root.join(GO_SUM_FILE_NAME),
                    ]
                );
            }
        }
    }

    #[test]
    fn go_apply_rejects_bad_inputs_and_runs_stub() {
        let dir = test_tempdir();
        let root = dir.path();
        write_go_tree(root);
        let ok_bin = root.join("go-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = GoRemediator::with_bin(ok_bin.to_string_lossy());
        assert_eq!(rem.strategy(), ApplyStrategy::Go);

        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                package_name: "github.com/example/mod",
                target_version: MIN_FIXED_VERSION_UNKNOWN,
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::TargetVersionUnknown));

        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                package_name: "-evil",
                target_version: "1.2.4",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::InvalidOperand(_)));

        // Missing sibling go.mod.
        let bare = test_tempdir();
        fs::create_dir_all(bare.path()).unwrap();
        let err = rem
            .preview(&RemediationContext {
                scan_root: bare.path(),
                declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                package_name: "github.com/example/mod",
                target_version: "1.2.4",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                package_name: "github.com/example/mod",
                target_version: "1.2.4",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));

        let missing =
            GoRemediator::with_bin(root.join("no-such-go").to_string_lossy());
        let err = missing
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                package_name: "github.com/example/mod",
                target_version: "1.2.4",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));

        rem.apply(&RemediationContext {
            scan_root: root,
            declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
            package_name: "github.com/example/mod",
            target_version: "1.2.4",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: false,
            offline: false,
        })
        .unwrap();

        let fail_bin = root.join("go-fail");
        write_exec(
            &fail_bin,
            "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then exit 0; fi\necho go-fail >&2\nexit 1\n",
        );
        let err = GoRemediator::with_bin(fail_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(GO_MANIFEST_FILE_NAME)],
                package_name: "github.com/example/mod",
                target_version: "1.2.4",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        match err {
            RemediationError::CommandFailed { strategy, message } => {
                assert_eq!(strategy, GO_BIN_NAME);
                assert!(message.contains("go-fail"));
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    #[test]
    fn bundle_add_argv_builder_is_stable() {
        assert_eq!(
            bundle_add_argv(BUNDLE_BIN_NAME, "rails", "7.0.8"),
            vec![
                BUNDLE_BIN_NAME.to_string(),
                "add".to_string(),
                "rails".to_string(),
                "--version=7.0.8".to_string(),
                BUNDLE_SKIP_INSTALL_FLAG.to_string(),
            ]
        );
    }

    #[test]
    fn rubygems_preview_pairs_locks_and_gates_execution() {
        let dir = test_tempdir();
        let root = dir.path();
        write_ruby_tree(
            root,
            RUBY_MANIFEST_GEMFILE_FILE_NAME,
            RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
        );
        let rem = RubyGemsRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::RubyGems);

        // Fail-closed without the SEC-023 gate (Gemfile Ruby is project code).
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let preview = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .expect("rubygems preview");
        assert_eq!(preview.strategy, ApplyStrategy::RubyGems);
        assert_eq!(
            preview.argv,
            bundle_add_argv(BUNDLE_BIN_NAME, "rails", "7.0.8")
        );
        assert_eq!(
            preview.files,
            vec![
                root.join(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME),
                root.join(RUBY_MANIFEST_GEMFILE_FILE_NAME),
            ]
        );

        // gems.rb / gems.locked pair.
        let dir2 = test_tempdir();
        let root2 = dir2.path();
        write_ruby_tree(
            root2,
            RUBY_MANIFEST_GEMS_RB_FILE_NAME,
            RUBY_LOCK_GEMS_LOCKED_FILE_NAME,
        );
        let preview2 = rem
            .preview(&RemediationContext {
                scan_root: root2,
                declarations: &[lock_decl(RUBY_LOCK_GEMS_LOCKED_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .expect("gems.rb preview");
        assert_eq!(
            preview2.files,
            vec![
                root2.join(RUBY_LOCK_GEMS_LOCKED_FILE_NAME),
                root2.join(RUBY_MANIFEST_GEMS_RB_FILE_NAME),
            ]
        );

        // Transitive apply would promote into the Gemfile: refuse.
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Transitive,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Mismatched pair (gems.locked next to Gemfile) is refused.
        let dir3 = test_tempdir();
        let root3 = dir3.path();
        write_ruby_tree(
            root3,
            RUBY_MANIFEST_GEMFILE_FILE_NAME,
            RUBY_LOCK_GEMS_LOCKED_FILE_NAME,
        );
        let err = rem
            .preview(&RemediationContext {
                scan_root: root3,
                declarations: &[lock_decl(RUBY_LOCK_GEMS_LOCKED_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    #[test]
    fn rubygems_apply_rejects_bad_inputs_and_runs_stub() {
        let dir = test_tempdir();
        let root = dir.path();
        write_ruby_tree(
            root,
            RUBY_MANIFEST_GEMFILE_FILE_NAME,
            RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
        );
        let ok_bin = root.join("bundle-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = RubyGemsRemediator::with_bin(ok_bin.to_string_lossy());

        for (gem, version) in
            [("rails", MIN_FIXED_VERSION_UNKNOWN), ("-evil", "7.0.8")]
        {
            let err = rem
                .preview(&RemediationContext {
                    scan_root: root,
                    declarations: &[lock_decl(
                        RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
                    )],
                    package_name: gem,
                    target_version: version,
                    dependency_kind: DependencyKind::Direct,
                    allow_dependency_code_execution: true,
                    offline: false,
                })
                .unwrap_err();
            assert!(matches!(
                err,
                RemediationError::TargetVersionUnknown
                    | RemediationError::InvalidOperand(_)
            ));
        }

        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));

        let missing = RubyGemsRemediator::with_bin(
            root.join("no-such-bundle").to_string_lossy(),
        );
        let err = missing
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));

        // Gated apply without the gate fails closed.
        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        rem.apply(&RemediationContext {
            scan_root: root,
            declarations: &[lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME)],
            package_name: "rails",
            target_version: "7.0.8",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: true,
            offline: false,
        })
        .unwrap();
    }

    #[test]
    fn gradle_update_argv_builder_is_stable() {
        assert_eq!(
            gradle_update_argv(GRADLE_BIN_NAME, "com.example:lib"),
            vec![
                GRADLE_BIN_NAME.to_string(),
                "dependencies".to_string(),
                "--write-locks".to_string(),
                "--update-locks".to_string(),
                "com.example:lib".to_string(),
            ]
        );
    }

    #[test]
    fn gradle_preview_regenerates_lock_and_gates_execution() {
        let dir = test_tempdir();
        let root = dir.path();
        write_gradle_tree(root);
        let rem = GradleRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Gradle);

        // Fail-closed without the SEC-023 gate (Gradle runs build scripts).
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        for kind in [DependencyKind::Direct, DependencyKind::Transitive] {
            let preview = rem
                .preview(&RemediationContext {
                    scan_root: root,
                    declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                    package_name: "com.example:lib",
                    target_version: "2.0.1",
                    dependency_kind: kind,
                    allow_dependency_code_execution: true,
                    offline: false,
                })
                .expect("gradle preview");
            assert_eq!(preview.strategy, ApplyStrategy::Gradle);
            assert_eq!(
                preview.argv,
                gradle_update_argv(GRADLE_BIN_NAME, "com.example:lib")
            );
            assert_eq!(preview.files, vec![root.join(GRADLE_LOCK_FILE_NAME)]);
        }

        // Lock without any sibling build manifest is refused.
        let bare = test_tempdir();
        fs::create_dir_all(bare.path()).unwrap();
        fs::write(bare.path().join(GRADLE_LOCK_FILE_NAME), "empty=\n")
            .unwrap();
        let err = rem
            .preview(&RemediationContext {
                scan_root: bare.path(),
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Non-coordinate package names are refused.
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "not-a-coordinate",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::InvalidOperand(_)));
    }

    #[test]
    fn gradle_apply_rejects_bad_inputs_and_runs_stub() {
        let dir = test_tempdir();
        let root = dir.path();
        write_gradle_tree(root);
        fs::write(
            root.join(GRADLE_LOCK_FILE_NAME),
            "com.example:lib:2.0.0=runtimeClasspath\n",
        )
        .unwrap();
        // Stub simulates lock regeneration by advancing the entry.
        let ok_bin = root.join("gradle-ok");
        write_exec(
            &ok_bin,
            "#!/usr/bin/env python3\nimport sys\nfrom pathlib import Path\nif len(sys.argv) > 1 and sys.argv[1] == '--version':\n    print('Gradle 8.0')\n    raise SystemExit(0)\nlock = Path('gradle.lockfile')\nlock.write_text(lock.read_text().replace('com.example:lib:2.0.0=', 'com.example:lib:2.0.1='), encoding='utf-8')\n",
        );
        let rem = GradleRemediator::with_bin(ok_bin.to_string_lossy());

        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: MIN_FIXED_VERSION_UNKNOWN,
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::TargetVersionUnknown));

        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));

        let missing = GradleRemediator::with_bin(
            root.join("no-such-gradle").to_string_lossy(),
        );
        let err = missing
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));

        rem.apply(&RemediationContext {
            scan_root: root,
            declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
            package_name: "com.example:lib",
            target_version: "2.0.1",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: true,
            offline: false,
        })
        .unwrap();
    }

    #[test]
    fn gradle_lock_versions_for_parses_gav_lines() {
        let text = "# lockfile\nempty=\ncom.example:lib:2.0.0=runtimeClasspath\ncom.example:lib:2.0.0=testRuntimeClasspath\ncom.other:thing:1.0=compileClasspath\nnot-a-gav-line\n";
        assert_eq!(
            gradle_lock_versions_for(text, "com.example:lib"),
            vec!["2.0.0".to_string(), "2.0.0".to_string()]
        );
        assert_eq!(
            gradle_lock_versions_for(text, "com.other:thing"),
            vec!["1.0".to_string()]
        );
        assert!(gradle_lock_versions_for(text, "com.missing:lib").is_empty());
        assert!(gradle_lock_versions_for("", "com.example:lib").is_empty());
    }

    #[test]
    fn gradle_lock_satisfies_target_compares_semver() {
        let at_target = "com.example:lib:2.0.1=runtimeClasspath\n";
        let newer = "com.example:lib:2.2.0=runtimeClasspath\n";
        let older = "com.example:lib:2.0.0=runtimeClasspath\n";
        assert!(gradle_lock_satisfies_target(
            at_target,
            "com.example:lib",
            "2.0.1"
        ));
        assert!(gradle_lock_satisfies_target(
            newer,
            "com.example:lib",
            "2.0.1"
        ));
        assert!(!gradle_lock_satisfies_target(
            older,
            "com.example:lib",
            "2.0.1"
        ));
        assert!(!gradle_lock_satisfies_target(
            "",
            "com.example:lib",
            "2.0.1"
        ));
        // Unparseable locked versions never satisfy a semver target.
        assert!(!gradle_lock_satisfies_target(
            "com.example:lib:1.0-SNAPSHOT=runtimeClasspath\n",
            "com.example:lib",
            "2.0.1"
        ));
    }

    #[test]
    fn gradle_apply_errors_when_lock_does_not_advance() {
        let dir = test_tempdir();
        let root = dir.path();
        write_gradle_tree(root);
        fs::write(
            root.join(GRADLE_LOCK_FILE_NAME),
            "com.example:lib:2.0.0=runtimeClasspath\n",
        )
        .unwrap();
        // Stub reports success but leaves the lock untouched.
        let noop_bin = root.join("gradle-noop");
        write_exec(&noop_bin, "#!/bin/sh\nexit 0\n");
        let err = GradleRemediator::with_bin(noop_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(GRADLE_LOCK_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        match err {
            RemediationError::CommandFailed { strategy, message } => {
                assert_eq!(strategy, GRADLE_BIN_NAME);
                assert!(
                    message.contains("did not advance"),
                    "stale lock must be loud, got: {message}"
                );
            }
            other => panic!("expected CommandFailed, got {other:?}"),
        }
    }

    fn write_pom(root: &Path, body: &str) {
        fs::create_dir_all(root).unwrap();
        fs::write(root.join(MAVEN_MANIFEST_FILE_NAME), body).unwrap();
    }

    const SINGLE_DEP_POM: &str = "<project>\n  <modelVersion>4.0.0</modelVersion>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n      <version>1.0</version>\n    </dependency>\n  </dependencies>\n</project>\n";

    const PROPERTY_DEP_POM: &str = "<project>\n  <properties>\n    <lib.version>1.0</lib.version>\n  </properties>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n      <version>${lib.version}</version>\n    </dependency>\n  </dependencies>\n</project>\n";

    #[test]
    fn maven_preview_is_no_exec_with_empty_argv() {
        let dir = test_tempdir();
        let root = dir.path();
        write_pom(root, SINGLE_DEP_POM);
        let rem = MavenRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Maven);
        let preview = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("maven preview");
        assert_eq!(preview.strategy, ApplyStrategy::Maven);
        assert!(preview.argv.is_empty());
        assert_eq!(preview.files, vec![root.join(MAVEN_MANIFEST_FILE_NAME)]);
        assert_eq!(preview.workdir, root.to_path_buf());
    }

    #[test]
    fn maven_apply_bumps_direct_and_property_versions() {
        let dir = test_tempdir();
        let root = dir.path();
        write_pom(root, SINGLE_DEP_POM);
        let rem = MavenRemediator::new();
        // Offline file edits are allowed (no package-manager network access).
        rem.apply(&RemediationContext {
            scan_root: root,
            declarations: &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
            package_name: "com.example:lib",
            target_version: "2.0.1",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: false,
            offline: true,
        })
        .unwrap();
        let updated =
            fs::read_to_string(root.join(MAVEN_MANIFEST_FILE_NAME)).unwrap();
        assert!(updated.contains("<version>2.0.1</version>"));
        assert!(!updated.contains("<version>1.0</version>"));

        let dir2 = test_tempdir();
        let root2 = dir2.path();
        write_pom(root2, PROPERTY_DEP_POM);
        rem.apply(&RemediationContext {
            scan_root: root2,
            declarations: &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
            package_name: "com.example:lib",
            target_version: "2.0.1",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: false,
            offline: false,
        })
        .unwrap();
        let updated2 =
            fs::read_to_string(root2.join(MAVEN_MANIFEST_FILE_NAME)).unwrap();
        assert!(updated2.contains("<lib.version>2.0.1</lib.version>"));
        assert!(updated2.contains("<version>${lib.version}</version>"));
    }

    #[test]
    fn maven_apply_refuses_ambiguous_and_unsafe_layouts() {
        let rem = MavenRemediator::new();
        let decls = [manifest_decl(MAVEN_MANIFEST_FILE_NAME)];
        fn ctx_for<'a>(
            root: &'a Path,
            decls: &'a [PackageDeclarationLocation],
        ) -> RemediationContext<'a> {
            RemediationContext {
                scan_root: root,
                declarations: decls,
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            }
        }

        // No matching dependency.
        let dir = test_tempdir();
        write_pom(dir.path(), "<project>\n</project>\n");
        let err = rem.apply(&ctx_for(dir.path(), &decls)).unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Two matching dependencies.
        let dir = test_tempdir();
        write_pom(
            dir.path(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n      <version>1.0</version>\n    </dependency>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n      <version>1.0</version>\n    </dependency>\n  </dependencies>\n</project>\n",
        );
        let err = rem.apply(&ctx_for(dir.path(), &decls)).unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Range version in pom is refused.
        let dir = test_tempdir();
        write_pom(
            dir.path(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n      <version>[1.0,2.0)</version>\n    </dependency>\n  </dependencies>\n</project>\n",
        );
        let err = rem.apply(&ctx_for(dir.path(), &decls)).unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Missing version (inherited) is refused.
        let dir = test_tempdir();
        write_pom(
            dir.path(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n    </dependency>\n  </dependencies>\n</project>\n",
        );
        let err = rem.apply(&ctx_for(dir.path(), &decls)).unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Property referenced but not defined in the same file.
        let dir = test_tempdir();
        write_pom(
            dir.path(),
            "<project>\n  <dependencies>\n    <dependency>\n      <groupId>com.example</groupId>\n      <artifactId>lib</artifactId>\n      <version>${lib.version}</version>\n    </dependency>\n  </dependencies>\n</project>\n",
        );
        let err = rem.apply(&ctx_for(dir.path(), &decls)).unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Dependency inside profiles is refused.
        let dir = test_tempdir();
        write_pom(
            dir.path(),
            "<project>\n  <profiles>\n    <profile>\n      <dependencies>\n        <dependency>\n          <groupId>com.example</groupId>\n          <artifactId>lib</artifactId>\n          <version>1.0</version>\n        </dependency>\n      </dependencies>\n    </profile>\n  </profiles>\n</project>\n",
        );
        let err = rem.apply(&ctx_for(dir.path(), &decls)).unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Unknown target version and invalid coordinates are refused.
        let dir = test_tempdir();
        write_pom(dir.path(), SINGLE_DEP_POM);
        let err = rem
            .preview(&RemediationContext {
                scan_root: dir.path(),
                declarations: &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: MIN_FIXED_VERSION_UNKNOWN,
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::TargetVersionUnknown));
        let err = rem
            .preview(&RemediationContext {
                scan_root: dir.path(),
                declarations: &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
                package_name: "not-a-coordinate",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::InvalidOperand(_)));
    }

    #[test]
    fn maven_apply_rejects_outside_root_and_missing_pom() {
        let root_dir = test_tempdir();
        let outside_dir = test_tempdir();
        let root = root_dir.path();
        let outside = outside_dir.path();
        write_pom(root, SINGLE_DEP_POM);
        write_pom(outside, SINGLE_DEP_POM);
        let rem = MavenRemediator::new();

        let abs = outside
            .join(MAVEN_MANIFEST_FILE_NAME)
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[manifest_decl(&abs)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let bare = test_tempdir();
        fs::create_dir_all(bare.path()).unwrap();
        let err = rem
            .preview(&RemediationContext {
                scan_root: bare.path(),
                declarations: &[manifest_decl(MAVEN_MANIFEST_FILE_NAME)],
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    #[test]
    fn default_constructors_use_standard_bin_names_for_new_strategies() {
        assert_eq!(GoRemediator::new().bin, GO_BIN_NAME);
        assert_eq!(GoRemediator::default().bin, GO_BIN_NAME);
        assert_eq!(RubyGemsRemediator::new().bin, BUNDLE_BIN_NAME);
        assert_eq!(GradleRemediator::new().bin, GRADLE_BIN_NAME);
        assert_eq!(GradleRemediator::default().bin, GRADLE_BIN_NAME);
        assert_eq!(MavenRemediator::new().strategy(), ApplyStrategy::Maven);
    }

    fn preview_err_contains(err: RemediationError, needle: &str) -> bool {
        err.to_string().contains(needle)
    }

    #[test]
    fn go_preview_refuses_multiple_go_mod_dirs() {
        let dir = test_tempdir();
        let root = dir.path();
        write_go_tree(root);
        let sub = root.join("sub");
        write_go_tree(&sub);
        let rem = GoRemediator::new();
        let decls = [
            manifest_decl(GO_MANIFEST_FILE_NAME),
            manifest_decl("sub/go.mod"),
        ];
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &decls,
                package_name: "github.com/example/mod",
                target_version: "1.2.4",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(
            preview_err_contains(err, "multiple"),
            "multi-module go trees must be refused, not first-only fixed"
        );
    }

    #[test]
    fn rubygems_preview_refuses_multiple_lock_dirs() {
        let dir = test_tempdir();
        let root = dir.path();
        write_ruby_tree(
            root,
            RUBY_MANIFEST_GEMFILE_FILE_NAME,
            RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
        );
        let sub = root.join("sub");
        write_ruby_tree(
            &sub,
            RUBY_MANIFEST_GEMFILE_FILE_NAME,
            RUBY_LOCK_GEMFILE_LOCK_FILE_NAME,
        );
        let rem = RubyGemsRemediator::new();
        let decls = [
            lock_decl(RUBY_LOCK_GEMFILE_LOCK_FILE_NAME),
            lock_decl("sub/Gemfile.lock"),
        ];
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &decls,
                package_name: "rails",
                target_version: "7.0.8",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(
            preview_err_contains(err, "multiple"),
            "multi-tree RubyGems findings must be refused"
        );
    }

    #[test]
    fn gradle_preview_refuses_multiple_lock_dirs() {
        let dir = test_tempdir();
        let root = dir.path();
        write_gradle_tree(root);
        let sub = root.join("sub");
        write_gradle_tree(&sub);
        let rem = GradleRemediator::new();
        let decls = [
            lock_decl(GRADLE_LOCK_FILE_NAME),
            lock_decl("sub/gradle.lockfile"),
        ];
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &decls,
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .unwrap_err();
        assert!(
            preview_err_contains(err, "multiple"),
            "multi-module Gradle findings must be refused"
        );
    }

    #[test]
    fn maven_preview_refuses_multiple_pom_dirs() {
        let dir = test_tempdir();
        let root = dir.path();
        write_pom(root, SINGLE_DEP_POM);
        let sub = root.join("sub");
        write_pom(&sub, SINGLE_DEP_POM);
        let rem = MavenRemediator::new();
        let decls = [
            manifest_decl(MAVEN_MANIFEST_FILE_NAME),
            manifest_decl("sub/pom.xml"),
        ];
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &decls,
                package_name: "com.example:lib",
                target_version: "2.0.1",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(
            preview_err_contains(err, "multiple"),
            "multi-module Maven findings must be refused, not first-only edited"
        );
    }

    #[test]
    fn strategy_unavailable_without_supported_lock_or_unknown_fixed() {
        let npm = pkg(NPM_ECOSYSTEM, "left-pad");
        let cargo = pkg(CRATES_IO_ECOSYSTEM, "serde");
        let other = pkg("Maven", "guava");
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
        let pypi = pkg(PYPI_ECOSYSTEM, "requests");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &pypi,
                "2.0.0",
                &[lock_decl("Pipfile.lock")],
            ),
            ApplyStrategy::Unavailable
        );
    }

    #[test]
    fn npm_apply_rejects_unknown_offline_missing_bin_and_lock() {
        let dir = test_tempdir();
        let root = dir.path();
        fs::create_dir_all(root).unwrap();
        let decls = [lock_decl("package-lock.json")];
        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = NpmRemediator::with_bin(ok_bin.to_string_lossy());

        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
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
                scan_root: root,
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
                scan_root: root,
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
                scan_root: root,
                declarations: &decls,
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));
    }

    #[test]
    fn cargo_apply_rejects_unknown_offline_missing_bin_and_lock() {
        let dir = test_tempdir();
        let root = dir.path();
        fs::create_dir_all(root).unwrap();
        let decls = [lock_decl("Cargo.lock")];
        let ok_bin = root.join("cargo-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let rem = CargoRemediator::with_bin(ok_bin.to_string_lossy());

        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
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
                scan_root: root,
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
                scan_root: root,
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
                scan_root: root,
                declarations: &decls,
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::MissingPackageManager(_)));
    }

    #[test]
    fn npm_apply_stub_bin_success_and_command_failed() {
        let dir = test_tempdir();
        let root = dir.path();
        write_npm_tree(root);
        let decls = [lock_decl("package-lock.json")];

        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        NpmRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
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
                scan_root: root,
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
    }

    #[test]
    fn cargo_apply_stub_bin_success_and_command_failed() {
        let dir = test_tempdir();
        let root = dir.path();
        write_cargo_tree(root);
        let decls = [lock_decl("Cargo.lock")];

        let ok_bin = root.join("cargo-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        CargoRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
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
                scan_root: root,
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
    }

    #[test]
    fn npm_apply_rejects_lock_path_outside_scan_root() {
        let root_dir = test_tempdir();
        let outside_dir = test_tempdir();
        let root = root_dir.path();
        let outside = outside_dir.path();
        write_npm_tree(root);
        write_npm_tree(outside);
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
                scan_root: root,
                declarations: &[lock_decl(&abs)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        // Relative escape: require siblings under the same parent, then join.
        assert_eq!(
            root.parent(),
            outside.parent(),
            "test tempdirs must share a parent for relative escape"
        );
        let rel = PathBuf::from("..")
            .join(outside.file_name().expect("outside tempdir name"))
            .join("package-lock.json");
        let rel = rel.to_string_lossy();
        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(&rel)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    #[test]
    fn npm_apply_rejects_missing_sibling_manifest() {
        let dir = test_tempdir();
        let root = dir.path();
        fs::create_dir_all(root).unwrap();
        fs::write(root.join("package-lock.json"), "{}\n").unwrap();
        let ok_bin = root.join("npm-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let err = NpmRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl("package-lock.json")],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    #[test]
    fn npm_and_cargo_apply_reject_invalid_operands() {
        let dir = test_tempdir();
        let root = dir.path();
        write_npm_tree(root);
        let cargo_root = root.join("cargo-tree");
        write_cargo_tree(&cargo_root);
        let npm_bin = root.join("npm-ok");
        let cargo_bin = root.join("cargo-ok");
        write_exec(&npm_bin, "#!/bin/sh\nexit 0\n");
        write_exec(&cargo_bin, "#!/bin/sh\nexit 0\n");

        let err = NpmRemediator::with_bin(npm_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
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
        assert_eq!(YarnRemediator::new().bin, YARN_BIN_NAME);
        assert_eq!(PnpmRemediator::new().bin, PNPM_BIN_NAME);
        assert_eq!(BunRemediator::new().bin, BUN_BIN_NAME);
        assert_eq!(PythonRemediator::new().poetry_bin, POETRY_BIN_NAME);
        assert_eq!(PythonRemediator::new().uv_bin, UV_BIN_NAME);
    }

    #[test]
    fn strategy_selects_python_yarn_pnpm_bun_locks() {
        let py = pkg(PYPI_ECOSYSTEM, "requests");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &py,
                "2.32.0",
                &[lock_decl(POETRY_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Python
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &py,
                "2.32.0",
                &[lock_decl(UV_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Python
        );
        let npm = pkg(NPM_ECOSYSTEM, "left-pad");
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &npm,
                "2.0.0",
                &[lock_decl(PNPM_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Pnpm
        );
        assert_eq!(
            remediation_apply_strategy_for_finding(
                &npm,
                "2.0.0",
                &[lock_decl(BUN_LOCK_FILE_NAME)],
            ),
            ApplyStrategy::Bun
        );
    }

    #[test]
    fn appendix_b_preview_apply_and_offline_guards() {
        let dir = test_tempdir();
        let root = dir.path();
        write_poetry_tree(root);
        let poetry = root.join("poetry-ok");
        write_exec(&poetry, "#!/bin/sh\nexit 0\n");
        let rem = PythonRemediator::with_poetry_bin(poetry.to_string_lossy());
        let preview = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(POETRY_LOCK_FILE_NAME)],
                package_name: "requests",
                target_version: "2.32.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("poetry preview");
        assert_eq!(
            preview.argv,
            poetry_add_argv(poetry.to_str().unwrap(), "requests", "2.32.0",)
        );

        let yarn_dir = test_tempdir();
        let yarn_root = yarn_dir.path();
        write_js_lock_tree(yarn_root, YARN_LOCK_FILE_NAME);
        let yarn = yarn_root.join("yarn-ok");
        write_exec(&yarn, "#!/bin/sh\nexit 0\n");
        let yarn_rem = YarnRemediator::with_bin(yarn.to_string_lossy());
        let yarn_preview = yarn_rem
            .preview(&RemediationContext {
                scan_root: yarn_root,
                declarations: &[lock_decl(YARN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "1.3.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("yarn preview");
        assert_eq!(
            yarn_preview.argv,
            yarn_up_argv(yarn.to_str().unwrap(), "left-pad", "1.3.0", false)
        );
        assert!(
            yarn_preview
                .argv
                .iter()
                .any(|a| a == YARN_BERRY_SKIP_BUILD_FLAG),
            "SEC-023: Yarn Berry must skip builds when gate is off"
        );

        let uv_dir = test_tempdir();
        let uv_root = uv_dir.path();
        write_uv_tree(uv_root);
        let uv = uv_root.join("uv-ok");
        write_exec(&uv, "#!/bin/sh\nexit 0\n");
        let uv_rem = PythonRemediator::with_uv_bin(uv.to_string_lossy());
        let uv_preview = uv_rem
            .preview(&RemediationContext {
                scan_root: uv_root,
                declarations: &[lock_decl(UV_LOCK_FILE_NAME)],
                package_name: "requests",
                target_version: "2.32.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("uv preview");
        assert_eq!(
            uv_preview.argv,
            uv_add_argv(uv.to_str().unwrap(), "requests", "2.32.0")
        );
        uv_rem
            .apply(&RemediationContext {
                scan_root: uv_root,
                declarations: &[lock_decl(UV_LOCK_FILE_NAME)],
                package_name: "requests",
                target_version: "2.32.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap();

        rem.apply(&RemediationContext {
            scan_root: root,
            declarations: &[lock_decl(POETRY_LOCK_FILE_NAME)],
            package_name: "requests",
            target_version: "2.32.0",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: false,
            offline: false,
        })
        .unwrap();
        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(POETRY_LOCK_FILE_NAME)],
                package_name: "requests",
                target_version: "2.32.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));

        yarn_rem
            .apply(&RemediationContext {
                scan_root: yarn_root,
                declarations: &[lock_decl(YARN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "1.3.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap();

        let pnpm_dir = test_tempdir();
        let pnpm_root = pnpm_dir.path();
        write_js_lock_tree(pnpm_root, PNPM_LOCK_FILE_NAME);
        let pnpm_bin = pnpm_root.join("pnpm-ok");
        write_exec(&pnpm_bin, "#!/bin/sh\nexit 0\n");
        let pnpm = PnpmRemediator::with_bin(pnpm_bin.to_string_lossy());
        let pnpm_preview = pnpm
            .preview(&RemediationContext {
                scan_root: pnpm_root,
                declarations: &[lock_decl(PNPM_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("pnpm preview");
        assert_eq!(
            pnpm_preview.argv,
            pnpm_update_argv(pnpm_bin.to_str().unwrap(), "left-pad", "2.0.0")
        );
        let err = pnpm
            .preview(&RemediationContext {
                scan_root: pnpm_root,
                declarations: &[lock_decl(PNPM_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Transitive,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
        pnpm.apply(&RemediationContext {
            scan_root: pnpm_root,
            declarations: &[lock_decl(PNPM_LOCK_FILE_NAME)],
            package_name: "left-pad",
            target_version: "2.0.0",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: false,
            offline: false,
        })
        .unwrap();

        let bun_dir = test_tempdir();
        let bun_root = bun_dir.path();
        write_js_lock_tree(bun_root, BUN_LOCK_FILE_NAME);
        let bun_bin = bun_root.join("bun-ok");
        write_exec(&bun_bin, "#!/bin/sh\nexit 0\n");
        let bun = BunRemediator::with_bin(bun_bin.to_string_lossy());
        let bun_preview = bun
            .preview(&RemediationContext {
                scan_root: bun_root,
                declarations: &[lock_decl(BUN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("bun preview");
        assert_eq!(
            bun_preview.argv,
            bun_update_argv(
                bun_bin.to_str().unwrap(),
                "left-pad",
                "2.0.0",
                false
            )
        );
        assert!(
            bun_preview
                .argv
                .iter()
                .any(|a| a == BUN_IGNORE_SCRIPTS_FLAG),
            "SEC-023: bun must ignore scripts when gate is off"
        );
        bun.apply(&RemediationContext {
            scan_root: bun_root,
            declarations: &[lock_decl(BUN_LOCK_FILE_NAME)],
            package_name: "left-pad",
            target_version: "2.0.0",
            dependency_kind: DependencyKind::Direct,
            allow_dependency_code_execution: false,
            offline: false,
        })
        .unwrap();
        let err = bun
            .preview(&RemediationContext {
                scan_root: bun_root,
                declarations: &[lock_decl(BUN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Transitive,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
        let err = bun
            .apply(&RemediationContext {
                scan_root: bun_root,
                declarations: &[lock_decl(BUN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: true,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::OfflineBlocked));
    }

    #[test]
    fn yarn_classic_uses_upgrade_and_ignore_scripts() {
        let dir = test_tempdir();
        let root = dir.path();
        write_yarn_classic_tree(root);
        let yarn = root.join("yarn-classic");
        write_exec(&yarn, "#!/bin/sh\nexit 0\n");
        let rem = YarnRemediator::with_bin(yarn.to_string_lossy());
        let preview = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(YARN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "1.3.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .expect("classic yarn preview");
        assert_eq!(
            preview.argv,
            yarn_remediate_argv(
                yarn.to_str().unwrap(),
                "left-pad",
                "1.3.0",
                YarnLockFlavor::Classic,
                false,
            )
        );
        assert!(preview.argv.contains(&"upgrade".to_string()));
        assert!(
            preview
                .argv
                .iter()
                .any(|a| a == YARN_CLASSIC_IGNORE_SCRIPTS_FLAG)
        );
    }

    #[test]
    fn yarn_bun_scripts_gate_and_path_confinement() {
        let root_dir = test_tempdir();
        let outside_dir = test_tempdir();
        let root = root_dir.path();
        let outside = outside_dir.path();
        write_js_lock_tree(root, YARN_LOCK_FILE_NAME);
        write_js_lock_tree(outside, YARN_LOCK_FILE_NAME);
        let yarn = root.join("yarn-ok");
        write_exec(&yarn, "#!/bin/sh\nexit 0\n");
        let rem = YarnRemediator::with_bin(yarn.to_string_lossy());
        let with_scripts = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(YARN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "1.3.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .expect("yarn preview with scripts");
        assert!(
            !with_scripts
                .argv
                .iter()
                .any(|a| a == YARN_BERRY_SKIP_BUILD_FLAG)
        );

        let abs = outside
            .join(YARN_LOCK_FILE_NAME)
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let err = rem
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(&abs)],
                package_name: "left-pad",
                target_version: "1.3.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));

        let bun_root_dir = test_tempdir();
        let bun_outside_dir = test_tempdir();
        let bun_root = bun_root_dir.path();
        let bun_outside = bun_outside_dir.path();
        write_js_lock_tree(bun_root, BUN_LOCK_FILE_NAME);
        write_js_lock_tree(bun_outside, BUN_LOCK_FILE_NAME);
        let bun_bin = bun_root.join("bun-ok");
        write_exec(&bun_bin, "#!/bin/sh\nexit 0\n");
        let bun = BunRemediator::with_bin(bun_bin.to_string_lossy());
        let bun_scripts = bun
            .preview(&RemediationContext {
                scan_root: bun_root,
                declarations: &[lock_decl(BUN_LOCK_FILE_NAME)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: true,
                offline: false,
            })
            .expect("bun with scripts");
        assert!(
            !bun_scripts
                .argv
                .iter()
                .any(|a| a == BUN_IGNORE_SCRIPTS_FLAG)
        );
        let abs = bun_outside
            .join(BUN_LOCK_FILE_NAME)
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let err = bun
            .apply(&RemediationContext {
                scan_root: bun_root,
                declarations: &[lock_decl(&abs)],
                package_name: "left-pad",
                target_version: "2.0.0",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    #[test]
    fn poetry_refuses_transitive_apply() {
        let dir = test_tempdir();
        let root = dir.path();
        write_poetry_tree(root);
        let poetry = root.join("poetry-ok");
        write_exec(&poetry, "#!/bin/sh\nexit 0\n");
        let rem = PythonRemediator::with_poetry_bin(poetry.to_string_lossy());
        let err = rem
            .preview(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(POETRY_LOCK_FILE_NAME)],
                package_name: "requests",
                target_version: "2.32.0",
                dependency_kind: DependencyKind::Transitive,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    #[test]
    fn npm_preview_matches_allowlisted_argv_and_ignore_scripts_gate() {
        let dir = test_tempdir();
        let root = dir.path();
        write_npm_tree(root);
        let decls = [lock_decl("package-lock.json")];
        let rem = NpmRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Npm);

        let preview = rem
            .preview(&RemediationContext {
                scan_root: root,
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
                scan_root: root,
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
    }

    #[test]
    fn cargo_preview_matches_allowlisted_argv() {
        let dir = test_tempdir();
        let root = dir.path();
        write_cargo_tree(root);
        let decls = [lock_decl("Cargo.lock")];
        let rem = CargoRemediator::new();
        assert_eq!(rem.strategy(), ApplyStrategy::Cargo);
        let preview = rem
            .preview(&RemediationContext {
                scan_root: root,
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

    /// Relative scan_root + declaration that already includes that prefix
    /// (the form discovery emits when the CLI root is relative) must not
    /// resolve via a double join. Callers must pass scan-root-relative or
    /// absolute declaration paths (SEC-025).
    #[test]
    fn cargo_preview_rejects_double_joined_relative_declaration() {
        let parent = test_tempdir();
        let proj_name = "proj";
        let proj = parent.path().join(proj_name);
        write_cargo_tree(&proj);

        let orig = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(parent.path()).expect("chdir parent");
        let result = std::panic::catch_unwind(|| {
            let rem = CargoRemediator::new();
            rem.preview(&RemediationContext {
                scan_root: Path::new(proj_name),
                declarations: &[lock_decl(&format!(
                    "{proj_name}/{CARGO_LOCK_FILE_NAME}"
                ))],
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
        });
        let _ = std::env::set_current_dir(&orig);
        let err = result
            .expect("preview must not panic")
            .expect_err("double-joined relative decl must fail");
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }

    /// Scan-root-relative lock basename (canonical remediator contract) works
    /// even when scan_root itself is a relative path under CWD.
    #[test]
    fn cargo_preview_accepts_scan_root_relative_decl_with_relative_root() {
        let parent = test_tempdir();
        let proj_name = "proj";
        let proj = parent.path().join(proj_name);
        write_cargo_tree(&proj);

        let orig = std::env::current_dir().expect("cwd");
        std::env::set_current_dir(parent.path()).expect("chdir parent");
        let result = std::panic::catch_unwind(|| {
            let rem = CargoRemediator::new();
            rem.preview(&RemediationContext {
                scan_root: Path::new(proj_name),
                declarations: &[lock_decl(CARGO_LOCK_FILE_NAME)],
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
        });
        let _ = std::env::set_current_dir(&orig);
        let preview = result
            .expect("preview must not panic")
            .expect("scan-root-relative decl must succeed");
        assert_eq!(preview.strategy, ApplyStrategy::Cargo);
        assert!(preview.workdir.ends_with(proj_name));
    }

    #[test]
    fn cargo_apply_rejects_symlink_lock_outside_scan_root() {
        let root_dir = test_tempdir();
        let outside_dir = test_tempdir();
        let root = root_dir.path();
        let outside = outside_dir.path();
        write_cargo_tree(outside);
        fs::create_dir_all(root).unwrap();
        std::os::unix::fs::symlink(
            outside.join(CARGO_LOCK_FILE_NAME),
            root.join(CARGO_LOCK_FILE_NAME),
        )
        .expect("symlink Cargo.lock out of root");
        // Sibling manifest inside root so failure is confinement, not missing
        // manifest.
        fs::write(
            root.join(CARGO_MANIFEST_FILE_NAME),
            "[package]\nname=\"app\"\n",
        )
        .unwrap();
        let ok_bin = root.join("cargo-ok");
        write_exec(&ok_bin, "#!/bin/sh\nexit 0\n");
        let err = CargoRemediator::with_bin(ok_bin.to_string_lossy())
            .apply(&RemediationContext {
                scan_root: root,
                declarations: &[lock_decl(CARGO_LOCK_FILE_NAME)],
                package_name: "serde",
                target_version: "1.0.200",
                dependency_kind: DependencyKind::Direct,
                allow_dependency_code_execution: false,
                offline: false,
            })
            .unwrap_err();
        assert!(matches!(err, RemediationError::UnsupportedLockLayout(_)));
    }
}
