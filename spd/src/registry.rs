// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::{Mutex, OnceLock};

use spd_cve_client::{CveProvider, OsvProvider};
use spd_db::DatabaseBackend;
use spd_integrity::{BackendDelegatingChecker, IntegrityChecker};
use spd_manifest_finder::ManifestFinder;
use spd_manifest_parser::{Parser, Resolver};
use spd_plugin_macro::spd_register;
use spd_report::{DefaultReporter, Reporter};

/// All possible plug‑in kinds.  The enum makes it easy to route a boxed
/// implementation to the correct registry without needing `Any` tricks.
#[allow(dead_code)]
pub enum Plugin {
    ManifestFinder(Box<dyn ManifestFinder>),
    Parser(Box<dyn Parser>),
    Resolver(Box<dyn Resolver>),
    CveProvider(Box<dyn CveProvider>),
    DatabaseBackend(Box<dyn DatabaseBackend>),
    Reporter(Box<dyn Reporter>),
    IntegrityChecker(Box<dyn IntegrityChecker>),
}

/// Register a plug‑in.  Typical usage (inside a plug‑in crate) is:
///
/// ```ignore
/// spd_register!(ManifestFinder, MyFinder);   // expands to registry::register(Plugin::ManifestFinder(...))
/// ```
///
/// The macro itself lives in the optional `spd-plugin-macro` crate; the
/// binary only needs the `register` function.
pub fn register(plugin: Plugin) {
    match plugin {
        Plugin::ManifestFinder(f) => {
            finders().lock().unwrap().push(f);
        }
        Plugin::Parser(p) => {
            parsers().lock().unwrap().push(p);
        }
        Plugin::Resolver(r) => {
            resolvers().lock().unwrap().push(r);
        }
        Plugin::CveProvider(cp) => {
            providers().lock().unwrap().push(cp);
        }
        Plugin::DatabaseBackend(db) => {
            db_backends().lock().unwrap().push(db);
        }
        Plugin::Reporter(r) => {
            reporters().lock().unwrap().push(r);
        }
        Plugin::IntegrityChecker(ic) => {
            integrity_checkers().lock().unwrap().push(ic);
        }
    }
}

/// Ensures at least one database backend is registered (e.g. RedB when built with `redb` feature).
/// Call this at startup so the default backend is used when no plugin has registered one.
#[cfg(feature = "redb")]
#[allow(dead_code)]
pub fn ensure_default_db_backend() {
    let mut backends = db_backends().lock().unwrap();
    if backends.is_empty() {
        backends.push(Box::new(spd_db_redb::RedbBackend::default()));
    }
}

/// Registers the default RedB backend with an explicit path and TTL (OP-002, OP-003, OP-004).
#[cfg(feature = "redb")]
pub fn ensure_default_db_backend_with_path(
    path: std::path::PathBuf,
    ttl_secs: u64,
) -> Result<(), spd_db::DatabaseError> {
    let mut backends = db_backends().lock().unwrap();
    if backends.is_empty() {
        let backend = spd_db_redb::RedbBackend::with_path(path, ttl_secs)?;
        backends.push(Box::new(backend));
    }
    Ok(())
}

/// Ensures at least one manifest finder is registered (Python finder when `python` feature).
/// Call this at startup so the default finder is used when no plugin has registered one.
#[cfg(feature = "python")]
pub fn ensure_default_manifest_finder() {
    if finders().lock().unwrap().is_empty() {
        use spd_python::PythonManifestFinder;
        spd_register!(ManifestFinder, PythonManifestFinder);
    }
}

#[cfg(not(feature = "python"))]
pub fn ensure_default_manifest_finder() {
    // No-op when python feature is disabled; registries stay empty.
}

/// Ensures at least one parser is registered (Python requirements.txt parser when `python` feature).
/// Call this at startup so the default parser is used when no plugin has registered one.
#[cfg(feature = "python")]
pub fn ensure_default_parser() {
    if parsers().lock().unwrap().is_empty() {
        use spd_python::RequirementsTxtParser;
        spd_register!(Parser, RequirementsTxtParser);
    }
}

#[cfg(not(feature = "python"))]
pub fn ensure_default_parser() {
    // No-op when python feature is disabled.
}

/// Ensures at least one resolver is registered (Python direct-only resolver when `python` feature).
#[cfg(feature = "python")]
pub fn ensure_default_resolver() {
    if resolvers().lock().unwrap().is_empty() {
        use spd_python::DirectOnlyResolver;
        spd_register!(Resolver, DirectOnlyResolver);
    }
}

#[cfg(not(feature = "python"))]
pub fn ensure_default_resolver() {
    // No-op when python feature is disabled.
}

/// Ensures at least one CVE provider is registered (default OSV.dev provider).
/// Call this at startup so the default provider is used when no plugin has registered one.
pub fn ensure_default_cve_provider() {
    let mut providers = providers().lock().unwrap();
    if providers.is_empty() {
        providers.push(Box::new(OsvProvider::default()));
    }
}

/// Ensures at least one reporter is registered (default plain-text table reporter).
/// Call this at startup so the default reporter is used when no plugin has registered one.
pub fn ensure_default_reporter() {
    if reporters().lock().unwrap().is_empty() {
        spd_register!(Reporter, DefaultReporter);
    }
}

/// Ensures at least one integrity checker is registered (delegates to backend's verify_integrity).
pub fn ensure_default_integrity_checker() {
    let mut checkers = integrity_checkers().lock().unwrap();
    if checkers.is_empty() {
        checkers.push(Box::new(BackendDelegatingChecker::new()));
    }
}

// ---------------------------------------------------------------------
// Global registries – OnceLock + helpers so `main.rs` can read them.
// ---------------------------------------------------------------------

pub fn finders() -> &'static Mutex<Vec<Box<dyn ManifestFinder>>> {
    static FINDERS: OnceLock<Mutex<Vec<Box<dyn ManifestFinder>>>> = OnceLock::new();
    FINDERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn parsers() -> &'static Mutex<Vec<Box<dyn Parser>>> {
    static PARSERS: OnceLock<Mutex<Vec<Box<dyn Parser>>>> = OnceLock::new();
    PARSERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn resolvers() -> &'static Mutex<Vec<Box<dyn Resolver>>> {
    static RESOLVERS: OnceLock<Mutex<Vec<Box<dyn Resolver>>>> = OnceLock::new();
    RESOLVERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn providers() -> &'static Mutex<Vec<Box<dyn CveProvider>>> {
    static PROVIDERS: OnceLock<Mutex<Vec<Box<dyn CveProvider>>>> = OnceLock::new();
    PROVIDERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn db_backends() -> &'static Mutex<Vec<Box<dyn DatabaseBackend>>> {
    static DB_BACKENDS: OnceLock<Mutex<Vec<Box<dyn DatabaseBackend>>>> = OnceLock::new();
    DB_BACKENDS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn reporters() -> &'static Mutex<Vec<Box<dyn Reporter>>> {
    static REPORTERS: OnceLock<Mutex<Vec<Box<dyn Reporter>>>> = OnceLock::new();
    REPORTERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn integrity_checkers() -> &'static Mutex<Vec<Box<dyn IntegrityChecker>>> {
    static INTEGRITY_CHECKERS: OnceLock<Mutex<Vec<Box<dyn IntegrityChecker>>>> = OnceLock::new();
    INTEGRITY_CHECKERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Serializes tests that mutate or consume global registries (avoids races with main's run() tests).
#[allow(dead_code)]
pub fn registry_test_mutex() -> &'static Mutex<()> {
    static REGISTRY_TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    REGISTRY_TEST_MUTEX.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------
// Unit tests – mutate global registries. Single test runs all steps
// sequentially to avoid races when tests run in parallel.
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn clear_finders() {
        finders().lock().unwrap().clear();
    }
    fn clear_parsers() {
        parsers().lock().unwrap().clear();
    }
    fn clear_resolvers() {
        resolvers().lock().unwrap().clear();
    }
    fn clear_providers() {
        providers().lock().unwrap().clear();
    }
    fn clear_db_backends() {
        db_backends().lock().unwrap().clear();
    }
    fn clear_reporters() {
        reporters().lock().unwrap().clear();
    }
    fn clear_integrity_checkers() {
        integrity_checkers().lock().unwrap().clear();
    }

    /// Registry behavior: register() pushes to correct registry; ensure_default_*
    /// add one impl when empty and are idempotent. All steps in one test to avoid
    /// global-state races when tests run in parallel.
    #[test]
    fn test_registry_register_and_ensure_defaults() {
        let _guard = registry_test_mutex().lock().unwrap();
        // 1) register(Plugin) pushes to the correct registry
        clear_finders();
        #[cfg(feature = "python")]
        register(Plugin::ManifestFinder(Box::new(spd_python::PythonManifestFinder::new())));
        #[cfg(not(feature = "python"))]
        {
            // When python is disabled, no finder to register; skip this assertion
        }
        #[cfg(feature = "python")]
        assert_eq!(finders().lock().unwrap().len(), 1);

        clear_parsers();
        #[cfg(feature = "python")]
        register(Plugin::Parser(Box::new(spd_python::RequirementsTxtParser::new())));
        #[cfg(feature = "python")]
        assert_eq!(parsers().lock().unwrap().len(), 1);

        clear_resolvers();
        #[cfg(feature = "python")]
        register(Plugin::Resolver(Box::new(spd_python::DirectOnlyResolver::new())));
        #[cfg(feature = "python")]
        assert_eq!(resolvers().lock().unwrap().len(), 1);

        clear_providers();
        register(Plugin::CveProvider(Box::new(OsvProvider::default())));
        assert_eq!(providers().lock().unwrap().len(), 1);

        clear_reporters();
        register(Plugin::Reporter(Box::new(DefaultReporter::new())));
        assert_eq!(reporters().lock().unwrap().len(), 1);

        clear_integrity_checkers();
        register(Plugin::IntegrityChecker(Box::new(BackendDelegatingChecker::new())));
        assert_eq!(integrity_checkers().lock().unwrap().len(), 1);

        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            register(Plugin::DatabaseBackend(Box::new(spd_db_redb::RedbBackend::default())));
            assert_eq!(db_backends().lock().unwrap().len(), 1);
        }

        // 2) ensure_default_* when empty add one; second call is idempotent
        #[cfg(feature = "python")]
        {
            clear_finders();
            ensure_default_manifest_finder();
            assert_eq!(finders().lock().unwrap().len(), 1);
            ensure_default_manifest_finder();
            assert_eq!(finders().lock().unwrap().len(), 1);

            clear_parsers();
            ensure_default_parser();
            assert_eq!(parsers().lock().unwrap().len(), 1);
            ensure_default_parser();
            assert_eq!(parsers().lock().unwrap().len(), 1);

            clear_resolvers();
            ensure_default_resolver();
            assert_eq!(resolvers().lock().unwrap().len(), 1);
            ensure_default_resolver();
            assert_eq!(resolvers().lock().unwrap().len(), 1);
        }

        clear_providers();
        ensure_default_cve_provider();
        assert_eq!(providers().lock().unwrap().len(), 1);
        ensure_default_cve_provider();
        assert_eq!(providers().lock().unwrap().len(), 1);

        clear_reporters();
        ensure_default_reporter();
        assert_eq!(reporters().lock().unwrap().len(), 1);
        ensure_default_reporter();
        assert_eq!(reporters().lock().unwrap().len(), 1);

        clear_integrity_checkers();
        ensure_default_integrity_checker();
        assert_eq!(integrity_checkers().lock().unwrap().len(), 1);
        ensure_default_integrity_checker();
        assert_eq!(integrity_checkers().lock().unwrap().len(), 1);

        // 3) ensure_default_db_backend (redb)
        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            ensure_default_db_backend();
            assert!(!db_backends().lock().unwrap().is_empty());
        }

        // 4) ensure_default_db_backend_with_path (redb)
        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.redb");
            let result = ensure_default_db_backend_with_path(path, 3600);
            assert!(result.is_ok());
            assert_eq!(db_backends().lock().unwrap().len(), 1);
            let path2 = dir.path().join("test2.redb");
            let result2 = ensure_default_db_backend_with_path(path2, 3600);
            assert!(result2.is_ok());
            assert_eq!(db_backends().lock().unwrap().len(), 1);
        }
    }
}
