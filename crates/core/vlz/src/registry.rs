// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::{Mutex, OnceLock};

use vlz_cve_client::{CveProvider, OSV_QUERY_URL, OsvProvider};
use vlz_db::DatabaseBackend;
use vlz_integrity::{BackendDelegatingChecker, IntegrityChecker};
use vlz_manifest_finder::ManifestFinder;
use vlz_manifest_parser::{Parser, Resolver};
use vlz_plugin_macro::vlz_register;
use vlz_report::{DefaultReporter, Reporter};

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
/// vlz_register!(ManifestFinder, MyFinder);   // expands to registry::register(Plugin::ManifestFinder(...))
/// ```
///
/// The macro itself lives in the optional `vlz-plugin-macro` crate; the
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
        backends.push(Box::new(vlz_db_redb::RedbBackend::default()));
    }
}

/// Registers the default RedB backend with an explicit path and TTL (OP-002, OP-003, OP-004).
#[cfg(feature = "redb")]
pub fn ensure_default_db_backend_with_path(
    path: std::path::PathBuf,
    ttl_secs: u64,
) -> Result<(), vlz_db::DatabaseError> {
    let mut backends = db_backends().lock().unwrap();
    if backends.is_empty() {
        let backend = vlz_db_redb::RedbBackend::with_path(path, ttl_secs)?;
        backends.push(Box::new(backend));
    }
    Ok(())
}

/// Ensures language finders are registered (Python and/or Rust when features enabled).
/// Call this at startup so default finders are used.
pub fn ensure_default_manifest_finder() {
    let mut f = finders().lock().unwrap();
    #[cfg(feature = "python")]
    if !f.iter().any(|x| x.language_name() == "python") {
        f.push(Box::new(vlz_python::PythonManifestFinder::new()));
    }
    #[cfg(feature = "rust")]
    if !f.iter().any(|x| x.language_name() == "rust") {
        f.push(Box::new(vlz_rust::RustManifestFinder::new()));
    }
    #[cfg(feature = "go")]
    if !f.iter().any(|x| x.language_name() == "go") {
        f.push(Box::new(vlz_go::GoManifestFinder::new()));
    }
}

/// Ensures language parsers are registered (Python and/or Rust when features enabled).
/// Call this at startup so default parsers are used.
pub fn ensure_default_parser() {
    let mut p = parsers().lock().unwrap();
    #[cfg(feature = "python")]
    if p.is_empty() {
        p.push(Box::new(vlz_python::RequirementsTxtParser::new()));
    }
    #[cfg(feature = "rust")]
    {
        let need_rust = if cfg!(feature = "python") {
            p.len() < 2
        } else {
            p.is_empty()
        };
        if need_rust {
            p.push(Box::new(vlz_rust::CargoTomlParser::new()));
        }
    }
    #[cfg(feature = "go")]
    {
        let expected: usize =
            [cfg!(feature = "python"), cfg!(feature = "rust")]
                .into_iter()
                .filter(|b| *b)
                .count()
                + 1;
        if p.len() < expected {
            p.push(Box::new(vlz_go::GoModParser::new()));
        }
    }
}

/// Ensures language resolvers are registered (Python and/or Rust when features enabled).
pub fn ensure_default_resolver() {
    let mut r = resolvers().lock().unwrap();
    #[cfg(feature = "python")]
    if !r.iter().any(|x| x.package_manager_hint().contains("pip")) {
        r.push(Box::new(vlz_python::DirectOnlyResolver::new()));
    }
    #[cfg(feature = "rust")]
    if !r.iter().any(|x| x.package_manager_hint().contains("cargo")) {
        r.push(Box::new(vlz_rust::CargoResolver::new()));
    }
    #[cfg(feature = "go")]
    if !r
        .iter()
        .any(|x| x.package_manager_hint().contains("golang"))
    {
        r.push(Box::new(vlz_go::GoResolver::new()));
    }
}

/// Ensures at least one CVE provider is registered (default OSV.dev provider).
/// Call this at startup so the default provider is used when no plugin has registered one.
/// When the `nvd` feature is enabled, also registers the NVD provider.
pub fn ensure_default_cve_provider(cfg: &crate::config::EffectiveConfig) {
    vlz_cve_client::ensure_default_decoders();
    let mut providers = providers().lock().unwrap();
    let c = cfg.provider_http_connect_timeout_secs;
    let r = cfg.provider_http_request_timeout_secs;
    let crl = cfg.tls_crl_bundle.as_deref();
    if providers.is_empty() {
        providers.push(Box::new(
            OsvProvider::with_base_url_timeouts(OSV_QUERY_URL, c, r, crl)
                .expect("OsvProvider HTTP client"),
        ));
    }
    #[cfg(feature = "nvd")]
    {
        if !providers.iter().any(|p| p.name() == "nvd") {
            vlz_cve_provider_nvd::register_nvd_decoder();
            providers.push(Box::new(
                vlz_cve_provider_nvd::NvdProvider::with_base_url_timeouts(
                    vlz_cve_provider_nvd::NVD_DEFAULT_BASE_URL,
                    c,
                    r,
                    crl,
                )
                .expect("NvdProvider HTTP client"),
            ));
        }
    }
    #[cfg(feature = "github")]
    {
        if !providers.iter().any(|p| p.name() == "github") {
            vlz_cve_provider_github::register_github_decoder();
            providers.push(Box::new(
                vlz_cve_provider_github::GitHubProvider::with_base_url_timeouts(
                    vlz_cve_provider_github::GITHUB_DEFAULT_ADVISORIES_URL,
                    c,
                    r,
                    crl,
                )
                .expect("GitHubProvider HTTP client"),
            ));
        }
    }
    #[cfg(feature = "sonatype")]
    {
        if !providers.iter().any(|p| p.name() == "sonatype") {
            vlz_cve_provider_sonatype::register_sonatype_decoder();
            providers.push(Box::new(
                vlz_cve_provider_sonatype::SonatypeProvider::with_base_url_timeouts(
                    vlz_cve_provider_sonatype::OSSINDEX_DEFAULT_BASE_URL,
                    c,
                    r,
                    crl,
                )
                .expect("SonatypeProvider HTTP client"),
            ));
        }
    }
}

/// Ensures at least one reporter is registered (default plain-text table reporter).
/// Call this at startup so the default reporter is used when no plugin has registered one.
pub fn ensure_default_reporter() {
    if reporters().lock().unwrap().is_empty() {
        vlz_register!(Reporter, DefaultReporter);
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
    static FINDERS: OnceLock<Mutex<Vec<Box<dyn ManifestFinder>>>> =
        OnceLock::new();
    FINDERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn parsers() -> &'static Mutex<Vec<Box<dyn Parser>>> {
    static PARSERS: OnceLock<Mutex<Vec<Box<dyn Parser>>>> = OnceLock::new();
    PARSERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn resolvers() -> &'static Mutex<Vec<Box<dyn Resolver>>> {
    static RESOLVERS: OnceLock<Mutex<Vec<Box<dyn Resolver>>>> =
        OnceLock::new();
    RESOLVERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn providers() -> &'static Mutex<Vec<Box<dyn CveProvider>>> {
    static PROVIDERS: OnceLock<Mutex<Vec<Box<dyn CveProvider>>>> =
        OnceLock::new();
    PROVIDERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn db_backends() -> &'static Mutex<Vec<Box<dyn DatabaseBackend>>> {
    static DB_BACKENDS: OnceLock<Mutex<Vec<Box<dyn DatabaseBackend>>>> =
        OnceLock::new();
    DB_BACKENDS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn reporters() -> &'static Mutex<Vec<Box<dyn Reporter>>> {
    static REPORTERS: OnceLock<Mutex<Vec<Box<dyn Reporter>>>> =
        OnceLock::new();
    REPORTERS.get_or_init(|| Mutex::new(Vec::new()))
}

pub fn integrity_checkers() -> &'static Mutex<Vec<Box<dyn IntegrityChecker>>> {
    static INTEGRITY_CHECKERS: OnceLock<
        Mutex<Vec<Box<dyn IntegrityChecker>>>,
    > = OnceLock::new();
    INTEGRITY_CHECKERS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Serializes tests that mutate or consume global registries (avoids races with main's run() tests).
#[allow(dead_code)]
pub fn registry_test_mutex() -> &'static Mutex<()> {
    static REGISTRY_TEST_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
    REGISTRY_TEST_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Clear registries for test use. Call before registering mocks (e.g. FailingResolver).
#[cfg(any(test, feature = "testing"))]
pub fn clear_resolvers() {
    resolvers().lock().unwrap().clear();
}

#[cfg(any(test, feature = "testing"))]
pub fn clear_providers() {
    providers().lock().unwrap().clear();
}

#[cfg(any(test, feature = "testing"))]
pub fn clear_db_backends() {
    db_backends().lock().unwrap().clear();
}

#[cfg(any(test, feature = "testing"))]
pub fn clear_reporters() {
    reporters().lock().unwrap().clear();
}

#[cfg(any(test, feature = "testing"))]
pub fn clear_integrity_checkers() {
    integrity_checkers().lock().unwrap().clear();
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
        let _guard = registry_test_mutex()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // 1) register(Plugin) pushes to the correct registry
        clear_finders();
        #[cfg(feature = "python")]
        register(Plugin::ManifestFinder(Box::new(
            vlz_python::PythonManifestFinder::new(),
        )));
        #[cfg(not(feature = "python"))]
        {
            // When python is disabled, no finder to register; skip this assertion
        }
        #[cfg(feature = "python")]
        assert_eq!(finders().lock().unwrap().len(), 1);

        clear_parsers();
        #[cfg(feature = "python")]
        register(Plugin::Parser(Box::new(
            vlz_python::RequirementsTxtParser::new(),
        )));
        #[cfg(feature = "python")]
        assert_eq!(parsers().lock().unwrap().len(), 1);

        clear_resolvers();
        #[cfg(feature = "python")]
        register(Plugin::Resolver(Box::new(
            vlz_python::DirectOnlyResolver::new(),
        )));
        #[cfg(feature = "python")]
        assert_eq!(resolvers().lock().unwrap().len(), 1);

        clear_providers();
        register(Plugin::CveProvider(Box::new(OsvProvider::default())));
        assert_eq!(providers().lock().unwrap().len(), 1);

        clear_reporters();
        register(Plugin::Reporter(Box::new(DefaultReporter::new())));
        assert_eq!(reporters().lock().unwrap().len(), 1);

        clear_integrity_checkers();
        register(Plugin::IntegrityChecker(Box::new(
            BackendDelegatingChecker::new(),
        )));
        assert_eq!(integrity_checkers().lock().unwrap().len(), 1);

        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("reg.redb");
            let backend = vlz_db_redb::RedbBackend::with_path(path, 3600)
                .expect("RedbBackend::with_path");
            register(Plugin::DatabaseBackend(Box::new(backend)));
            assert_eq!(db_backends().lock().unwrap().len(), 1);
        }

        // 2) ensure_default_* when empty add one per language; second call is idempotent
        #[cfg(any(feature = "python", feature = "rust", feature = "go"))]
        {
            let expected: usize = [
                cfg!(feature = "python"),
                cfg!(feature = "rust"),
                cfg!(feature = "go"),
            ]
            .into_iter()
            .filter(|b| *b)
            .count();

            clear_finders();
            ensure_default_manifest_finder();
            assert_eq!(finders().lock().unwrap().len(), expected);
            ensure_default_manifest_finder();
            assert_eq!(finders().lock().unwrap().len(), expected);

            clear_parsers();
            ensure_default_parser();
            assert_eq!(parsers().lock().unwrap().len(), expected);
            ensure_default_parser();
            assert_eq!(parsers().lock().unwrap().len(), expected);

            clear_resolvers();
            ensure_default_resolver();
            assert_eq!(resolvers().lock().unwrap().len(), expected);
            ensure_default_resolver();
            assert_eq!(resolvers().lock().unwrap().len(), expected);
        }

        clear_providers();
        let cve_cfg = crate::config::EffectiveConfig {
            provider_http_connect_timeout_secs:
                vlz_cve_client::DEFAULT_PROVIDER_HTTP_CONNECT_TIMEOUT_SECS,
            provider_http_request_timeout_secs:
                vlz_cve_client::DEFAULT_PROVIDER_HTTP_REQUEST_TIMEOUT_SECS,
            ..Default::default()
        };
        ensure_default_cve_provider(&cve_cfg);
        let expected_providers = 1
            + if cfg!(feature = "nvd") { 1 } else { 0 }
            + if cfg!(feature = "github") { 1 } else { 0 }
            + if cfg!(feature = "sonatype") { 1 } else { 0 };
        assert_eq!(providers().lock().unwrap().len(), expected_providers);
        ensure_default_cve_provider(&cve_cfg);
        assert_eq!(providers().lock().unwrap().len(), expected_providers);

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

        // 3) ensure_default_db_backend_with_path (redb) when empty adds one
        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("ensure.redb");
            ensure_default_db_backend_with_path(path, 3600)
                .expect("ensure_default_db_backend_with_path");
            assert!(!db_backends().lock().unwrap().is_empty());
        }

        // 4) ensure_default_db_backend_with_path idempotent (redb)
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
