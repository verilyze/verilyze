//! Global registries for each plug‑in type.
//! The core binary pulls the concrete implementations out of these vectors.
//! Registration is binary-driven: ensure_default_* use spd_register! for types
//! with ::new(), or manual register() for types using ::default().

use lazy_static::lazy_static;
use std::sync::Mutex;

use spd_cve_client::{CveProvider, OsvProvider};
use spd_db::DatabaseBackend;
use spd_integrity::IntegrityChecker;
use spd_manifest_finder::{DefaultManifestFinder, ManifestFinder};
use spd_manifest_parser::{Parser, RequirementsTxtParser};
use spd_plugin_macro::spd_register;
use spd_report::{DefaultReporter, Reporter};

/// All possible plug‑in kinds.  The enum makes it easy to route a boxed
/// implementation to the correct registry without needing `Any` tricks.
pub enum Plugin {
    ManifestFinder(Box<dyn ManifestFinder>),
    Parser(Box<dyn Parser>),
    CveProvider(Box<dyn CveProvider>),
    DatabaseBackend(Box<dyn DatabaseBackend>),
    Reporter(Box<dyn Reporter>),
    IntegrityChecker(Box<dyn IntegrityChecker>),
}

/// Register a plug‑in.  Typical usage (inside a plug‑in crate) is:
///
/// ```rust
/// spd_register!(MyFinder);   // expands to `registry::register(Plugin::ManifestFinder(...))`
/// ```
///
/// The macro itself lives in the optional `spd-plugin-macro` crate; the
/// binary only needs the `register` function.
pub fn register(plugin: Plugin) {
    match plugin {
        Plugin::ManifestFinder(f) => {
            FINDERS.lock().unwrap().push(f);
        }
        Plugin::Parser(p) => {
            PARSERS.lock().unwrap().push(p);
        }
        Plugin::CveProvider(cp) => {
            PROVIDERS.lock().unwrap().push(cp);
        }
        Plugin::DatabaseBackend(db) => {
            DB_BACKENDS.lock().unwrap().push(db);
        }
        Plugin::Reporter(r) => {
            REPORTERS.lock().unwrap().push(r);
        }
        Plugin::IntegrityChecker(ic) => {
            INTEGRITY_CHECKERS.lock().unwrap().push(ic);
        }
    }
}

/// Ensures at least one database backend is registered (e.g. RedB when built with `redb` feature).
/// Call this at startup so the default backend is used when no plugin has registered one.
#[cfg(feature = "redb")]
pub fn ensure_default_db_backend() {
    let mut backends = DB_BACKENDS.lock().unwrap();
    if backends.is_empty() {
        backends.push(Box::new(spd_db_redb::RedbBackend::default()));
    }
}

/// Ensures at least one manifest finder is registered (default Python finder).
/// Call this at startup so the default finder is used when no plugin has registered one.
pub fn ensure_default_manifest_finder() {
    if FINDERS.lock().unwrap().is_empty() {
        spd_register!(ManifestFinder, DefaultManifestFinder);
    }
}

/// Ensures at least one parser is registered (default requirements.txt parser).
/// Call this at startup so the default parser is used when no plugin has registered one.
pub fn ensure_default_parser() {
    if PARSERS.lock().unwrap().is_empty() {
        spd_register!(Parser, RequirementsTxtParser);
    }
}

/// Ensures at least one CVE provider is registered (default OSV.dev provider).
/// Call this at startup so the default provider is used when no plugin has registered one.
pub fn ensure_default_cve_provider() {
    let mut providers = PROVIDERS.lock().unwrap();
    if providers.is_empty() {
        providers.push(Box::new(OsvProvider::default()));
    }
}

/// Ensures at least one reporter is registered (default plain-text table reporter).
/// Call this at startup so the default reporter is used when no plugin has registered one.
pub fn ensure_default_reporter() {
    if REPORTERS.lock().unwrap().is_empty() {
        spd_register!(Reporter, DefaultReporter);
    }
}

// ---------------------------------------------------------------------
// Global registries – made `pub(crate)` so `main.rs` can read them.
// ---------------------------------------------------------------------
lazy_static! {
    pub(crate) static ref FINDERS: Mutex<Vec<Box<dyn ManifestFinder>>> = Mutex::new(Vec::new());
    pub(crate) static ref PARSERS: Mutex<Vec<Box<dyn Parser>>> = Mutex::new(Vec::new());
    pub(crate) static ref PROVIDERS: Mutex<Vec<Box<dyn CveProvider>>> = Mutex::new(Vec::new());
    pub(crate) static ref DB_BACKENDS: Mutex<Vec<Box<dyn DatabaseBackend>>> =
        Mutex::new(Vec::new());
    pub(crate) static ref REPORTERS: Mutex<Vec<Box<dyn Reporter>>> = Mutex::new(Vec::new());
    pub(crate) static ref INTEGRITY_CHECKERS: Mutex<Vec<Box<dyn IntegrityChecker>>> =
        Mutex::new(Vec::new());
}
