// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// This file is part of super-duper.
//
// super-duper is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// super-duper is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// super-duper (see the COPYING file in the project root for the full text). If
// not, see <https://www.gnu.org/licenses/>.

use lazy_static::lazy_static;
use std::sync::Mutex;

use spd_cve_client::{CveProvider, OsvProvider};
use spd_db::DatabaseBackend;
use spd_integrity::{BackendDelegatingChecker, IntegrityChecker};
use spd_manifest_finder::{DefaultManifestFinder, ManifestFinder};
use spd_manifest_parser::{DirectOnlyResolver, Parser, RequirementsTxtParser, Resolver};
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
        Plugin::Resolver(r) => {
            RESOLVERS.lock().unwrap().push(r);
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
#[allow(dead_code)]
pub fn ensure_default_db_backend() {
    let mut backends = DB_BACKENDS.lock().unwrap();
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
    let mut backends = DB_BACKENDS.lock().unwrap();
    if backends.is_empty() {
        let backend = spd_db_redb::RedbBackend::with_path(path, ttl_secs)?;
        backends.push(Box::new(backend));
    }
    Ok(())
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

/// Ensures at least one resolver is registered (default direct-only resolver).
pub fn ensure_default_resolver() {
    if RESOLVERS.lock().unwrap().is_empty() {
        spd_register!(Resolver, DirectOnlyResolver);
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

/// Ensures at least one integrity checker is registered (delegates to backend's verify_integrity).
pub fn ensure_default_integrity_checker() {
    let mut checkers = INTEGRITY_CHECKERS.lock().unwrap();
    if checkers.is_empty() {
        checkers.push(Box::new(BackendDelegatingChecker::new()));
    }
}

// ---------------------------------------------------------------------
// Global registries – made `pub(crate)` so `main.rs` can read them.
// ---------------------------------------------------------------------
lazy_static! {
    pub(crate) static ref FINDERS: Mutex<Vec<Box<dyn ManifestFinder>>> = Mutex::new(Vec::new());
    pub(crate) static ref PARSERS: Mutex<Vec<Box<dyn Parser>>> = Mutex::new(Vec::new());
    pub(crate) static ref RESOLVERS: Mutex<Vec<Box<dyn Resolver>>> = Mutex::new(Vec::new());
    pub(crate) static ref PROVIDERS: Mutex<Vec<Box<dyn CveProvider>>> = Mutex::new(Vec::new());
    pub(crate) static ref DB_BACKENDS: Mutex<Vec<Box<dyn DatabaseBackend>>> =
        Mutex::new(Vec::new());
    pub(crate) static ref REPORTERS: Mutex<Vec<Box<dyn Reporter>>> = Mutex::new(Vec::new());
    pub(crate) static ref INTEGRITY_CHECKERS: Mutex<Vec<Box<dyn IntegrityChecker>>> =
        Mutex::new(Vec::new());
    /// Serializes tests that mutate or consume global registries (avoids races with main's run() tests).
    pub(crate) static ref REGISTRY_TEST_MUTEX: Mutex<()> = Mutex::new(());
}

// ---------------------------------------------------------------------
// Unit tests – mutate global registries. Single test runs all steps
// sequentially to avoid races when tests run in parallel.
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn clear_finders() {
        FINDERS.lock().unwrap().clear();
    }
    fn clear_parsers() {
        PARSERS.lock().unwrap().clear();
    }
    fn clear_resolvers() {
        RESOLVERS.lock().unwrap().clear();
    }
    fn clear_providers() {
        PROVIDERS.lock().unwrap().clear();
    }
    fn clear_db_backends() {
        DB_BACKENDS.lock().unwrap().clear();
    }
    fn clear_reporters() {
        REPORTERS.lock().unwrap().clear();
    }
    fn clear_integrity_checkers() {
        INTEGRITY_CHECKERS.lock().unwrap().clear();
    }

    /// Registry behavior: register() pushes to correct registry; ensure_default_*
    /// add one impl when empty and are idempotent. All steps in one test to avoid
    /// global-state races when tests run in parallel.
    #[test]
    fn test_registry_register_and_ensure_defaults() {
        let _guard = REGISTRY_TEST_MUTEX.lock().unwrap();
        // 1) register(Plugin) pushes to the correct registry
        clear_finders();
        register(Plugin::ManifestFinder(Box::new(DefaultManifestFinder::new())));
        assert_eq!(FINDERS.lock().unwrap().len(), 1);

        clear_parsers();
        register(Plugin::Parser(Box::new(RequirementsTxtParser::new())));
        assert_eq!(PARSERS.lock().unwrap().len(), 1);

        clear_resolvers();
        register(Plugin::Resolver(Box::new(DirectOnlyResolver::new())));
        assert_eq!(RESOLVERS.lock().unwrap().len(), 1);

        clear_providers();
        register(Plugin::CveProvider(Box::new(OsvProvider::default())));
        assert_eq!(PROVIDERS.lock().unwrap().len(), 1);

        clear_reporters();
        register(Plugin::Reporter(Box::new(DefaultReporter::new())));
        assert_eq!(REPORTERS.lock().unwrap().len(), 1);

        clear_integrity_checkers();
        register(Plugin::IntegrityChecker(Box::new(BackendDelegatingChecker::new())));
        assert_eq!(INTEGRITY_CHECKERS.lock().unwrap().len(), 1);

        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            register(Plugin::DatabaseBackend(Box::new(spd_db_redb::RedbBackend::default())));
            assert_eq!(DB_BACKENDS.lock().unwrap().len(), 1);
        }

        // 2) ensure_default_* when empty add one; second call is idempotent
        clear_finders();
        ensure_default_manifest_finder();
        assert_eq!(FINDERS.lock().unwrap().len(), 1);
        ensure_default_manifest_finder();
        assert_eq!(FINDERS.lock().unwrap().len(), 1);

        clear_parsers();
        ensure_default_parser();
        assert_eq!(PARSERS.lock().unwrap().len(), 1);
        ensure_default_parser();
        assert_eq!(PARSERS.lock().unwrap().len(), 1);

        clear_resolvers();
        ensure_default_resolver();
        assert_eq!(RESOLVERS.lock().unwrap().len(), 1);
        ensure_default_resolver();
        assert_eq!(RESOLVERS.lock().unwrap().len(), 1);

        clear_providers();
        ensure_default_cve_provider();
        assert_eq!(PROVIDERS.lock().unwrap().len(), 1);
        ensure_default_cve_provider();
        assert_eq!(PROVIDERS.lock().unwrap().len(), 1);

        clear_reporters();
        ensure_default_reporter();
        assert_eq!(REPORTERS.lock().unwrap().len(), 1);
        ensure_default_reporter();
        assert_eq!(REPORTERS.lock().unwrap().len(), 1);

        clear_integrity_checkers();
        ensure_default_integrity_checker();
        assert_eq!(INTEGRITY_CHECKERS.lock().unwrap().len(), 1);
        ensure_default_integrity_checker();
        assert_eq!(INTEGRITY_CHECKERS.lock().unwrap().len(), 1);

        // 3) ensure_default_db_backend (redb)
        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            ensure_default_db_backend();
            assert!(!DB_BACKENDS.lock().unwrap().is_empty());
        }

        // 4) ensure_default_db_backend_with_path (redb)
        #[cfg(feature = "redb")]
        {
            clear_db_backends();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.redb");
            let result = ensure_default_db_backend_with_path(path, 3600);
            assert!(result.is_ok());
            assert_eq!(DB_BACKENDS.lock().unwrap().len(), 1);
            let path2 = dir.path().join("test2.redb");
            let result2 = ensure_default_db_backend_with_path(path2, 3600);
            assert!(result2.is_ok());
            assert_eq!(DB_BACKENDS.lock().unwrap().len(), 1);
        }
    }
}
