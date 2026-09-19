// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Resolve and select CVE providers (FR-019, FR-019-EXT).

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use vlz_cve_client::{RetryingCveProvider, SharedCveProvider};

#[cfg(any(test, feature = "testing"))]
use crate::cli_values::TESTING_PROVIDER_NAMES;
use crate::cli_values::production_provider_names;

/// Split a comma-separated provider list; trim and drop empty tokens.
pub fn parse_providers_csv(raw: &str) -> Vec<String> {
    crate::config::parse_csv_list(raw)
}

/// True when `name` is a testing-only mock provider.
pub fn is_testing_provider_name(name: &str) -> bool {
    #[cfg(any(test, feature = "testing"))]
    {
        TESTING_PROVIDER_NAMES
            .iter()
            .any(|n| n.eq_ignore_ascii_case(name))
    }
    #[cfg(not(any(test, feature = "testing")))]
    {
        let _ = name;
        false
    }
}

fn registered_name_matching(name: &str) -> Option<String> {
    let guard = crate::registry::providers()
        .lock()
        .expect("PROVIDERS lock poisoned");
    guard
        .iter()
        .find(|p| p.name().eq_ignore_ascii_case(name))
        .map(|p| p.name().to_string())
}

fn expand_all_token() -> Vec<String> {
    let production: HashSet<&str> =
        production_provider_names().into_iter().collect();
    let guard = crate::registry::providers()
        .lock()
        .expect("PROVIDERS lock poisoned");
    guard
        .iter()
        .map(|p| p.name().to_string())
        .filter(|n| production.contains(n.as_str()))
        .collect()
}

fn normalize_list(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for token in raw {
        if token.eq_ignore_ascii_case("all") {
            for name in expand_all_token() {
                if seen.insert(name.to_ascii_lowercase()) {
                    out.push(name);
                }
            }
            continue;
        }
        let Some(canonical) = registered_name_matching(token) else {
            return Err(anyhow!(
                "Unknown provider: {token} (use `vlz db list-providers` to list)"
            ));
        };
        if seen.insert(canonical.to_ascii_lowercase()) {
            out.push(canonical);
        }
    }
    if out.is_empty() {
        return Err(anyhow!(
            "providers list is empty (use `vlz db list-providers` to list)"
        ));
    }
    Ok(out)
}

fn set_key(names: &[String]) -> HashSet<String> {
    names.iter().map(|n| n.to_ascii_lowercase()).collect()
}

/// Apply CLI `--provider` / `--providers` onto `effective.providers` (CFG-007).
pub fn apply_cli_providers(
    effective: &mut crate::config::EffectiveConfig,
    cli_provider: Option<&str>,
    cli_providers: Option<&str>,
) -> Result<()> {
    match (cli_provider, cli_providers) {
        (Some(one), Some(list)) => {
            let from_one = normalize_list(&[one.to_string()])?;
            let from_list = normalize_list(&parse_providers_csv(list))?;
            if set_key(&from_one) != set_key(&from_list) {
                return Err(anyhow!(
                    "--provider and --providers name different provider sets"
                ));
            }
            effective.providers = from_list;
        }
        (None, Some(list)) => {
            effective.providers = normalize_list(&parse_providers_csv(list))?;
        }
        (Some(one), None) => {
            effective.providers = normalize_list(&[one.to_string()])?;
        }
        (None, None) => match normalize_list(&effective.providers) {
            Ok(list) => effective.providers = list,
            Err(err) => {
                let fallback = expand_all_token();
                if effective.providers.len() == 1
                    && effective.providers[0].eq_ignore_ascii_case(
                        crate::config::DEFAULT_CVE_PROVIDER,
                    )
                    && !fallback.is_empty()
                {
                    effective.providers = vec![fallback[0].clone()];
                } else {
                    return Err(err);
                }
            }
        },
    }
    Ok(())
}

/// Wrap each resolved name in `RetryingCveProvider` without draining the registry.
pub fn select_providers(
    names: &[String],
    effective: &crate::config::EffectiveConfig,
) -> Result<Vec<SharedCveProvider>> {
    let guard = crate::registry::providers()
        .lock()
        .expect("PROVIDERS lock poisoned");
    if guard.is_empty() {
        log::error!("No CveProvider plug-in registered");
        return Err(anyhow!("No CveProvider plug-in registered"));
    }
    let backoff_config = vlz_cve_client::BackoffConfig {
        base_ms: effective.backoff_base_ms,
        max_ms: effective.backoff_max_ms,
        max_retries: effective.max_retries,
    };
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        let Some(inner) = guard
            .iter()
            .find(|p| p.name().eq_ignore_ascii_case(name))
            .cloned()
        else {
            log::error!(
                "Unknown provider: {name} (use `vlz db list-providers` to list)"
            );
            return Err(anyhow!(
                "Unknown provider: {name} (use `vlz db list-providers` to list)"
            ));
        };
        let wrapped = RetryingCveProvider::new(inner, backoff_config.clone());
        out.push(Arc::new(wrapped) as SharedCveProvider);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_providers_csv_trims_and_drops_empties() {
        assert_eq!(
            parse_providers_csv(" osv, nvd ,,github "),
            vec!["osv", "nvd", "github"]
        );
        assert!(parse_providers_csv(" , , ").is_empty());
    }

    #[test]
    fn testing_mock_names_are_detected() {
        #[cfg(any(test, feature = "testing"))]
        {
            assert!(is_testing_provider_name("panicking"));
            assert!(is_testing_provider_name("FAILING"));
            assert!(!is_testing_provider_name("osv"));
        }
    }

    fn locked_cfg() -> crate::config::EffectiveConfig {
        crate::registry::clear_providers();
        crate::registry::register(crate::registry::Plugin::CveProvider(
            Box::new(crate::mocks::OsvMockCveProvider),
        ));
        crate::registry::register(crate::registry::Plugin::CveProvider(
            Box::new(crate::mocks::FailingCveProvider::new()),
        ));
        crate::config::EffectiveConfig::default()
    }

    #[test]
    fn select_providers_does_not_drain_registry() {
        let _guard = crate::registry::lock_registry_for_test();
        let cfg = locked_cfg();
        let first = select_providers(&["osv".to_string()], &cfg).unwrap();
        let second = select_providers(&["osv".to_string()], &cfg).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_eq!(first[0].name(), "osv");
        assert_eq!(second[0].name(), "osv");
        let still = crate::registry::providers().lock().unwrap().len();
        assert!(still >= 2);
    }

    #[test]
    fn apply_cli_all_excludes_testing_mocks() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        apply_cli_providers(&mut cfg, None, Some("all")).unwrap();
        assert_eq!(cfg.providers, vec!["osv"]);
    }

    #[test]
    fn apply_cli_provider_overrides_file_list() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        cfg.providers = vec!["failing".to_string()];
        apply_cli_providers(&mut cfg, Some("osv"), None).unwrap();
        assert_eq!(cfg.providers, vec!["osv"]);
    }

    #[test]
    fn apply_cli_none_keeps_effective_providers() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        cfg.providers = vec!["failing".to_string()];
        apply_cli_providers(&mut cfg, None, None).unwrap();
        assert_eq!(cfg.providers, vec!["failing"]);
    }

    #[test]
    fn apply_cli_both_flags_same_set_keeps_providers_order() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        apply_cli_providers(&mut cfg, Some("OSV"), Some("osv")).unwrap();
        assert_eq!(cfg.providers, vec!["osv"]);
    }

    #[test]
    fn apply_cli_both_flags_different_sets_error() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        let err = apply_cli_providers(&mut cfg, Some("osv"), Some("failing"))
            .unwrap_err();
        assert!(err.to_string().contains("different provider sets"));
    }

    #[test]
    fn apply_cli_unknown_name_errors() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        let err = apply_cli_providers(&mut cfg, None, Some("not-a-provider"))
            .unwrap_err();
        assert!(err.to_string().contains("Unknown provider"));
        assert!(err.to_string().contains("list-providers"));
    }

    #[test]
    fn apply_cli_empty_list_errors() {
        let err = parse_providers_csv(" , ");
        assert!(err.is_empty());
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        let err =
            apply_cli_providers(&mut cfg, None, Some(" , ")).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn apply_cli_dedup_and_case() {
        let _guard = crate::registry::lock_registry_for_test();
        let mut cfg = locked_cfg();
        apply_cli_providers(&mut cfg, None, Some("OSV, osv, failing"))
            .unwrap();
        assert_eq!(cfg.providers, vec!["osv", "failing"]);
    }
}
