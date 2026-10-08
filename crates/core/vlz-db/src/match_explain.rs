// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Matching transparency fields for findings (roadmap W3-1).

/// Winner selection reason when merging multi-provider records (FR-019-EXT).
pub const WINNER_REASON_AFFECTED_RANGES: &str = "affected_ranges";
/// Winner had a newer CVSS version than other candidates.
pub const WINNER_REASON_CVSS_VERSION: &str = "cvss_version";
/// Winner won on user `--providers` list order.
pub const WINNER_REASON_PROVIDER_ORDER: &str = "provider_order";
/// Sole provider record in the alias group (no merge contest).
pub const WINNER_REASON_SOLE: &str = "sole";

/// Package identity used when querying CVE providers (W3-1).
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
pub struct MatchQuery {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem: Option<String>,
}

/// Structured matching / explain payload attached to a CVE finding (W3-1).
#[derive(
    Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
pub struct MatchExplain {
    /// Provider ids that contributed records to this finding's alias group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    /// Provider id of the merge winner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner_provider: Option<String>,
    /// Why the winner was selected (`affected_ranges`, `cvss_version`,
    /// `provider_order`, or `sole`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winner_reason: Option<String>,
    /// Package identity sent to providers for this lookup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<MatchQuery>,
    /// Alias ids collapsed into this finding (normalized).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases_collapsed: Vec<String>,
    /// Whether the installed package version sits in a covering advisory
    /// range (local re-evaluation of FR-039 ranges).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_in_covering_range: Option<bool>,
    /// Index into `affected_ranges` of the first covering interval, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub covering_range_index: Option<usize>,
    /// NVD CPE string when the winning provider used CPE matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpe: Option<String>,
}

/// Build a [`MatchQuery`] from package identity fields.
pub fn match_query_for(
    name: &str,
    version: &str,
    ecosystem: Option<&str>,
) -> MatchQuery {
    MatchQuery {
        name: name.to_string(),
        version: version.to_string(),
        ecosystem: ecosystem.map(str::to_string),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_query_for_sets_fields() {
        let q = match_query_for("lodash", "4.17.21", Some("npm"));
        assert_eq!(q.name, "lodash");
        assert_eq!(q.version, "4.17.21");
        assert_eq!(q.ecosystem.as_deref(), Some("npm"));
    }

    #[test]
    fn match_explain_serde_omits_empty_defaults() {
        let explain = MatchExplain {
            winner_provider: Some("osv".to_string()),
            winner_reason: Some(WINNER_REASON_SOLE.to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&explain).unwrap();
        assert!(json.contains("winner_provider"));
        assert!(!json.contains("providers"));
        assert!(!json.contains("aliases_collapsed"));
        let back: MatchExplain = serde_json::from_str(&json).unwrap();
        assert_eq!(back.winner_provider.as_deref(), Some("osv"));
        assert_eq!(back.winner_reason.as_deref(), Some(WINNER_REASON_SOLE));
    }
}
