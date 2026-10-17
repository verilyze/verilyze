// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Per-entry cache seals (SEC-004 / SEC-005).

use crate::DatabaseError;

/// RedB table holding one seal per `cve_cache` key.
pub const SEAL_TABLE_NAME: &str = "cve_cache_seal";

/// Label reported by backends that keep nothing on disk to verify.
pub const INTEGRITY_LABEL_NOT_PERSISTED: &str = "in-memory, not persisted";

/// Label reported by an on-disk backend built without a seal algorithm.
pub const INTEGRITY_LABEL_DISABLED: &str = "disabled";

/// Error shown by `vlz db verify` when the build has no seal algorithm.
pub const INTEGRITY_DISABLED_MESSAGE: &str = "Cache integrity sealing is not \
     enabled in this build; rebuild vlz with the integrity-sha256 or \
     integrity-fips204 feature";

/// Produces and checks the seal stored beside each cache value.
pub trait EntrySealer: Send + Sync {
    /// Algorithm name shown by `vlz db verify` (e.g. `SHA-256`).
    fn label(&self) -> &'static str;

    /// Seal the stored value for `key`.
    fn seal(&self, key: &str, value: &str) -> Result<String, DatabaseError>;

    /// `Ok(false)` when the seal does not match or uses another algorithm;
    /// `Err` only when the check cannot run (e.g. key material unavailable).
    fn check(
        &self,
        key: &str,
        value: &str,
        seal: &str,
    ) -> Result<bool, DatabaseError>;
}

/// Bytes covered by a seal: `key`, a NUL separator, then the stored value,
/// so a value cannot be replayed under a different key.
pub fn seal_message(key: &str, value: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(key.len() + 1 + value.len());
    msg.extend_from_slice(key.as_bytes());
    msg.push(0);
    msg.extend_from_slice(value.as_bytes());
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_message_joins_key_and_value_with_nul() {
        assert_eq!(seal_message("a::1::osv", "{}"), b"a::1::osv\0{}".to_vec());
    }

    #[test]
    fn seal_message_binds_key_to_value() {
        assert_ne!(seal_message("ab", "c"), seal_message("a", "bc"));
    }

    #[test]
    fn seal_table_name_is_stable() {
        assert_eq!(SEAL_TABLE_NAME, "cve_cache_seal");
    }
}
