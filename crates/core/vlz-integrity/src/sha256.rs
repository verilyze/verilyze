// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! SEC-004: unkeyed SHA-256 seal per cache entry. Detects edits made
//! outside vlz, but not an attacker who recomputes the digest.

use vlz_db::{DatabaseError, EntrySealer, seal_message, sha256_hex};

use crate::INTEGRITY_LABEL_SHA256;

pub const SHA256_SEAL_PREFIX: &str = "sha256:";

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha256Sealer;

impl EntrySealer for Sha256Sealer {
    fn label(&self) -> &'static str {
        INTEGRITY_LABEL_SHA256
    }

    fn seal(&self, key: &str, value: &str) -> Result<String, DatabaseError> {
        Ok(format!(
            "{SHA256_SEAL_PREFIX}{}",
            sha256_hex(&seal_message(key, value))
        ))
    }

    fn check(
        &self,
        key: &str,
        value: &str,
        seal: &str,
    ) -> Result<bool, DatabaseError> {
        Ok(self.seal(key, value)? == seal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vlz_db::EntrySealer;

    const KEY: &str = "pkg::1.0::osv";
    const VALUE: &str = r#"{"raw_vulns":[],"provider_id":"osv"}"#;

    #[test]
    fn seal_is_prefixed_hex_digest_of_seal_message() {
        let seal = Sha256Sealer.seal(KEY, VALUE).unwrap();
        let expected = format!(
            "{SHA256_SEAL_PREFIX}{}",
            vlz_db::sha256_hex(&vlz_db::seal_message(KEY, VALUE))
        );
        assert_eq!(seal, expected);
    }

    #[test]
    fn check_accepts_own_seal() {
        let seal = Sha256Sealer.seal(KEY, VALUE).unwrap();
        assert!(Sha256Sealer.check(KEY, VALUE, &seal).unwrap());
    }

    #[test]
    fn check_rejects_tampered_value() {
        let seal = Sha256Sealer.seal(KEY, VALUE).unwrap();
        assert!(!Sha256Sealer.check(KEY, "{}", &seal).unwrap());
    }

    #[test]
    fn check_rejects_value_moved_to_other_key() {
        let seal = Sha256Sealer.seal(KEY, VALUE).unwrap();
        assert!(!Sha256Sealer.check("other::1.0::osv", VALUE, &seal).unwrap());
    }

    #[test]
    fn check_rejects_foreign_or_malformed_seal() {
        let digest = vlz_db::sha256_hex(&vlz_db::seal_message(KEY, VALUE));
        for seal in [
            format!("mldsa65:{digest}"),
            digest.clone(),
            String::new(),
            SHA256_SEAL_PREFIX.to_string(),
        ] {
            assert!(!Sha256Sealer.check(KEY, VALUE, &seal).unwrap(), "{seal}");
        }
    }

    #[test]
    fn label_is_sha256() {
        assert_eq!(Sha256Sealer.label(), crate::INTEGRITY_LABEL_SHA256);
    }
}
