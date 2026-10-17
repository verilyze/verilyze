// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! SEC-005: ML-DSA-65 (FIPS 204) signature per cache entry. Algorithm
//! conformance only; `ml-dsa` is not a FIPS 140 validated module.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ml_dsa::{
    EncodedVerifyingKey, Generate, Keypair, MlDsa65, Seed, Signature,
    SignatureEncoding, Signer, SigningKey, Verifier, VerifyingKey,
};
use vlz_db::{DatabaseError, EntrySealer, seal_message};

use crate::INTEGRITY_LABEL_FIPS204;

pub const MLDSA65_SEAL_PREFIX: &str = "mldsa65:";
/// 32-byte ML-DSA seed (FIPS 204 `xi`), stored next to the cache DB.
pub const SIGNING_KEY_FILE_NAME: &str = "cache-signing.mldsa65.key";
/// Encoded ML-DSA-65 public key; the only file `vlz db verify` needs.
pub const VERIFYING_KEY_FILE_NAME: &str = "cache-signing.mldsa65.pub";
/// Owner read/write only (SEC-014). Windows relies on the directory ACL.
#[cfg(unix)]
const SIGNING_KEY_MODE: u32 = 0o600;

/// Signs `key || 0x00 || value` with a keypair kept beside the cache DB.
/// Keys are read (or generated, on the first seal) lazily, and every key
/// problem fails closed instead of silently rotating the keypair.
pub struct MlDsa65Sealer {
    signing_key_path: PathBuf,
    verifying_key_path: PathBuf,
    signing: OnceLock<SigningKey<MlDsa65>>,
    verifying: OnceLock<VerifyingKey<MlDsa65>>,
}

impl MlDsa65Sealer {
    pub fn for_cache_db(cache_db_path: &Path) -> Self {
        let dir = cache_db_path.parent().unwrap_or(Path::new(""));
        Self {
            signing_key_path: dir.join(SIGNING_KEY_FILE_NAME),
            verifying_key_path: dir.join(VERIFYING_KEY_FILE_NAME),
            signing: OnceLock::new(),
            verifying: OnceLock::new(),
        }
    }

    pub fn signing_key_path(&self) -> &Path {
        &self.signing_key_path
    }

    pub fn verifying_key_path(&self) -> &Path {
        &self.verifying_key_path
    }

    fn signing_key(&self) -> Result<&SigningKey<MlDsa65>, DatabaseError> {
        if let Some(key) = self.signing.get() {
            return Ok(key);
        }
        let key = self.load_or_create_signing_key()?;
        self.ensure_verifying_key_file(&key)?;
        Ok(self.signing.get_or_init(|| key))
    }

    fn load_or_create_signing_key(
        &self,
    ) -> Result<SigningKey<MlDsa65>, DatabaseError> {
        match fs::read(&self.signing_key_path) {
            Ok(bytes) => self.decode_signing_key(&bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if self.verifying_key_path.exists() {
                    return Err(key_error(
                        &self.signing_key_path,
                        &format!(
                            "missing; refusing to generate a new keypair \
                             while {} exists",
                            self.verifying_key_path.display()
                        ),
                    ));
                }
                self.create_signing_key()
            }
            Err(e) => Err(io_key_error(&self.signing_key_path)(e)),
        }
    }

    fn decode_signing_key(
        &self,
        bytes: &[u8],
    ) -> Result<SigningKey<MlDsa65>, DatabaseError> {
        let seed = Seed::try_from(bytes).map_err(|_| {
            key_error(&self.signing_key_path, "not a 32-byte ML-DSA seed")
        })?;
        Ok(SigningKey::from_seed(&seed))
    }

    fn create_signing_key(
        &self,
    ) -> Result<SigningKey<MlDsa65>, DatabaseError> {
        let path = &self.signing_key_path;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(io_key_error(path))?;
        }
        let key = SigningKey::<MlDsa65>::try_generate()
            .map_err(std::io::Error::other)
            .map_err(io_key_error(path))?;
        match write_owner_only(path, key.to_seed().as_slice()) {
            Ok(()) => Ok(key),
            // Another process generated the keypair first; use theirs.
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let bytes = fs::read(path).map_err(io_key_error(path))?;
                self.decode_signing_key(&bytes)
            }
            Err(e) => Err(io_key_error(path)(e)),
        }
    }

    fn ensure_verifying_key_file(
        &self,
        key: &SigningKey<MlDsa65>,
    ) -> Result<(), DatabaseError> {
        let path = &self.verifying_key_path;
        let encoded = key.verifying_key().encode();
        match fs::read(path) {
            Ok(bytes) if bytes.as_slice() == encoded.as_slice() => Ok(()),
            Ok(_) => Err(key_error(
                path,
                &format!("does not match {}", self.signing_key_path.display()),
            )),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                write_replace(path, encoded.as_slice())
                    .map_err(io_key_error(path))
            }
            Err(e) => Err(io_key_error(path)(e)),
        }
    }

    fn verifying_key(&self) -> Result<&VerifyingKey<MlDsa65>, DatabaseError> {
        if let Some(key) = self.verifying.get() {
            return Ok(key);
        }
        let path = &self.verifying_key_path;
        let bytes = fs::read(path).map_err(io_key_error(path))?;
        let encoded =
            EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice())
                .map_err(|_| key_error(path, "not an ML-DSA-65 public key"))?;
        Ok(self
            .verifying
            .get_or_init(|| VerifyingKey::decode(&encoded)))
    }
}

impl EntrySealer for MlDsa65Sealer {
    fn label(&self) -> &'static str {
        INTEGRITY_LABEL_FIPS204
    }

    fn seal_prefix(&self) -> &'static str {
        MLDSA65_SEAL_PREFIX
    }

    fn seal(&self, key: &str, value: &str) -> Result<String, DatabaseError> {
        let signature = self.signing_key()?.sign(&seal_message(key, value));
        Ok(format!(
            "{MLDSA65_SEAL_PREFIX}{}",
            STANDARD.encode(signature.to_bytes())
        ))
    }

    fn check(
        &self,
        key: &str,
        value: &str,
        seal: &str,
    ) -> Result<bool, DatabaseError> {
        let Some(encoded) = seal.strip_prefix(MLDSA65_SEAL_PREFIX) else {
            return Ok(false);
        };
        let Ok(bytes) = STANDARD.decode(encoded) else {
            return Ok(false);
        };
        let Ok(signature) = Signature::<MlDsa65>::try_from(bytes.as_slice())
        else {
            return Ok(false);
        };
        Ok(self
            .verifying_key()?
            .verify(&seal_message(key, value), &signature)
            .is_ok())
    }
}

fn key_error(path: &Path, reason: &str) -> DatabaseError {
    DatabaseError::IntegrityViolation(format!(
        "Cache signing key {}: {reason}",
        path.display()
    ))
}

fn io_key_error(path: &Path) -> impl Fn(std::io::Error) -> DatabaseError {
    move |e| key_error(path, &e.to_string())
}

/// Create `path` with owner-only permissions; fails if it already exists.
fn write_owner_only(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(SIGNING_KEY_MODE);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Write via a temp file and rename so readers never see a partial key.
fn write_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, bytes)?;
    let renamed = fs::rename(&tmp, path);
    if renamed.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    renamed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use vlz_db::EntrySealer;

    /// FIPS 204 Table 2: ML-DSA seed and ML-DSA-65 public key sizes.
    const SEED_LEN: usize = 32;
    const VERIFYING_KEY_LEN: usize = 1952;

    const KEY: &str = "pkg::1.0::osv";
    const VALUE: &str = r#"{"raw_vulns":[],"provider_id":"osv"}"#;

    fn cache_db(dir: &Path) -> PathBuf {
        dir.join("vlz-cache.redb")
    }

    fn sealer(dir: &Path) -> MlDsa65Sealer {
        MlDsa65Sealer::for_cache_db(&cache_db(dir))
    }

    fn err_text(
        r: Result<impl std::fmt::Debug, vlz_db::DatabaseError>,
    ) -> String {
        r.expect_err("must fail closed").to_string()
    }

    #[test]
    fn key_files_live_next_to_cache_db() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        assert_eq!(
            s.signing_key_path(),
            dir.path().join(SIGNING_KEY_FILE_NAME)
        );
        assert_eq!(
            s.verifying_key_path(),
            dir.path().join(VERIFYING_KEY_FILE_NAME)
        );
    }

    #[test]
    fn construction_does_not_touch_disk() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        assert!(!s.signing_key_path().exists());
        assert!(!s.verifying_key_path().exists());
    }

    #[test]
    fn first_seal_generates_keypair() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.seal(KEY, VALUE).unwrap();
        let seed = std::fs::read(s.signing_key_path()).unwrap();
        let public = std::fs::read(s.verifying_key_path()).unwrap();
        assert_eq!(seed.len(), SEED_LEN);
        assert_eq!(public.len(), VERIFYING_KEY_LEN);
    }

    #[cfg(unix)]
    #[test]
    fn signing_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.seal(KEY, VALUE).unwrap();
        let mode = std::fs::metadata(s.signing_key_path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, SIGNING_KEY_MODE);
    }

    #[test]
    fn seal_round_trips_with_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        let seal = s.seal(KEY, VALUE).unwrap();
        assert!(seal.starts_with(MLDSA65_SEAL_PREFIX), "{seal}");
        assert_eq!(s.seal_prefix(), MLDSA65_SEAL_PREFIX);
        assert!(s.check(KEY, VALUE, &seal).unwrap());
    }

    #[test]
    fn check_rejects_tampered_value_and_key_swap() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        let seal = s.seal(KEY, VALUE).unwrap();
        assert!(!s.check(KEY, "{}", &seal).unwrap());
        assert!(!s.check("other::1.0::osv", VALUE, &seal).unwrap());
    }

    #[test]
    fn existing_keypair_is_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = sealer(dir.path());
        let seal = first.seal(KEY, VALUE).unwrap();
        let seed = std::fs::read(first.signing_key_path()).unwrap();

        let second = sealer(dir.path());
        assert!(second.check(KEY, VALUE, &seal).unwrap());
        second.seal("k2", "v2").unwrap();
        assert_eq!(std::fs::read(second.signing_key_path()).unwrap(), seed);
    }

    #[test]
    fn verify_needs_only_public_key() {
        let dir = tempfile::tempdir().unwrap();
        let seal = sealer(dir.path()).seal(KEY, VALUE).unwrap();
        std::fs::remove_file(dir.path().join(SIGNING_KEY_FILE_NAME)).unwrap();
        assert!(sealer(dir.path()).check(KEY, VALUE, &seal).unwrap());
    }

    #[test]
    fn check_rejects_seal_from_other_keypair() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let foreign = sealer(a.path()).seal(KEY, VALUE).unwrap();
        let local = sealer(b.path());
        local.seal(KEY, VALUE).unwrap();
        assert!(!local.check(KEY, VALUE, &foreign).unwrap());
    }

    #[test]
    fn check_rejects_foreign_or_malformed_seal() {
        let dir = tempfile::tempdir().unwrap();
        let s = sealer(dir.path());
        s.seal(KEY, VALUE).unwrap();
        for seal in [
            String::new(),
            MLDSA65_SEAL_PREFIX.to_string(),
            format!("sha256:{}", "0".repeat(64)),
            format!("{MLDSA65_SEAL_PREFIX}!!!not-base64"),
            format!("{MLDSA65_SEAL_PREFIX}{}", STANDARD.encode(b"short")),
        ] {
            assert!(!s.check(KEY, VALUE, &seal).unwrap(), "{seal}");
        }
    }

    #[test]
    fn check_without_public_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let seal = sealer(dir.path()).seal(KEY, VALUE).unwrap();
        let other = tempfile::tempdir().unwrap();
        let msg = err_text(sealer(other.path()).check(KEY, VALUE, &seal));
        assert!(msg.contains(VERIFYING_KEY_FILE_NAME), "{msg}");
    }

    #[test]
    fn corrupt_public_key_fails_check_closed() {
        let dir = tempfile::tempdir().unwrap();
        let seal = sealer(dir.path()).seal(KEY, VALUE).unwrap();
        std::fs::write(dir.path().join(VERIFYING_KEY_FILE_NAME), b"bad")
            .unwrap();
        let msg = err_text(sealer(dir.path()).check(KEY, VALUE, &seal));
        assert!(msg.contains(VERIFYING_KEY_FILE_NAME), "{msg}");
    }

    #[test]
    fn corrupt_signing_key_fails_seal_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SIGNING_KEY_FILE_NAME), b"short")
            .unwrap();
        let msg = err_text(sealer(dir.path()).seal(KEY, VALUE));
        assert!(msg.contains(SIGNING_KEY_FILE_NAME), "{msg}");
    }

    #[test]
    fn missing_signing_key_with_public_key_fails_seal_closed() {
        let dir = tempfile::tempdir().unwrap();
        sealer(dir.path()).seal(KEY, VALUE).unwrap();
        std::fs::remove_file(dir.path().join(SIGNING_KEY_FILE_NAME)).unwrap();
        let s = sealer(dir.path());
        let msg = err_text(s.seal(KEY, VALUE));
        assert!(msg.contains(SIGNING_KEY_FILE_NAME), "{msg}");
        assert!(!s.signing_key_path().exists(), "must not rotate keys");
    }

    #[test]
    fn public_key_not_matching_signing_key_fails_seal_closed() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        sealer(a.path()).seal(KEY, VALUE).unwrap();
        sealer(b.path()).seal(KEY, VALUE).unwrap();
        std::fs::copy(
            b.path().join(VERIFYING_KEY_FILE_NAME),
            a.path().join(VERIFYING_KEY_FILE_NAME),
        )
        .unwrap();
        let msg = err_text(sealer(a.path()).seal(KEY, VALUE));
        assert!(msg.contains(VERIFYING_KEY_FILE_NAME), "{msg}");
    }

    #[test]
    fn missing_public_key_is_restored_from_signing_key() {
        let dir = tempfile::tempdir().unwrap();
        let seal = sealer(dir.path()).seal(KEY, VALUE).unwrap();
        let public = dir.path().join(VERIFYING_KEY_FILE_NAME);
        let original = std::fs::read(&public).unwrap();
        std::fs::remove_file(&public).unwrap();
        let s = sealer(dir.path());
        s.seal("k2", "v2").unwrap();
        assert_eq!(std::fs::read(&public).unwrap(), original);
        assert!(s.check(KEY, VALUE, &seal).unwrap());
    }

    #[test]
    fn unwritable_cache_dir_fails_seal_closed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"").unwrap();
        let s = MlDsa65Sealer::for_cache_db(&file.join("vlz-cache.redb"));
        assert!(s.seal(KEY, VALUE).is_err());
    }

    #[test]
    fn losing_keygen_race_adopts_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let winner = sealer(dir.path());
        let seal = winner.seal(KEY, VALUE).unwrap();
        let loser = sealer(dir.path());
        let adopted = loser.create_signing_key().unwrap();
        assert_eq!(
            adopted.to_seed().as_slice(),
            std::fs::read(winner.signing_key_path()).unwrap()
        );
        assert!(loser.check(KEY, VALUE, &seal).unwrap());
    }

    #[test]
    fn unreadable_public_key_fails_seal_closed() {
        let dir = tempfile::tempdir().unwrap();
        sealer(dir.path()).seal(KEY, VALUE).unwrap();
        let public = dir.path().join(VERIFYING_KEY_FILE_NAME);
        std::fs::remove_file(&public).unwrap();
        std::fs::create_dir(&public).unwrap();
        let msg = err_text(sealer(dir.path()).seal(KEY, VALUE));
        assert!(msg.contains(VERIFYING_KEY_FILE_NAME), "{msg}");
    }

    #[test]
    fn label_is_fips204() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(sealer(dir.path()).label(), crate::INTEGRITY_LABEL_FIPS204);
    }
}
