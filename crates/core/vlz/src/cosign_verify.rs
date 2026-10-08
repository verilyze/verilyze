// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Optional cosign verify-blob helper (W4-3 / W4-4).
//!
//! Thin wrapper over [`vlz_db::verify_cosign_blob`] so the binary and report
//! crates share one allowlisted spawn path.

use std::path::{Path, PathBuf};

pub use vlz_db::{
    COSIGN_BIN_NAME, COSIGN_BUNDLE_SUFFIX, sibling_cosign_bundle,
};

/// Error from optional cosign verification.
#[derive(Debug, thiserror::Error)]
pub enum CosignVerifyError {
    #[error(
        "cosign not found on PATH; install cosign or omit --cosign-bundle"
    )]
    CosignMissing,
    #[error("cosign bundle not found: {0}")]
    BundleMissing(String),
    #[error("cosign verify-blob failed for {}: {detail}", .path.display())]
    VerifyFailed { path: PathBuf, detail: String },
}

impl From<vlz_db::CorpusImportError> for CosignVerifyError {
    fn from(err: vlz_db::CorpusImportError) -> Self {
        match err {
            vlz_db::CorpusImportError::CosignMissing => Self::CosignMissing,
            vlz_db::CorpusImportError::CosignBundleMissing(p) => {
                Self::BundleMissing(p)
            }
            vlz_db::CorpusImportError::CosignVerifyFailed(detail) => {
                Self::VerifyFailed {
                    path: PathBuf::new(),
                    detail,
                }
            }
            other => Self::VerifyFailed {
                path: PathBuf::new(),
                detail: other.to_string(),
            },
        }
    }
}

/// Run `cosign verify-blob --bundle BUNDLE PATH` (fail closed).
pub fn verify_blob_with_bundle(
    blob_path: &Path,
    bundle_path: &Path,
) -> Result<(), CosignVerifyError> {
    vlz_db::verify_cosign_blob(blob_path, bundle_path).map_err(|err| {
        let mut mapped = CosignVerifyError::from(err);
        if let CosignVerifyError::VerifyFailed { path, .. } = &mut mapped {
            *path = blob_path.to_path_buf();
        }
        mapped
    })
}

/// Resolve an explicit bundle path or the sibling `{path}.sigstore.json`.
pub fn resolve_cosign_bundle(
    blob_path: &Path,
    explicit: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(p.to_path_buf());
    }
    let sibling = sibling_cosign_bundle(blob_path);
    if sibling.is_file() {
        Some(sibling)
    } else {
        None
    }
}

/// Verify when a bundle is available; `Ok(true)` on success, `Ok(false)` when
/// no bundle is present, `Err` when a bundle was required/found but verify
/// failed or cosign is missing.
pub fn try_verify_blob(
    blob_path: &Path,
    explicit_bundle: Option<&Path>,
) -> Result<bool, CosignVerifyError> {
    let Some(bundle) = resolve_cosign_bundle(blob_path, explicit_bundle)
    else {
        return Ok(false);
    };
    verify_blob_with_bundle(blob_path, &bundle)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cosign_or_bundle_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let blob = dir.path().join("doc.json");
        let bundle = dir.path().join("doc.sigstore.json");
        std::fs::write(&blob, b"{}").unwrap();
        std::fs::write(&bundle, b"{}").unwrap();
        let err = verify_blob_with_bundle(&blob, &bundle).unwrap_err();
        match err {
            CosignVerifyError::CosignMissing
            | CosignVerifyError::VerifyFailed { .. }
            | CosignVerifyError::BundleMissing(_) => {}
        }
    }

    #[test]
    fn resolve_prefers_explicit_then_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let blob = dir.path().join("vex.json");
        std::fs::write(&blob, b"{}").unwrap();
        assert!(resolve_cosign_bundle(&blob, None).is_none());
        let sib = sibling_cosign_bundle(&blob);
        std::fs::write(&sib, b"{}").unwrap();
        assert_eq!(
            resolve_cosign_bundle(&blob, None).as_deref(),
            Some(sib.as_path())
        );
        let other = dir.path().join("other.sigstore.json");
        assert_eq!(
            resolve_cosign_bundle(&blob, Some(&other)).as_deref(),
            Some(other.as_path())
        );
    }

    #[test]
    fn from_maps_all_corpus_import_cosign_variants() {
        assert!(matches!(
            CosignVerifyError::from(vlz_db::CorpusImportError::CosignMissing),
            CosignVerifyError::CosignMissing
        ));
        assert!(matches!(
            CosignVerifyError::from(
                vlz_db::CorpusImportError::CosignBundleMissing(
                    "/missing.bundle".into()
                )
            ),
            CosignVerifyError::BundleMissing(p) if p == "/missing.bundle"
        ));
        match CosignVerifyError::from(
            vlz_db::CorpusImportError::CosignVerifyFailed("bad sig".into()),
        ) {
            CosignVerifyError::VerifyFailed { detail, .. } => {
                assert_eq!(detail, "bad sig");
            }
            other => panic!("unexpected {other:?}"),
        }
        match CosignVerifyError::from(vlz_db::CorpusImportError::Parse(
            "oops".into(),
        )) {
            CosignVerifyError::VerifyFailed { detail, .. } => {
                assert!(detail.contains("oops"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn try_verify_blob_skips_without_bundle_and_fails_with_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let blob = dir.path().join("vex.json");
        std::fs::write(&blob, b"{}").unwrap();
        assert!(!try_verify_blob(&blob, None).unwrap());

        let bundle = dir.path().join("forced.sigstore.json");
        std::fs::write(&bundle, b"{}").unwrap();
        let err = try_verify_blob(&blob, Some(&bundle)).unwrap_err();
        match err {
            CosignVerifyError::CosignMissing
            | CosignVerifyError::VerifyFailed { .. }
            | CosignVerifyError::BundleMissing(_) => {}
        }
    }
}
