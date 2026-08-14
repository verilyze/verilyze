// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_manifest_parser::{Parser, ResolutionDepth, ResolveContext, Resolver};
use vlz_ruby::{RubyManifestParser, RubyResolver};

#[tokio::test]
async fn paired_lock_resolves_transitively_even_offline() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("Gemfile");
    std::fs::write(&manifest, include_str!("fixtures/Gemfile.fixture"))
        .unwrap();
    std::fs::write(
        dir.path().join("Gemfile.lock"),
        include_str!("fixtures/Gemfile.lock.fixture"),
    )
    .unwrap();

    let graph = RubyManifestParser::new().parse(&manifest).await.unwrap();
    let result = RubyResolver::new()
        .resolve(
            &graph,
            &ResolveContext {
                skip_pip_resolution: true,
                scan_root: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.depth, ResolutionDepth::Transitive);
    assert!(result.packages.iter().any(|p| p.name == "rails"));
}

#[tokio::test]
async fn gems_rb_uses_gems_locked() {
    let dir = tempfile::tempdir().unwrap();
    let manifest = dir.path().join("gems.rb");
    std::fs::write(&manifest, "gem 'rack'\n").unwrap();
    std::fs::write(
        dir.path().join("gems.locked"),
        "GEM\n  specs:\n    rack (2.2.8)\n",
    )
    .unwrap();
    let graph = RubyManifestParser::new().parse(&manifest).await.unwrap();
    let result = RubyResolver::new()
        .resolve(
            &graph,
            &ResolveContext {
                skip_pip_resolution: true,
                scan_root: Some(dir.path().to_path_buf()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(result.depth, ResolutionDepth::Transitive);
    assert!(
        result
            .packages
            .iter()
            .any(|p| p.name == "rack" && p.version == "2.2.8")
    );
}

#[test]
fn pair_matching_never_unions_lock_names() {
    let dir = tempfile::tempdir().unwrap();
    let gemfile = dir.path().join("Gemfile");
    std::fs::write(&gemfile, "").unwrap();
    std::fs::write(dir.path().join("gems.locked"), "GEM\n").unwrap();
    assert!(
        vlz_ruby::find_ruby_lock_file(&gemfile, Some(dir.path())).is_none()
    );
}
