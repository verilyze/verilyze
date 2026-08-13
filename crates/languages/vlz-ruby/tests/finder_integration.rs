// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_manifest_finder::ManifestFinder;
use vlz_ruby::RubyManifestFinder;

#[tokio::test]
async fn finds_ruby_manifests_but_not_locks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Gemfile"), "gem 'rack'\n").unwrap();
    std::fs::write(dir.path().join("gems.rb"), "gem 'rails'\n").unwrap();
    std::fs::write(
        dir.path().join("demo.gemspec"),
        "Gem::Specification.new\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("Gemfile.lock"), "GEM\n").unwrap();

    let found = RubyManifestFinder::new().find(dir.path()).await.unwrap();
    assert_eq!(found.len(), 3);
    assert!(found.iter().all(|path| !path.ends_with("Gemfile.lock")));
}

#[tokio::test]
async fn custom_patterns_filter_manifests() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("Gemfile"), "gem 'rack'\n").unwrap();
    std::fs::write(dir.path().join("gems.rb"), "gem 'rails'\n").unwrap();
    let finder =
        RubyManifestFinder::with_patterns(vec![r"^Gemfile$".into()]).unwrap();
    let found = finder.find(dir.path()).await.unwrap();
    assert_eq!(found.len(), 1);
    assert!(found[0].ends_with("Gemfile"));
}
