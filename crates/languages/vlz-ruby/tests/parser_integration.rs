// SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
//
// SPDX-License-Identifier: GPL-3.0-or-later

use vlz_ruby::{
    RUBYGEMS_ECOSYSTEM, parse_gemfile, parse_gemfile_lock, parse_gemspec,
};

#[test]
fn parses_fixture_manifests_and_lock() {
    let gemfile = include_str!("fixtures/Gemfile");
    let gemspec = include_str!("fixtures/example.gemspec");
    let lock = include_str!("fixtures/Gemfile.lock");

    let direct = parse_gemfile(gemfile).unwrap();
    assert!(direct.iter().any(|p| p.name == "rack"));
    assert!(!direct.iter().any(|p| p.name == "local-gem"));
    assert!(!direct.iter().any(|p| p.name == "git-gem"));

    let spec = parse_gemspec(gemspec).unwrap();
    assert!(spec.iter().any(|p| p.name == "rspec"));

    let locked = parse_gemfile_lock(lock).unwrap();
    assert!(
        locked
            .iter()
            .any(|p| p.name == "rails" && p.version == "7.0.4")
    );
    assert!(!locked.iter().any(|p| p.name == "local-gem"));
    assert!(
        locked
            .iter()
            .all(|p| p.ecosystem.as_deref() == Some(RUBYGEMS_ECOSYSTEM))
    );
}

#[test]
fn fixture_gemfile_skips_path_and_github() {
    let gemfile = include_str!("fixtures/Gemfile");
    let packages = parse_gemfile(gemfile).unwrap();
    assert!(packages.iter().any(|p| p.name == "rails"));
    assert!(
        !packages
            .iter()
            .any(|p| { p.name == "local-gem" || p.name == "git-gem" })
    );
}
