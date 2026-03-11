# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

# Minimal ebuild for reference. Gentoo maintainers or overlay developers
# should regenerate the CRATES variable using pycargoebuild or cargo-ebuild
# each time Cargo.lock changes. This file is manually maintained and has no
# automated Makefile target.

EAPI=8

inherit cargo

DESCRIPTION="Fast, modular Software Composition Analysis tool"
HOMEPAGE="https://github.com/tpost/verilyze"
SRC_URI="https://github.com/tpost/verilyze/archive/v${PV}.tar.gz -> ${P}.tar.gz"
# Regenerate with: pycargoebuild -i ${P}.tar.gz
# or: cargo-ebuild ebuild
SRC_URI+=" $(cargo_crate_uris)"

LICENSE="GPL-3.0-or-later"
# Include all dependency licenses here; audit with cargo-license.
LICENSE+=" Apache-2.0 MIT"
SLOT="0"
KEYWORDS="~amd64"

# Regenerate CRATES from Cargo.lock:
#   pycargoebuild -i verilyze-${PV}.tar.gz
# Paste output below.
CRATES=""

DEPEND="dev-lang/rust"
RDEPEND=""
BDEPEND="virtual/rust"

src_compile() {
	cargo_src_compile
	./scripts/generate_completions.sh ./target/release/vlz
}

src_install() {
	dobin target/release/vlz

	insinto /etc
	newins verilyze.conf.example verilyze.conf

	dodoc verilyze.conf.example

	doman man/vlz.1 man/verilyze.conf.5

	insinto /usr/share/bash-completion/completions
	newins completions/vlz.bash vlz
	insinto /usr/share/zsh/site-functions
	doins completions/_vlz
	insinto /usr/share/fish/vendor_completions.d
	doins completions/vlz.fish
}

src_test() {
	cargo_src_test
}
