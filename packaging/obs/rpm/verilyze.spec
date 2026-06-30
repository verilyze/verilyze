# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

%global crate_name vlz
%global pkg_name verilyze

Name:           %{pkg_name}
Version:        0.2.3
Release:        0%{?dist}
Summary:        Fast, modular Software Composition Analysis tool
License:        GPL-3.0-or-later
%if 0%{?suse_version}
Group:          Productivity/Security
%endif
URL:            https://github.com/verilyze/verilyze
Source0:        %{pkg_name}-%{version}.tar.xz
Source1:        vendor.tar.zst

BuildRequires:  cargo >= 1.78.0
BuildRequires:  rust >= 1.78.0
BuildRequires:  make
BuildRequires:  zstd

%if 0%{?suse_version}
BuildRequires:  libopenssl-devel
%endif
%if 0%{?fedora} || 0%{?rhel}
BuildRequires:  openssl-devel
%endif

%description
verilyze (vlz) is an open-source Software Composition Analysis (SCA) tool
written in Rust. It scans codebases for known vulnerable dependencies,
generates SBOMs, and supports multiple output formats. Designed to be fast,
accurate, modular, and CI-friendly.

%prep
%autosetup -n %{pkg_name}-%{version}
# Unpack OBS cargo_vendor tarball; it overlays .cargo, vendor/, and Cargo.lock.
tar --zstd -xf %{SOURCE1}

%build
export CARGO_TARGET_DIR="$PWD/target"
cargo build --release --locked --offline
mkdir -p completions
./target/release/%{crate_name} generate-completions bash > completions/vlz.bash
./target/release/%{crate_name} generate-completions zsh > completions/_vlz
./target/release/%{crate_name} generate-completions fish > completions/vlz.fish

%check
expected_version="%{version}"
set -- $(./target/release/%{crate_name} --version)
actual_version="$2"
[ "$actual_version" = "$expected_version" ]
./target/release/%{crate_name} --help >/dev/null

%install
install -D -m 0755 target/release/%{crate_name} \
    %{buildroot}%{_bindir}/%{crate_name}

install -D -m 0644 verilyze.conf.example \
    %{buildroot}%{_sysconfdir}/verilyze.conf

install -D -m 0644 verilyze.conf.example \
    %{buildroot}%{_docdir}/%{pkg_name}/verilyze.conf.example

install -D -m 0644 man/vlz.1 \
    %{buildroot}%{_mandir}/man1/vlz.1

install -D -m 0644 man/verilyze.conf.5 \
    %{buildroot}%{_mandir}/man5/verilyze.conf.5

install -D -m 0644 completions/vlz.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/vlz
install -D -m 0644 completions/_vlz \
    %{buildroot}%{_datadir}/zsh/site-functions/_vlz
install -D -m 0644 completions/vlz.fish \
    %{buildroot}%{_datadir}/fish/vendor_completions.d/vlz.fish

%files
%license LICENSES/GPL-3.0-or-later.txt
%license THIRD-PARTY-LICENSES
%doc README.md
%{_bindir}/%{crate_name}
%config(noreplace) %{_sysconfdir}/verilyze.conf
%{_docdir}/%{pkg_name}/verilyze.conf.example
%{_mandir}/man1/vlz.1*
%{_mandir}/man5/verilyze.conf.5*
%{_datadir}/bash-completion/completions/vlz
# Parent dirs for zsh and fish completions (OBS 50-check-filelist).
%dir %{_datadir}/zsh
%dir %{_datadir}/zsh/site-functions
%{_datadir}/zsh/site-functions/_vlz
%dir %{_datadir}/fish
%dir %{_datadir}/fish/vendor_completions.d
%{_datadir}/fish/vendor_completions.d/vlz.fish

%changelog
