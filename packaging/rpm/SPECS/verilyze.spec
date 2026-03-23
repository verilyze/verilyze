# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

%global crate_name vlz
%global pkg_name verilyze
%{!?version:%global version 0.1.0}

Name:           %{pkg_name}
Version:        %{version}
Release:        1%{?dist}
Summary:        Fast, modular Software Composition Analysis tool
License:        GPL-3.0-or-later
URL:            https://github.com/verilyze/verilyze
Source0:        %{pkg_name}-%{version}.tar.gz

BuildRequires:  cargo >= 1.78.0
BuildRequires:  rust >= 1.78.0
BuildRequires:  make

%if 0%{?suse_version}
BuildRequires:  libopenssl-devel
%else
BuildRequires:  openssl-devel
%endif

%description
verilyze (vlz) is an open-source Software Composition Analysis (SCA) tool
written in Rust. It scans codebases for known vulnerable dependencies,
generates SBOMs, and supports multiple output formats. Designed to be fast,
accurate, modular, and CI-friendly.

%prep
%autosetup -n %{pkg_name}-%{version}

%build
export CARGO_TARGET_DIR="$PWD/target"
cargo build --release --locked
mkdir -p completions
./target/release/%{crate_name} generate-completions bash > completions/vlz.bash
./target/release/%{crate_name} generate-completions zsh > completions/_vlz
./target/release/%{crate_name} generate-completions fish > completions/vlz.fish
# THIRD-PARTY-LICENSES is committed; see make generate-third-party-licenses

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
%{_datadir}/zsh/site-functions/_vlz
%{_datadir}/fish/vendor_completions.d/vlz.fish

%changelog
