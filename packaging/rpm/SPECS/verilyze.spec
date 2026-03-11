# SPDX-FileCopyrightText: 2026 Travis Post <post.travis+git@gmail.com>
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
URL:            https://github.com/tpost/verilyze
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
cargo build --release --locked

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

%files
%license LICENSES/GPL-3.0-or-later.txt
%doc README.md
%{_bindir}/%{crate_name}
%config(noreplace) %{_sysconfdir}/verilyze.conf
%{_docdir}/%{pkg_name}/verilyze.conf.example
%{_mandir}/man1/vlz.1*
%{_mandir}/man5/verilyze.conf.5*

%changelog
