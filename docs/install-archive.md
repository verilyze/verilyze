<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Installing verilyze from a release archive

This guide is included in the platform release archives published on GitHub.
Verify the archive **before** extraction using the checksums and Sigstore
bundles from the same GitHub Release (see the repository
[INSTALL.md](https://github.com/verilyze/verilyze/blob/main/INSTALL.md)).

Other install methods (`.deb`, RPM, container, Cargo, source build) are
documented in that same file.

## Layout

Unix archives (`*.tar.gz`) unpack a single directory:

```text
vlz-<version>-<platform>/
  INSTALL.md
  LICENSE
  THIRD-PARTY-LICENSES
  bin/vlz
  share/doc/verilyze/verilyze.conf.example
  share/man/man1/vlz.1
  share/man/man5/verilyze.conf.5
  share/bash-completion/completions/vlz
  share/zsh/site-functions/_vlz
  share/fish/vendor_completions.d/vlz.fish
```

Windows archives (`*.zip`) unpack:

```text
vlz-<version>-windows-x86_64/
  INSTALL.md
  LICENSE
  THIRD-PARTY-LICENSES
  vlz.exe
  verilyze.conf.example
```

The `bin/` and `share/` tree matches `make install` under `PREFIX`
(`/usr/local` by default). Package installs (`.deb` / RPM) use `/usr/bin/vlz`
and do not conflict with a `/usr/local` archive install. `/usr/local/bin`
normally precedes `/usr/bin` in `PATH`, so an archive install shadows a
package install when both are present.

## Extract

```bash
# Linux example
tar -xzf vlz-0.8.0-linux-x86_64.tar.gz
cd vlz-0.8.0-linux-x86_64
```

```powershell
# Windows example (PowerShell)
Expand-Archive .\vlz-0.8.0-windows-x86_64.zip -DestinationPath .
cd vlz-0.8.0-windows-x86_64
```

## Install (Unix)

Copy the relative prefix tree into `/usr/local` (system-wide) or `~/.local`
(per-user):

```bash
# System-wide (requires write access to /usr/local)
sudo cp -a bin share /usr/local/

# Or per-user
mkdir -p ~/.local
cp -a bin share ~/.local/
# Ensure ~/.local/bin is on PATH
```

Optional config:

```bash
sudo install -m 644 share/doc/verilyze/verilyze.conf.example /etc/verilyze.conf
# or: mkdir -p ~/.config && cp share/doc/verilyze/verilyze.conf.example ~/.config/verilyze.conf
```

Confirm:

```bash
vlz --version
man vlz
```

## Install (Windows)

Copy `vlz.exe` to a directory on your `PATH`, or invoke it by path. Keep
`verilyze.conf.example` nearby or copy it to your preferred config location
(see the repository INSTALL.md).

## Upgrade

Download and verify the new archive, extract it, and copy `bin` and `share`
over the previous install prefix (or replace `vlz.exe` on Windows).

## Remove

Delete the installed files under your chosen prefix (`/usr/local` or
`~/.local`), or remove `vlz.exe` on Windows. Also remove any config file you
created under `/etc` or `~/.config` if desired.
