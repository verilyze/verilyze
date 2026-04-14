<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Installing verilyze (vlz)

Pre-built binaries, [crates.io](https://crates.io/) packages, public container
registry images, and third-party distro packages are **not published yet**.
Install by building from this repository (or from packages you build locally
with the Makefile targets below).

For development setup (venvs, `make check`, fuzz, coverage), see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Recommended: `make release`

From a clone of the repository root, with [Rust](https://rustup.rs/) and
**GNU Make 4+** available:

```bash
make release
```

This runs `check-headers` then `cargo build --release`. The binary is
`target/release/vlz` (or under your `CARGO_TARGET_DIR` if set). Run it by path
or add the directory to `PATH`:

```bash
./target/release/vlz --version
```

The release profile uses a stripped binary (PRD NFR-023).

### Build troubleshooting: missing linker on first compile

If the first `make debug`, `make release`, or `cargo build` warns that a linker
is missing, install a system C toolchain and linker. Preferred for this project:
**`gcc` + GNU `ld` (`ld.bfd`)**.

Typical installs:

```bash
# Debian/Ubuntu
sudo apt install build-essential gcc binutils

# Fedora
sudo dnf install gcc binutils

# openSUSE
sudo zypper install gcc binutils
```

Local linker defaults are overridable per command, for example:
`CC=clang RUSTFLAGS="-Clink-arg=-fuse-ld=lld" make debug`.

For contributor-oriented setup details and coverage fallback guidance, see
[CONTRIBUTING.md](CONTRIBUTING.md#quick-setup).

## `make install` (prefix layout)

Installs the release binary, `verilyze.conf.example`, man pages, and shell
completions under `PREFIX` (default `/usr/local`). Use `DESTDIR` for staged or
packaging installs.

```bash
sudo make install
# or: make install PREFIX=$HOME/.local DESTDIR=
```

See the [`install` target in the Makefile](Makefile) for exact paths (bash,
zsh, fish completions; `man/vlz.1`, `man/verilyze.conf.5`). If `/etc/verilyze.conf`
does not exist, a direct install (no `DESTDIR`) may copy the example there when
run as root.

## Cargo install from a clone

Installs `vlz` into Cargo’s global binary directory (e.g. `~/.cargo/bin`):

```bash
cargo install --path crates/core/vlz --locked
```

Use `--features nvd` (and optional provider features) if you need providers
beyond the default OSV client. See [docs/FAQ.md](docs/FAQ.md) for NVD rate
limits and binary size.

## Cargo build without the Makefile

If you do not use `make release`:

```bash
cargo build --release -p vlz
```

This skips the Makefile’s `check-headers` step. Prefer `make release` for a
normal clone workflow.

## HTTP proxy for CVE providers (OP-018)

Online CVE provider traffic uses the same industry-standard variables as many
other tools (curl-style rules via the bundled HTTP stack):

- **ALL_PROXY** / **all_proxy** -- default proxy when a scheme-specific
  variable is unset.
- **HTTP_PROXY** / **http_proxy** -- proxy for `http:` URLs.
- **HTTPS_PROXY** / **https_proxy** -- proxy for `https:` URLs (CVE providers
  use HTTPS).
- **NO_PROXY** / **no_proxy** -- comma-separated hosts, domains, or CIDRs that
  bypass the proxy. Suffix matching applies (for example, `example.com` matches
  `api.example.com`).

When **both** the uppercase and lowercase form of a pair are set and the values
differ (after trimming spaces and tabs at each end), `vlz` prints **one**
warning per run to **stderr**, names the pair, and states that the **uppercase**
value wins for this program. Values are never printed (they may contain proxy
credentials). Keep both forms identical if your environment defines both, so
other tools agree with `vlz`.

On **macOS** and **Windows**, **system** HTTP proxy settings are used when the
variables above leave a scheme without a proxy. On **Linux**, only these
environment variables apply for this mechanism. **SOCKS** URLs in these
variables are not supported in this release.

TLS verification for HTTPS stays on (SEC-002). Corporate TLS inspection may
require trusting your organization’s CA in the OS store; see
[SECURITY.md](SECURITY.md).

## Optional CVE providers (NVD)

The default build includes OSV. For NVD:

```bash
cargo build --release -p vlz --features nvd
# or: cargo install --path crates/core/vlz --locked --features nvd
./target/release/vlz scan --provider nvd
```

## Packaging from this tree (OP-013)

All commands below assume the repository root as the current working directory.

### Debian (`.deb`)

Requires [cargo-deb](https://github.com/kornelski/cargo-deb) (`cargo install cargo-deb`).

```bash
make deb
```

Produces a `.deb` under `target/debian/` (filename includes version and
architecture). Install with `sudo apt install ./target/debian/vlz_*.deb` or
equivalent.

### RPM (`.rpm`)

Requires `rpmbuild` (e.g. `rpm-build` on Fedora/openSUSE). **Commit all
changes** before building; the spec uses `git archive`.

```bash
make rpm
```

Packages appear under `packaging/rpm/RPMS/<arch>/` (for example
`verilyze-<version>-1.<dist>.<arch>.rpm`). Install examples:

```bash
sudo zypper in packaging/rpm/RPMS/*/verilyze-*.rpm
# or: sudo dnf install packaging/rpm/RPMS/*/verilyze-*.rpm
```

Use `ls packaging/rpm/RPMS/*/` to pick the exact file name.

### Arch Linux (AUR artifacts)

Requires **cargo-aur** (`cargo install cargo-aur`; see [crates.io/crates/cargo-aur](https://crates.io/crates/cargo-aur)).

```bash
make aur
```

`cargo aur` writes the PKGBUILD and source tarball under `target/` (see its
output). There is also a reference [packaging/arch/PKGBUILD](packaging/arch/PKGBUILD)
in the tree.

### Alpine APK

Requires an Alpine build environment (`abuild`, `alpine-sdk`). Regenerates
packaging metadata, then builds in `packaging/alpine`:

```bash
make apk
```

Run inside Alpine (container or chroot) as documented for your distro.

### Container image

There is **no pre-published** image. Build locally:

```bash
make docker
```

This tags `verilyze:<version>` and `verilyze:latest` (see root `Cargo.toml`
version). Equivalent:

```bash
docker build -f packaging/docker/Dockerfile -t verilyze .
```

Scan a project by mounting it:

```bash
docker run --rm -v "$(pwd)":/scan verilyze:latest scan /scan
```

On SELinux systems (Fedora, RHEL, CentOS), add `:z` to the volume so the
container can read the mounted files:

```bash
docker run --rm -v "$(pwd)":/scan:z verilyze:latest scan /scan
```

The image runs as UID **1000** with a writable home at **`/home/verilyze`**
(see [`packaging/docker/Dockerfile`](packaging/docker/Dockerfile)). Default
cache and ignore DB paths live under that tree and are **ephemeral** unless you
persist them with a volume or `--cache-db` / `VLZ_CACHE_DB`.

To reuse the CVE cache on the host, mount your cache directory over the default
location:

```bash
mkdir -p ~/.cache/verilyze
docker run --rm \
  -v "$(pwd)":/scan:z \
  -v "$HOME/.cache/verilyze":/home/verilyze/.cache/verilyze:z \
  verilyze:latest scan /scan
```

Or mount a host directory and set the cache file explicitly:

```bash
mkdir -p ~/.cache/verilyze
docker run --rm \
  -v "$(pwd)":/scan:z \
  -v "$HOME/.cache/verilyze":/cache:z \
  verilyze:latest scan /scan --cache-db /cache/vlz-cache.redb
```

Use `--user "$(id -u):$(id -g)"` when the process UID/GID must match the host
(for example, writing to a bind-mounted path where host ownership matters).

## Shell completion

After **`make install`**, completions are installed under `PREFIX` for Bash,
Zsh, and Fish (see the Makefile `install` target).

If you use a binary without `make install`, generate scripts with
`vlz generate-completions` and install them in the appropriate directory for
your shell:

**Bash:**
```bash
vlz generate-completions bash | sudo tee /usr/share/bash-completion/completions/vlz > /dev/null
# or for current user:
vlz generate-completions bash > ~/.local/share/bash-completion/completions/vlz
```

**Zsh:**
```bash
vlz generate-completions zsh > "${fpath[1]}/_vlz"
# or: vlz generate-completions zsh > ~/.zsh/site-functions/_vlz
```

**Fish:**
```bash
vlz generate-completions fish > ~/.config/fish/completions/vlz.fish
```
