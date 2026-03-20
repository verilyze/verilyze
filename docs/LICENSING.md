<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Licensing and Third-Party Attribution

## License count vs component count

The number of unique licenses in THIRD-PARTY-LICENSES is typically less than
the number of components (dependencies). This is intentional and correct.

`cargo-about` groups crates by unique license text. Many crates share the same
license (e.g., MIT, Apache-2.0). Each distinct license text appears once in
the LICENSE TEXTS section. Every dependency is listed in the COMPONENTS
section with its license expression. Deduplication avoids repeating the same
license text many times.

## cargo-deny allow list vs GPL compatibility

`deny.toml` `[licenses] allow` and per-crate **exceptions** mean **automated
`cargo deny check licenses`** accepts the dependency’s declared SPDX here. That
is **not** a legal conclusion that combining that dependency with
**GPL-3.0-or-later** code is always permissible. Use organizational legal review
where it matters, as noted in **SECURITY.md**.

## Single source of truth: deny.toml

The project uses `deny.toml` as the canonical source for allowed licenses.
`about.toml` (used by cargo-about for THIRD-PARTY-LICENSES generation) is kept
in sync via `make sync-license-config`.

**When adding a license:** Edit deny.toml only. Add the license to
`[licenses] allow = [...]`. Then run `make sync-license-config` to update
about.toml. The sync runs automatically as the first step of
`make generate-third-party-licenses`.

## Make targets

| Target                               | Purpose                                                |
|--------------------------------------|--------------------------------------------------------|
| `make sync-license-config`           | Copy deny.toml [licenses] allow to about.toml accepted |
| `make check-license-config`          | Fail if about.toml is out of sync with deny.toml       |
| `make generate-third-party-licenses` | Generate THIRD-PARTY-LICENSES (syncs first)            |
| `make check-third-party-licenses`    | Regenerate and fail if file differs from committed     |

`make check` includes both `check-license-config` and `check-third-party-licenses`.

## THIRD-PARTY-LICENSES

THIRD-PARTY-LICENSES is committed to the repository. Packaging (Docker, RPM,
DEB, etc.) uses the committed file instead of generating at build time. When
dependencies change, run `make generate-third-party-licenses` and commit the
updated file. CI fails if the file is out of sync.
