<!--
SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>

SPDX-License-Identifier: GPL-3.0-or-later
-->

# Ecosystem capabilities

Readable view of language coverage for scanners and remediators. Canonical
sources:

- Manifest and lock formats: [architecture/PRD.md](../architecture/PRD.md)
  Appendix A
- Remediator strategies: `crates/core/vlz-remediate` registry

When you add a language plugin, update **both** Appendix A and this matrix
(see CONTRIBUTING "Adding a new language plugin").

## Matrix

Default `reachability_mode` is `best-available` (Tier B + Tier C where
supported). Tier D is on by default for Python, Go, and JavaScript; Rust
Tier D is opt-in (`rust-tier-d`). Reachability never suppresses findings by
default.

| Ecosystem | Manifests (summary) | Preferred locks | Lock-less default | Reachability | `vlz fix` apply |
|-----------|---------------------|-----------------|-------------------|--------------|-----------------|
| Python | `requirements*.txt`, `pyproject.toml`, `Pipfile`, `setup.cfg`, `setup.py` | `pylock.toml` / `pylock.<name>.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `pdm.lock` | Exit **4** (safe `pip lock -r` may help `requirements.txt` only) | Tier B/C; Tier D on by default | poetry / uv locks; **pylock apply unavailable** |
| Rust | `Cargo.toml` | `Cargo.lock` | May run `cargo metadata` when `cargo` is on PATH | Tier B/C; Tier D opt-in | Yes (`cargo`) |
| Go | `go.mod` | `go.sum` | May run `go list` when `go` is on PATH | Tier B/C; Tier D on by default | Yes (`go`) |
| JavaScript / TypeScript | `package.json` | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` (text; `bun.lockb` out of scope) | Exit **4** | Tier B/C; Tier D on by default | npm / yarn / pnpm / bun |
| Java / Kotlin | `pom.xml`, `build.gradle(.kts)`, version catalogs | `gradle.lockfile` (Maven has no standard lock) | Exit **4** | Tier B/C (`.java` / `.kt`); Tier D planned (W4-2) | gradle / maven (gradle apply needs SEC-023 gate) |
| Ruby | `Gemfile`, `gems.rb`, `*.gemspec` | `Gemfile.lock`, `gems.locked` | Exit **4** | Tier B/C; Tier D planned (W4-2) | bundler (needs SEC-023 gate; no transitive apply) |
| PHP | `composer.json` | `composer.lock` | Exit **4** | Tier B/C; Tier D planned (W4-2) | **No remediator** (scan only; W4-1) |
| .NET | `*.csproj` / `*.fsproj` / `*.vbproj`, `packages.config` | `packages.lock.json`, then `project.assets.json` / `*.deps.json` | Exit **4** | Tier B/C (`.cs` / `.fs`); Tier D planned (W4-2) | **No remediator** (scan only; W4-1) |
| SBOM | CycloneDX 1.x / SPDX 2.2--3.0 JSON | n/a (pre-resolved) | n/a | n/a | Dry-run only; never apply |

## Notes

- **Fail closed:** For ecosystems marked exit 4, commit a usable lock (or use
  an explicit opt-in such as `--allow-direct-only-fallback` /
  `--allow-dependency-code-execution`) before expecting CI green.
- **SBOM / VEX:** Scan export supports CycloneDX 1.6, SPDX 3.0, and OpenVEX.
  Import via `--from-sbom` or discovered allowlisted names. VEX consume uses
  `--from-vex` (see FAQ).
- **Roadmap:** Matching transparency, suppression expiry, and remediator
  gaps are tracked in [ROADMAP.md](ROADMAP.md).
