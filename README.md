# super-duper (spd)

Fast, modular Software Composition Analysis (SCA) tool for dependency
vulnerabilities. Written in Rust.

**License:** SPDX-License-Identifier: GPL-3.0-or-later. See [COPYING](COPYING).

## Installation

```bash
cargo install spd
```

- **Privileged:** binary goes to `/usr/local/bin/` (or equivalent).
- **Non-privileged:** binary goes to `$HOME/.cargo/bin/`.

## Quick start

```bash
# Scan current directory for Python manifests (e.g. requirements.txt) and check
# for CVEs
spd scan

# Scan a specific path
spd scan /path/to/project

# JSON output
spd scan --format json

# List registered language plugins
spd list
```

## Configuration precedence

Options are resolved in order (highest wins):

1. **CLI flags** (e.g. `--parallel 20`, `--cache-ttl-secs 86400`, `--min-score 7.0`)
2. **Environment variables** `SPD_*` (e.g. `SPD_PARALLEL_QUERIES=20`,
   `SPD_CACHE_TTL_SECS=86400`)
3. **User config file** (`-c/--config <path>` or default
   `$XDG_CONFIG_HOME/super-duper/super-duper.conf`)
4. **System config** (`/etc/super-duper.conf`)

See [architecture/PRD.md](architecture/PRD.md) (CFG-001–CFG-008) for full details.

| Key | Default | Env var | CLI flag |
|-----|---------|---------|----------|
| cache_ttl_secs | 432000 (5 days) | SPD_CACHE_TTL_SECS | --cache-ttl-secs |
| parallel_queries | 10 | SPD_PARALLEL_QUERIES | --parallel |
| min_score | 0 | SPD_MIN_SCORE | --min-score |
| min_count | 0 | SPD_MIN_COUNT | --min-count |

Changing **cache_ttl_secs** only affects new cache entries; existing entries
keep their stored expiry until they expire or are purged.

Run `spd config --list` to print effective values.

## CLI reference (summary)

| Subcommand | Description |
|------------|-------------|
| `spd scan [PATH]` | Scan for manifests and CVEs; optional path (default: cwd) |
| `spd list` | List registered language plugins |
| `spd config --list` | Show effective configuration |
| `spd config --set KEY=VALUE` | Set a config key (e.g. `python.regex="^requirements\\.txt$"`) |
| `spd db list-providers` | List CVE providers (e.g. osv) |
| `spd db stats` | Cache statistics |
| `spd db show [--format FORMAT] [--full]` | Display cache entries (key, TTL, added-at, CVE summary or full payload) |
| `spd db set-ttl SECS [--entry KEY] [--all] [--pattern PATTERN] [--entries KEYS]` | Update TTL for existing cache entries |
| `spd db verify` | Verify database integrity (SHA-256) |
| `spd db migrate` | Run migrations |
| `spd fp mark CVE-ID [--comment ...]` | Mark CVE as false positive |
| `spd fp unmark CVE-ID` | Remove false-positive marking |
| `spd --version` | Print version |

**Scan options (examples):** `--format plain|json|sarif`,
`--summary-file html:path,json:path`, `--provider osv`, `--parallel N`,
`--cache-ttl-secs SECS`, `--offline`, `--benchmark`, `--min-score`,
`--min-count`, `--exit-code-on-cve`, `--fp-exit-code`, `--cache-db`,
`--ignore-db`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (no CVEs, or only false-positives when using default fp-exit-code) |
| 1 | Panic / internal error |
| 2 | Misconfiguration (unknown key, invalid value, etc.) |
| 3 | Missing required package manager |
| 4 | CVE lookup needed but `--offline` |
| 86 | One or more CVEs meet threshold (overridable via `--exit-code-on-cve`) |

## Documentation

- **Requirements and architecture:** [architecture/PRD.md](architecture/PRD.md)
- **Execution flow:** [architecture/execution-flow.mmd](architecture/execution-flow.mmd)
- **FAQ and troubleshooting:** [docs/FAQ.md](docs/FAQ.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)
- **Security:** [SECURITY.md](SECURITY.md)
