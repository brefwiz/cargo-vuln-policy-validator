# cargo-vuln-policy-validator

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)

`cargo-vuln-policy-validator` checks that vulnerability ignore entries declared in
`cargo audit` and `cargo deny` configuration files are backed by reviewed
exception records in a YAML allowlist.

Ignoring a RustSec advisory is sometimes necessary. What breaks down is the
process around it: one team adds an ignore to `audit.toml`, another adds a
different one to `deny.toml`, and the exception record either never gets added
or quietly expires months later. The tooling tells you that an advisory is
ignored, but not whether the ignore is still justified or documented.

**cargo-vuln-policy-validator is the policy check for that gap.** It compares
your TOML ignore lists against a reviewed exception file and fails the build
when an ignore entry is missing approval, has stale review metadata, or is
missing required review fields. Violations point to the exact file, line, and
column to edit.

## What It Validates

- Every ignored advisory in TOML exists in the YAML exception file.
- Every exception has a non-expired `review_by` date.
- Every exception includes the required review metadata fields.
- Violations report the exact file, line, and column to edit.

## Who This Is For

- Security-conscious Rust teams using `cargo audit` and `cargo deny`
- Repositories that want reviewed, time-bounded exceptions instead of permanent
  ignore entries
- CI pipelines that should fail when vulnerability exceptions drift out of
  policy

## Usage

```bash
cargo run -- audit.toml deny.toml exceptions.yaml
```

The command exits non-zero when policy violations are found.

## Input Format

### Exception file

```yaml
exceptions:
  - id: RUSTSEC-2024-0001
    owner: team-security
    review_by: 2099-01-01
    reason: temporary exception
    risk: known
    impact: low
    tracking: SEC-123
    resolution: upgrade planned
```

### `cargo audit` / `cargo deny` ignore entries

Simple string entries and inline-table entries are both supported:

```toml
[advisories]
ignore = [
  "RUSTSEC-2024-0001",
  { id = "RUSTSEC-2024-0002" }
]
```

## Output

Violations point to the exact input location that needs attention:

```text
❌ Policy validation failed:

 - RUSTSEC-2024-9999: ignore present in advisories.ignore but missing from allowlist
   ↳ deny.toml:14:5
   ↳ Edit this ignore entry or add a matching exception record.

 - RUSTSEC-2024-0001: required field 'owner' is blank
   ↳ exceptions.yaml:8:12
   ↳ Update the 'owner' field in this exception record.
```

## Current Scope

- Validates one YAML exception file against two TOML config files
- Reports human-readable violations to stdout
- Uses exact source locations for normal `audit.toml`, `deny.toml`, and
  exception YAML layouts

## License

MIT. See [LICENSE](LICENSE).
