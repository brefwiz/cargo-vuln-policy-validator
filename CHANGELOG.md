# Changelog

## [Unreleased]

## [0.1.0] - 2026-04-22

### Added

- Initial release of `cargo-vuln-policy-validator`
- Validation for TOML ignore entries missing from the YAML allowlist
- Validation for expired `review_by` exception dates
- Validation for missing required exception metadata
- Source-aware validation output that points to the exact file, line, and
  column to edit in `audit.toml`, `deny.toml`, or the exception YAML file
- CLI integration tests covering zero exit on success and non-zero exit on
  policy violations
- Standard open source packaging files: `README.md`, `CHANGELOG.md`,
  `CODE_OF_CONDUCT.md`, and MIT `LICENSE`

### Changed

- Validation now reports field-specific exception metadata failures instead of a
  single generic "missing required fields" result
- TOML ignore parsing now handles Unicode comments and richer inline-table
  entries without crashing
