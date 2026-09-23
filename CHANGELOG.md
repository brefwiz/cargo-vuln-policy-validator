# Changelog

## [Unreleased]

## [0.1.1] - 2026-09-23

### Added

- Scratch OCI image (`Dockerfile`) that ships only the validator binary for
  ci-internal to COPY, instead of compiling from git on every rebake.

### Fixed

- An expired exception in the shared allowlist now fails a consumer only
  when the advisory it covers actually affects that consumer's own
  Cargo.lock (checked via the `rustsec` advisory database), instead of
  failing every consumer whose shared/central ignore list merely mentions
  the id. RUSTSEC-2026-0173 previously failed consumers like
  otel-bootstrap that depend on neither `validator` nor
  `proc-macro-error2`.
- This repo's own CI security job now builds and runs the validator from
  the PR's checked-out source instead of the binary baked into
  `ghcr.io/brefwiz/ci:latest`, so a fix here is actually exercised by its
  own PR.

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
