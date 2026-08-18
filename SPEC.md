---
service: cargo-vuln-policy-validator
wire_surface: utoipa-legacy
surface_kind: library
sdk_languages: []
capability_exposes: []
capability_consumes: []
ci_snowflakes:
  - clippy
  - test
  - audit
  - deny
  - cargo-package
migration_baseline:
  utoipa_handler_count: 0
canonical_exempt:
  - check: release-coverage
    reason: >-
      CLI crate; the published artifact is a scratch OCI image plus the
      crates.io/cargo package, not a Helm chart or service runtime
---

# cargo-vuln-policy-validator

CLI that checks cargo-audit / cargo-deny ignore lists against a reviewed
exception policy. No HTTP surface. `wire_surface: utoipa-legacy` with
count 0 satisfies the L1 gate.
