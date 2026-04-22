# cargo-vuln-policy-validator

`cargo-vuln-policy-validator` checks that vulnerability ignore entries declared in
`cargo audit` and `cargo deny` config files are backed by reviewed exception
records in a YAML allowlist.

## What It Validates

- Every ignored advisory in TOML exists in the YAML exception file.
- Every exception has a non-expired `review_by` date.
- Every exception includes the required review metadata fields.

## Usage

```bash
cargo run -- audit.toml deny.toml exceptions.yaml
```

The command exits non-zero when policy violations are found.
