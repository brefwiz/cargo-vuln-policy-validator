use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("cargo-vuln-policy-validator-{name}-{nanos}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn exits_non_zero_when_policy_violations_are_found() {
    let dir = temp_dir("cli-policy-violation");
    let audit = dir.join("audit.toml");
    let deny = dir.join("deny.toml");
    let exceptions = dir.join("exceptions.yaml");

    fs::write(
        &audit,
        r#"
[advisories]
ignore = [
  "RUSTSEC-2024-9999"
]
"#,
    )
    .unwrap();
    fs::write(&deny, "[advisories]\nignore = []\n").unwrap();
    fs::write(
        &exceptions,
        r#"
exceptions:
  - id: RUSTSEC-2024-0001
    owner: team-security
    review_by: 2099-01-01
    reason: temporary exception
    risk: known
    impact: low
    tracking: SEC-123
    resolution: upgrade planned
"#,
    )
    .unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_cargo-vuln-policy-validator"))
        .arg(&audit)
        .arg(&deny)
        .arg(&exceptions)
        .status()
        .unwrap();

    assert!(
        !status.success(),
        "expected non-zero exit code for policy violations"
    );

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn exits_zero_when_policy_validation_succeeds() {
    let dir = temp_dir("cli-policy-success");
    let audit = dir.join("audit.toml");
    let deny = dir.join("deny.toml");
    let exceptions = dir.join("exceptions.yaml");

    fs::write(
        &audit,
        r#"
[advisories]
ignore = [
  "RUSTSEC-2024-0001"
]
"#,
    )
    .unwrap();
    fs::write(&deny, "[advisories]\nignore = []\n").unwrap();
    fs::write(
        &exceptions,
        r#"
exceptions:
  - id: RUSTSEC-2024-0001
    owner: team-security
    review_by: 2099-01-01
    reason: temporary exception
    risk: known
    impact: low
    tracking: SEC-123
    resolution: upgrade planned
"#,
    )
    .unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_cargo-vuln-policy-validator"))
        .arg(&audit)
        .arg(&deny)
        .arg(&exceptions)
        .status()
        .unwrap();

    assert!(status.success(), "expected zero exit code for valid policy");

    fs::remove_dir_all(dir).unwrap();
}
