//! Integration tests for rule SG001, exercising the real CLI binary.
//!
//! Asserts that `stellar-guard scan` flags the vulnerable fixture and does
//! NOT flag the safe fixture, both as single files and via directory scans.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn run_scan(target: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_stellar-guard"))
        .arg("scan")
        .arg(target)
        .output()
        .expect("failed to run stellar-guard")
}

fn parse_findings(output: &Output) -> Vec<Value> {
    let value: Value = serde_json::from_slice(&output.stdout).expect("stdout must be a JSON array");
    value
        .as_array()
        .expect("JSON value must be an array")
        .clone()
}

#[test]
fn flags_vulnerable_fixture() {
    let output = run_scan(&fixtures_dir().join("vulnerable.rs"));

    assert!(
        !output.status.success(),
        "scanning the vulnerable fixture must exit non-zero"
    );

    let findings = parse_findings(&output);
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one finding: {findings:#?}"
    );

    let finding = &findings[0];
    assert_eq!(finding["rule_id"], "SG001");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["function"], "withdraw");
    assert_eq!(
        finding["line"], 28,
        "line must point at the env.storage().persistent().set(...) call"
    );
    assert!(finding["file"]
        .as_str()
        .unwrap()
        .ends_with("fixtures/vulnerable.rs"));
    assert!(finding["message"]
        .as_str()
        .unwrap()
        .contains("mutates persistent storage"));
}

#[test]
fn does_not_flag_safe_fixture() {
    let output = run_scan(&fixtures_dir().join("safe.rs"));

    assert!(
        output.status.success(),
        "scanning the safe fixture must exit zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let findings = parse_findings(&output);
    assert!(findings.is_empty(), "expected no findings: {findings:#?}");
}
#[test]
fn directory_scan_flags_only_the_vulnerable_fixture() {
    let output = run_scan(&fixtures_dir());

    assert!(
        !output.status.success(),
        "directory scan must exit non-zero"
    );

    let findings = parse_findings(&output);
    let sg001: Vec<&Value> = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "SG001")
        .collect();
    assert_eq!(
        sg001.len(),
        1,
        "expected exactly one SG001 finding (other rules may also fire): {findings:#?}"
    );
    assert!(sg001[0]["file"]
        .as_str()
        .unwrap()
        .ends_with("vulnerable.rs"));
}
