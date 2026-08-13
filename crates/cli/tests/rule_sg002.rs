//! Integration tests for rule SG002, exercising the real CLI binary.
//!
//! Asserts that `stellar-guard scan` flags the reentrant fixture and does
//! NOT flag the safe-ordering fixture, both as single files and via
//! directory scans (where SG001 and SG002 findings coexist).

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

fn sg002_findings(output: &Output) -> Vec<Value> {
    parse_findings(output)
        .into_iter()
        .filter(|finding| finding["rule_id"] == "SG002")
        .collect()
}

#[test]
fn flags_reentrant_fixture() {
    let output = run_scan(&fixtures_dir().join("reentrant.rs"));

    assert!(
        !output.status.success(),
        "scanning the reentrant fixture must exit non-zero"
    );

    let findings = sg002_findings(&output);
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one SG002 finding: {findings:#?}"
    );

    let finding = &findings[0];
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["function"], "swap");
    assert_eq!(
        finding["line"], 31,
        "line must point at the env.storage().persistent().set(...) call after the external call"
    );
    assert!(finding["file"]
        .as_str()
        .unwrap()
        .ends_with("fixtures/reentrant.rs"));
    assert!(finding["message"]
        .as_str()
        .unwrap()
        .contains("mutates storage after an external contract call"));
}

#[test]
fn does_not_flag_safe_ordering_fixture() {
    let output = run_scan(&fixtures_dir().join("safe_ordering.rs"));

    assert!(
        output.status.success(),
        "scanning the safe-ordering fixture must exit zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let findings = sg002_findings(&output);
    assert!(
        findings.is_empty(),
        "expected no SG002 findings: {findings:#?}"
    );
}

#[test]
fn directory_scan_reports_both_rules() {
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
    let sg002: Vec<&Value> = findings
        .iter()
        .filter(|finding| finding["rule_id"] == "SG002")
        .collect();

    assert_eq!(sg001.len(), 1, "expected one SG001 finding: {findings:#?}");
    assert_eq!(sg002.len(), 2, "expected two SG002 findings: {findings:#?}");
    assert!(sg001[0]["file"]
        .as_str()
        .unwrap()
        .ends_with("fixtures/vulnerable.rs"));
    let sg002_files: Vec<&str> = sg002.iter().map(|f| f["file"].as_str().unwrap()).collect();
    assert!(
        sg002_files
            .iter()
            .any(|f| f.ends_with("fixtures/reentrant.rs")),
        "expected reentrant.rs in SG002 findings: {sg002_files:?}"
    );
    assert!(
        sg002_files
            .iter()
            .any(|f| f.ends_with("fixtures/reentrant_client_pattern.rs")),
        "expected reentrant_client_pattern.rs in SG002 findings: {sg002_files:?}"
    );
}

#[test]
fn flags_reentrant_client_pattern_fixture() {
    let output = run_scan(&fixtures_dir().join("reentrant_client_pattern.rs"));

    assert!(
        !output.status.success(),
        "scanning the reentrant-client-pattern fixture must exit non-zero"
    );

    let findings = sg002_findings(&output);
    assert_eq!(
        findings.len(),
        1,
        "expected exactly one SG002 finding: {findings:#?}"
    );

    let finding = &findings[0];
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["function"], "swap");
    assert!(finding["message"]
        .as_str()
        .unwrap()
        .contains("mutates storage after an external contract call"));
}

#[test]
fn does_not_flag_safe_client_pattern_fixture() {
    let output = run_scan(&fixtures_dir().join("safe_client_pattern.rs"));

    assert!(
        output.status.success(),
        "scanning the safe-client-pattern fixture must exit zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let findings = sg002_findings(&output);
    assert!(
        findings.is_empty(),
        "expected no SG002 findings: {findings:#?}"
    );
}
