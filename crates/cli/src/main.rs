//! `stellar-guard` — CLI entry point.
//!
//! Usage: `stellar-guard scan <path>`
//!
//! Scans a Rust file or directory for Soroban contract vulnerabilities,
//! prints the findings as a JSON array to stdout, and exits non-zero when
//! any high-severity finding is present (ready to fail PR checks in the
//! future GitHub Action).

use std::path::Path;
use std::process::ExitCode;

use stellar_guard_core::{scan_path, Finding};

const USAGE: &str = "\
Usage: stellar-guard scan <path>

Scans <path> (a .rs file or a directory tree) for Soroban smart-contract
vulnerabilities and prints the findings as a JSON array to stdout.

Exit codes:
  0  scan completed, no high-severity findings
  1  scan completed, at least one high-severity finding
  2  usage error or scan failure
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 3 || args[1] != "scan" {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }

    match scan_path(Path::new(&args[2])) {
        Ok(findings) => {
            println!("{}", to_json(&findings));
            if findings.iter().any(|finding| finding.severity == "high") {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn to_json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).expect("findings must always serialize")
}
