//! `stellar-guard-core` — parsing and rule engine for static security
//! analysis of Soroban smart contracts.
//!
//! v1 ships a single rule, SG001: an entry point (`#[contractimpl]` `pub fn`)
//! that mutates contract storage without first calling `require_auth()` /
//! `require_auth_for_args()` on an `Address`. Detection is syntax-level and
//! pattern-based; see [`rules::sg001`] and `LIMITATIONS.md`.

pub mod finding;
pub mod rules;

pub use finding::Finding;

use std::fmt;
use std::path::Path;

/// Errors that can occur while scanning.
#[derive(Debug)]
pub enum ScanError {
    /// The target path does not exist.
    NotFound(std::path::PathBuf),
    /// Failed to read a file from disk.
    Io(std::io::Error),
    /// Failed while walking a directory tree.
    Walk(walkdir::Error),
    /// Failed to parse a `.rs` file with `syn`.
    Parse { file: String, error: syn::Error },
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::NotFound(path) => write!(f, "path not found: {}", path.display()),
            ScanError::Io(err) => write!(f, "failed to read file: {err}"),
            ScanError::Walk(err) => write!(f, "failed to walk directory: {err}"),
            ScanError::Parse { file, error } => write!(f, "failed to parse {file}: {error}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Scans a file, or a directory tree (recursively, `*.rs` files only), and
/// returns all findings sorted by file then line.
pub fn scan_path(path: &Path) -> Result<Vec<Finding>, ScanError> {
    let mut findings = Vec::new();

    if path.is_file() {
        findings.extend(scan_file(path)?);
    } else if path.is_dir() {
        for entry in walkdir::WalkDir::new(path) {
            let entry = entry.map_err(ScanError::Walk)?;
            if entry.file_type().is_file() && is_rs_file(entry.path()) {
                findings.extend(scan_file(entry.path())?);
            }
        }
    } else {
        return Err(ScanError::NotFound(path.to_path_buf()));
    }

    findings.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    Ok(findings)
}

/// Parses a single Rust file and runs all rules against it.
pub fn scan_file(path: &Path) -> Result<Vec<Finding>, ScanError> {
    let source = std::fs::read_to_string(path).map_err(ScanError::Io)?;
    check_source(&source, &path.to_string_lossy())
}

/// Parses a Rust source string and runs all rules. The `file` label is
/// attached to any findings, verbatim.
pub fn check_source(source: &str, file: &str) -> Result<Vec<Finding>, ScanError> {
    let ast = syn::parse_file(source).map_err(|error| ScanError::Parse {
        file: file.to_string(),
        error,
    })?;
    Ok(rules::sg001::run(&ast, file))
}

fn is_rs_file(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "rs")
}
