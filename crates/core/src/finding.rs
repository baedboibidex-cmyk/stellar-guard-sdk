//! Finding model shared across rules and the CLI.

use serde::{Deserialize, Serialize};

/// A single security finding emitted by a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule identifier, e.g. `SG001`.
    pub rule_id: String,
    /// Severity level, e.g. `high`, `medium`, `low`.
    pub severity: String,
    /// Path of the analyzed file as given to the scanner.
    pub file: String,
    /// 1-based line number of the offending code.
    pub line: usize,
    /// Name of the entry point function the finding belongs to.
    pub function: String,
    /// Human-readable description of the problem.
    pub message: String,
}
