# stellar-guard-sdk

Rust CLI & GitHub Action for static analysis of Soroban smart contracts —
detects missing auth checks, reentrancy risks, and unauthorized state
mutations before mainnet deploy.

## Status

v1 milestone: a working CLI that detects **SG001** — entry points
(`#[contractimpl]` `pub fn`s) that mutate contract storage without a
preceding `require_auth()` / `require_auth_for_args()` call. See
[`rules/SG001.md`](rules/SG001.md) for the rule and [`LIMITATIONS.md`](LIMITATIONS.md)
for known constraints.

## Usage

```bash
# Scan a single file
stellar-guard scan path/to/contract/src/lib.rs

# Scan a whole directory tree
stellar-guard scan path/to/contract

# Output (JSON array on stdout)
# [
#   {
#     "rule_id": "SG001",
#     "severity": "high",
#     "file": "fixtures/vulnerable.rs",
#     "line": 25,
#     "function": "withdraw",
#     "message": "Entry point 'withdraw' mutates persistent storage without a preceding require_auth() call."
#   }
# ]
```

Exit codes: `0` = clean, `1` = high-severity findings present, `2` = usage
error or scan failure.

## Development

```bash
cargo test    # unit + integration tests (fixtures live in fixtures/)
cargo clippy  # lints
```

## Workspace layout

```
crates/
  core/    # parsing + rule engine (syn, quote, serde, serde_json, walkdir)
  cli/     # `stellar-guard` binary
fixtures/  # sample Soroban contracts used by the tests
rules/     # one markdown file per rule
```
