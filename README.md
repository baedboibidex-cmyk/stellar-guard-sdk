# stellar-guard-sdk

Rust CLI & GitHub Action for static analysis of Soroban smart contracts —
detects missing auth checks, reentrancy risks, and unauthorized state
mutations before mainnet deploy.

## Status

v1 milestone: a working CLI that detects

- **SG001** — entry points (`#[contractimpl]` `pub fn`s) that mutate
  contract storage without a preceding `require_auth()` /
  `require_auth_for_args()` call.
- **SG002** — entry points that mutate storage **after** an external
  contract call (`env.invoke_contract` / `env.try_invoke_contract` or a
  generated `...Client::new(...).method(...)` call), i.e. a reentrancy
  ordering risk.

See [`rules/SG001.md`](rules/SG001.md) and [`rules/SG002.md`](rules/SG002.md)
for the rules and [`LIMITATIONS.md`](LIMITATIONS.md) for known constraints.

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

## Using the GitHub Action

A [composite GitHub Action](action.yml) is included at the repo root. Point
it at your Soroban contract sources on every pull request; it builds the
CLI, runs `stellar-guard scan <path>`, posts a Markdown report as a PR
comment, and **fails the check when any high-severity finding exists**
(matching the CLI's exit-code behavior).

- **Inputs**
  - `path` — file or directory to scan, relative to the repository root
    (default: `.`).
  - `github-token` — token used to post the report comment; needs
    `pull-requests: write` permission (default: the automatic `GITHUB_TOKEN`).
- **Comments, not spam** — the report is posted as one comment containing a
  `<!-- stellar-guard-report -->` marker; on subsequent pushes to the same
  PR the existing comment is **updated** instead of creating duplicates.
- **Result** — the job fails (red check) when findings with severity
  `high` exist; otherwise it passes, posting a short "no issues found"
  report so the outcome is visible on the PR.

Consuming workflow (see [`examples/stellar-guard-scan.yml`](examples/stellar-guard-scan.yml)
for the full version):

```yaml
name: stellar-guard

on:
  pull_request:

permissions:
  contents: read
  pull-requests: write # required to post/update the PR report comment

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run stellar-guard security scan
        uses: baedboibidex-cmyk/stellar-guard-sdk@main
        with:
          path: contracts # path to your Soroban contract sources
```

`examples/stellar-guard-scan.yml` shows the same setup as a copy-paste
workflow for an external project. This repository's own dogfooding workflow
([`.github/workflows/stellar-guard.yml`](.github/workflows/stellar-guard.yml))
runs the action on the tool's own `crates/` sources; it intentionally does
not scan `fixtures/` (those samples trigger findings by design).

## Development

```bash
cargo test    # unit + integration tests (fixtures live in fixtures/)
cargo clippy  # lints
```

## Workspace layout

```
crates/
  core/    # parsing + rule engine (syn, quote, serde, serde_json, walkdir)
           #   rules/common.rs holds shared analysis primitives
  cli/     # `stellar-guard` binary
fixtures/  # sample Soroban contracts used by the tests
rules/     # one markdown file per rule
```
