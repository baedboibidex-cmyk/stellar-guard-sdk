//! SG002 — Storage mutation after an external contract call (reentrancy
//! ordering).
//!
//! Flags an entry point that mutates its own contract storage AFTER making a
//! cross-contract call, instead of before it (interaction-then-effect
//! ordering). Per the checks-effects-interactions pattern, state writes
//! should precede external calls: a callee could be a malicious or
//! upgradeable contract that re-enters the caller before the caller's own
//! state update lands.
//!
//! Detection is deliberately syntax-level and line-based (same constraints as
//! SG001): no control-flow or dataflow analysis. See `LIMITATIONS.md`.

use crate::finding::Finding;

use super::common::{collect_body_events, entry_points};

/// Stable identifier for this rule.
pub const RULE_ID: &str = "SG002";
/// Severity assigned to every SG002 finding.
pub const SEVERITY: &str = "high";

/// Runs the SG002 rule over a parsed file.
pub fn run(ast: &syn::File, file: &str) -> Vec<Finding> {
    entry_points(ast)
        .into_iter()
        .filter_map(|method| check_entry_point(method, file))
        .collect()
}

/// Analyzes one entry point; returns a finding if an external call precedes
/// a storage mutation.
fn check_entry_point(method: &syn::ImplItemFn, file: &str) -> Option<Finding> {
    let events = collect_body_events(&method.block);

    let first_external = events.external_call_lines.iter().min().copied()?;
    let bad_mutation = events
        .mutations
        .iter()
        .find(|mutation| first_external < mutation.line)?;

    let function = method.sig.ident.to_string();
    Some(Finding {
        rule_id: RULE_ID.to_string(),
        severity: SEVERITY.to_string(),
        file: file.to_string(),
        line: bad_mutation.line,
        function: function.clone(),
        message: format!(
            "Entry point '{function}' mutates storage after an external contract call, which can allow reentrancy if the callee re-enters before state is finalized."
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wraps a function body in a minimal `#[contractimpl]` contract so tests
    /// exercise the same code paths as real Soroban sources.
    fn contract_with(body: &str) -> String {
        format!(
            r#"
#![no_std]
use soroban_sdk::{{contract, contractimpl, Address, Env, Symbol}};

#[contract]
pub struct Router;

#[contractimpl]
impl Router {{
    {body}
}}
"#
        )
    }

    fn check(source: &str) -> Vec<Finding> {
        let ast = syn::parse_file(source).expect("test source must parse");
        run(&ast, "test.rs")
    }

    fn assert_flagged(source: &str) -> Finding {
        let mut findings = check(source);
        assert_eq!(
            findings.len(),
            1,
            "expected exactly one finding: {findings:?}"
        );
        findings.remove(0)
    }

    fn assert_clean(source: &str) {
        let findings = check(source);
        assert!(findings.is_empty(), "expected no findings: {findings:?}");
    }

    #[test]
    fn flags_external_call_before_mutation() {
        let finding = assert_flagged(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                let received = env.invoke_contract::<i128>(&pool, &Symbol::new(&env, \"swap\"), vec![&env, amount.into_val(&env)]);
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &received);
                received
            }",
        ));
        assert_eq!(finding.rule_id, "SG002");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.file, "test.rs");
        assert_eq!(finding.function, "swap");
        assert!(finding
            .message
            .contains("mutates storage after an external contract call"));
    }

    #[test]
    fn does_not_flag_when_mutation_precedes_external_call() {
        assert_clean(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &amount);
                env.invoke_contract::<i128>(&pool, &Symbol::new(&env, \"swap\"), vec![&env, amount.into_val(&env)])
            }",
        ));
    }

    #[test]
    fn flags_try_invoke_contract() {
        assert_flagged(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                let r = env.try_invoke_contract::<i128, _>(&pool, &Symbol::new(&env, \"swap\"), vec![&env, amount.into_val(&env)]);
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &r);
                r
            }",
        ));
    }

    #[test]
    fn flags_chained_client_call_before_mutation() {
        assert_flagged(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                let received = PoolClient::new(&env, &pool).swap(&amount);
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &received);
                received
            }",
        ));
    }

    #[test]
    fn read_only_storage_after_external_call_is_not_flagged() {
        assert_clean(&contract_with(
            "pub fn peek(env: Env, pool: Address) -> i128 {
                let received = env.invoke_contract::<i128>(&pool, &Symbol::new(&env, \"quote\"), vec![&env]);
                env.storage().persistent().get(&Symbol::new(&env, \"total\")).unwrap_or(received)
            }",
        ));
    }

    #[test]
    fn external_call_without_mutation_is_not_flagged() {
        assert_clean(&contract_with(
            "pub fn relay(env: Env, pool: Address, amount: i128) -> i128 {
                env.invoke_contract::<i128>(&pool, &Symbol::new(&env, \"swap\"), vec![&env, amount.into_val(&env)])
            }",
        ));
    }

    #[test]
    fn only_contractimpl_impl_blocks_are_checked() {
        assert_clean(
            r#"
            pub struct Router;

            impl Router {
                pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                    let received = env.invoke_contract::<i128>(&pool, &Symbol::new(&env, "swap"), vec![&env, amount.into_val(&env)]);
                    env.storage().persistent().set(&Symbol::new(&env, "total"), &received);
                    received
                }
            }
            "#,
        );
    }

    #[test]
    fn flags_tracked_client_call_before_mutation() {
        assert_flagged(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                let client = PoolClient::new(&env, &pool);
                let received = client.swap(&amount);
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &received);
                received
            }",
        ));
    }

    #[test]
    fn does_not_flag_tracked_client_call_when_mutation_precedes() {
        assert_clean(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &amount);
                let client = PoolClient::new(&env, &pool);
                client.swap(&amount)
            }",
        ));
    }

    #[test]
    fn flags_module_qualified_client_call_before_mutation() {
        assert_flagged(&contract_with(
            "pub fn swap(env: Env, pool: Address, amount: i128) -> i128 {
                let client = pool::Client::new(&env, &pool);
                let received = client.swap(&amount);
                env.storage().persistent().set(&Symbol::new(&env, \"total\"), &received);
                received
            }",
        ));
    }
}
