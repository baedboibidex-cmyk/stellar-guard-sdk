//! SG001 — Storage mutation without authorization.
//!
//! Flags an entry point (`pub fn` inside a `#[contractimpl]` impl block) that
//! mutates contract storage — via an `env.storage()` chain — without a
//! preceding `require_auth()` / `require_auth_for_args()` call in the same
//! function body.
//!
//! Detection is deliberately syntax-level and line-based: method calls are
//! matched by name and receiver shape, with no control-flow or dataflow
//! analysis. See `LIMITATIONS.md` for the known constraints.

use crate::finding::Finding;

use super::common::{collect_body_events, entry_points};

/// Stable identifier for this rule.
pub const RULE_ID: &str = "SG001";
/// Severity assigned to every SG001 finding.
pub const SEVERITY: &str = "high";

/// Runs the SG001 rule over a parsed file.
pub fn run(ast: &syn::File, file: &str) -> Vec<Finding> {
    entry_points(ast)
        .into_iter()
        .filter_map(|method| check_entry_point(method, file))
        .collect()
}

/// Analyzes one entry point; returns a finding if it mutates storage without
/// a preceding auth call.
fn check_entry_point(method: &syn::ImplItemFn, file: &str) -> Option<Finding> {
    let events = collect_body_events(&method.block);

    for mutation in &events.mutations {
        let authorized = events
            .auth_lines
            .iter()
            .any(|&auth_line| auth_line < mutation.line);
        if !authorized {
            let function = method.sig.ident.to_string();
            return Some(Finding {
                rule_id: RULE_ID.to_string(),
                severity: SEVERITY.to_string(),
                file: file.to_string(),
                line: mutation.line,
                function: function.clone(),
                message: format!(
                    "Entry point '{function}' mutates {} storage without a preceding require_auth() call.",
                    mutation.kind.label()
                ),
            });
        }
    }
    None
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
pub struct Vault;

#[contractimpl]
impl Vault {{
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
    fn flags_persistent_mutation_without_auth() {
        let finding = assert_flagged(&contract_with(
            "pub fn withdraw(env: Env, amount: i128) -> i128 {
                env.storage().persistent().set(&Symbol::new(&env, \"k\"), &amount);
                amount
            }",
        ));
        assert_eq!(finding.rule_id, "SG001");
        assert_eq!(finding.severity, "high");
        assert_eq!(finding.file, "test.rs");
        assert_eq!(finding.function, "withdraw");
        assert!(finding.message.contains("mutates persistent storage"));
        assert!(finding.message.contains("'withdraw'"));
    }

    #[test]
    fn does_not_flag_when_auth_precedes_mutation() {
        assert_clean(&contract_with(
            "pub fn withdraw(env: Env, caller: Address, amount: i128) -> i128 {
                caller.require_auth();
                env.storage().persistent().set(&Symbol::new(&env, \"k\"), &amount);
                amount
            }",
        ));
    }

    #[test]
    fn require_auth_for_args_counts_as_auth() {
        assert_clean(&contract_with(
            "pub fn withdraw(env: Env, caller: Address, amount: i128) -> i128 {
                caller.require_auth_for_args(vec![&env, amount.into_val(&env)]);
                env.storage().persistent().set(&Symbol::new(&env, \"k\"), &amount);
                amount
            }",
        ));
    }

    #[test]
    fn flags_mutation_when_auth_comes_after() {
        let finding = assert_flagged(&contract_with(
            "pub fn withdraw(env: Env, caller: Address, amount: i128) -> i128 {
                env.storage().persistent().set(&Symbol::new(&env, \"k\"), &amount);
                caller.require_auth();
                amount
            }",
        ));
        assert!(finding.message.contains("mutates persistent storage"));
    }

    #[test]
    fn flags_instance_and_temporary_mutations() {
        let finding = assert_flagged(&contract_with(
            "pub fn init(env: Env, v: u32) {
                env.storage().instance().set(&Symbol::new(&env, \"k\"), &v);
            }",
        ));
        assert!(finding.message.contains("mutates instance storage"));

        let finding = assert_flagged(&contract_with(
            "pub fn cache(env: Env, v: u32) {
                env.storage().temporary().set(&Symbol::new(&env, \"k\"), &v);
            }",
        ));
        assert!(finding.message.contains("mutates temporary storage"));
    }

    #[test]
    fn flags_remove_and_extend_ttl() {
        assert_flagged(&contract_with(
            "pub fn clean(env: Env) {
                env.storage().persistent().remove(&Symbol::new(&env, \"k\"));
            }",
        ));
        assert_flagged(&contract_with(
            "pub fn bump(env: Env) {
                env.storage().persistent().extend_ttl(&Symbol::new(&env, \"k\"), 1_000, 5_000);
            }",
        ));
    }

    #[test]
    fn read_only_storage_calls_are_not_flagged() {
        assert_clean(&contract_with(
            "pub fn peek(env: Env) -> i128 {
                env.storage().persistent().get(&Symbol::new(&env, \"k\")).unwrap_or(0)
            }",
        ));
    }

    #[test]
    fn set_on_unrelated_receiver_is_not_flagged() {
        assert_clean(&contract_with(
            "pub fn tweak(env: Env, s: Vec<u32>) {
                let mut other = s;
                other.set(0, 1);
            }",
        ));
    }

    #[test]
    fn only_contractimpl_impl_blocks_are_checked() {
        assert_clean(
            r#"
            pub struct Vault;

            impl Vault {
                pub fn withdraw(env: Env, amount: i128) -> i128 {
                    env.storage().persistent().set(&Symbol::new(&env, "k"), &amount);
                    amount
                }
            }
            "#,
        );
    }

    #[test]
    fn walks_nested_blocks() {
        assert_flagged(&contract_with(
            "pub fn maybe(env: Env, flag: bool, amount: i128) -> i128 {
                if flag {
                    env.storage().persistent().set(&Symbol::new(&env, \"k\"), &amount);
                }
                amount
            }",
        ));
    }
}
