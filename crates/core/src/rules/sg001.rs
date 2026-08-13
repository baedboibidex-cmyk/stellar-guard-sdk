//! SG001 — Storage mutation without authorization.
//!
//! Flags an entry point (`pub fn` inside a `#[contractimpl]` impl block) that
//! mutates contract storage — via an `env.storage()` chain — without a
//! preceding `require_auth()` / `require_auth_for_args()` call in the same
//! function body.
//!
//! v1 detection is deliberately syntax-level and line-based: method calls are
//! matched by name and receiver shape, with no control-flow or dataflow
//! analysis. See `LIMITATIONS.md` for the known constraints.

use syn::visit::Visit;

use crate::finding::Finding;

/// Stable identifier for this rule.
pub const RULE_ID: &str = "SG001";
/// Severity assigned to every SG001 finding.
pub const SEVERITY: &str = "high";

/// Method names that mutate state on `Persistent` / `Instance` / `Temporary`
/// storage handles (verified against the `soroban-sdk` docs).
const MUTATING_METHODS: &[&str] = &[
    "set",
    "put", // pre-`set` SDK naming for temporary storage
    "remove",
    "update",
    "try_update",
    "extend_ttl",
    "extend_ttl_with_limits",
];

/// `Storage` accessors that select the storage kind.
const STORAGE_ACCESSORS: &[&str] = &["persistent", "instance", "temporary"];

/// Method names that perform authorization on an `Address`.
const AUTH_METHODS: &[&str] = &["require_auth", "require_auth_for_args"];

/// Runs the SG001 rule over a parsed file.
pub fn run(ast: &syn::File, file: &str) -> Vec<Finding> {
    let mut visitor = ContractImplVisitor {
        file: file.to_string(),
        findings: Vec::new(),
    };
    visitor.visit_file(ast);
    visitor.findings
}

/// Collects `#[contractimpl]` impl blocks and checks their `pub fn` items.
struct ContractImplVisitor {
    file: String,
    findings: Vec<Finding>,
}

impl Visit<'_> for ContractImplVisitor {
    fn visit_item_impl(&mut self, node: &syn::ItemImpl) {
        if has_contractimpl_attribute(node) {
            for item in &node.items {
                if let syn::ImplItem::Fn(method) = item {
                    if is_public(&method.vis) {
                        if let Some(finding) = check_entry_point(method, &self.file) {
                            self.findings.push(finding);
                        }
                    }
                }
            }
        }
        syn::visit::visit_item_impl(self, node);
    }
}

fn has_contractimpl_attribute(node: &syn::ItemImpl) -> bool {
    node.attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "contractimpl")
    })
}

fn is_public(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// Analyzes one entry point; returns a finding if it mutates storage without
/// a preceding auth call.
fn check_entry_point(method: &syn::ImplItemFn, file: &str) -> Option<Finding> {
    let mut analyzer = BodyAnalyzer::default();
    analyzer.visit_block(&method.block);

    for mutation in &analyzer.mutations {
        let authorized = analyzer
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
                    mutation.storage_kind.label()
                ),
            });
        }
    }
    None
}

/// Which storage kind a mutating call targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StorageKind {
    Persistent,
    Instance,
    Temporary,
    /// `env.storage()` without a recognized accessor.
    Contract,
}

impl StorageKind {
    fn label(self) -> &'static str {
        match self {
            StorageKind::Persistent => "persistent",
            StorageKind::Instance => "instance",
            StorageKind::Temporary => "temporary",
            StorageKind::Contract => "contract",
        }
    }
}

/// A storage-mutating call found in a function body.
#[derive(Debug, Clone, Copy)]
struct Mutation {
    line: usize,
    storage_kind: StorageKind,
}

/// Collects auth calls and storage mutations across a function body by
/// walking every method call expression, including nested ones.
#[derive(Default)]
struct BodyAnalyzer {
    auth_lines: Vec<usize>,
    mutations: Vec<Mutation>,
}

impl Visit<'_> for BodyAnalyzer {
    fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
        let method = node.method.to_string();

        if AUTH_METHODS.contains(&method.as_str()) {
            self.auth_lines.push(line_of(&node.method));
        }
        if let Some(storage_kind) = storage_kind_of(node) {
            self.mutations.push(Mutation {
                line: line_of(&node.method),
                storage_kind,
            });
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

fn line_of(spanned: &impl syn::spanned::Spanned) -> usize {
    spanned.span().start().line
}

/// Returns the storage kind targeted by `call` if it is a mutating method
/// reached through an `env.storage()` chain, else `None`.
fn storage_kind_of(call: &syn::ExprMethodCall) -> Option<StorageKind> {
    let method = call.method.to_string();
    if !MUTATING_METHODS.contains(&method.as_str()) {
        return None;
    }

    // Expected receiver shapes:
    //   env.storage().persistent()/instance()/temporary()   (common)
    //   env.storage()                                       (no accessor)
    let syn::Expr::MethodCall(accessor) = &*call.receiver else {
        return None;
    };

    let accessor_name = accessor.method.to_string();
    if !STORAGE_ACCESSORS.contains(&accessor_name.as_str()) {
        // `env.storage().<mutating>(...)` directly — `Storage` exposes no
        // mutating methods in the current SDK, but keep a conservative
        // catch-all for robustness.
        return if is_env_storage(&call.receiver) {
            Some(StorageKind::Contract)
        } else {
            None
        };
    }
    if !is_env_storage(&accessor.receiver) {
        return None;
    }

    let kind = match accessor_name.as_str() {
        "persistent" => StorageKind::Persistent,
        "instance" => StorageKind::Instance,
        _ => StorageKind::Temporary,
    };
    Some(kind)
}

/// True when `expr` is exactly `env.storage()`.
fn is_env_storage(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::MethodCall(call)
            if call.method == "storage"
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("env"))
    )
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
