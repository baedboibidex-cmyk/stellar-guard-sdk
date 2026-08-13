//! Shared primitives used by multiple rules.
//!
//! These were extracted from `sg001` when SG002 was added, so that
//! entry-point discovery, storage-mutation detection, external-call
//! detection, and body walking are implemented once and reused by every rule.

use syn::visit::Visit;

/// Method names that mutate state on `Persistent` / `Instance` / `Temporary`
/// storage handles (verified against the `soroban-sdk` docs).
pub const MUTATING_METHODS: &[&str] = &[
    "set",
    "put", // pre-`set` SDK naming for temporary storage
    "remove",
    "update",
    "try_update",
    "extend_ttl",
    "extend_ttl_with_limits",
];

/// `Storage` accessors that select the storage kind.
pub const STORAGE_ACCESSORS: &[&str] = &["persistent", "instance", "temporary"];

/// Method names that perform authorization on an `Address`.
pub const AUTH_METHODS: &[&str] = &["require_auth", "require_auth_for_args"];

/// Cross-contract call method names on `Env`, verified against the
/// `soroban-sdk` source (`src/env.rs`): `invoke_contract` and its fallible
/// variant `try_invoke_contract`. The commonly assumed
/// `invoke_contract_check_args` does **not** exist in the current SDK.
pub const EXTERNAL_CALL_METHODS: &[&str] = &["invoke_contract", "try_invoke_contract"];

/// Which storage kind a mutating call targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageKind {
    Persistent,
    Instance,
    Temporary,
    /// `env.storage()` without a recognized accessor.
    Contract,
}

impl StorageKind {
    pub fn label(self) -> &'static str {
        match self {
            StorageKind::Persistent => "persistent",
            StorageKind::Instance => "instance",
            StorageKind::Temporary => "temporary",
            StorageKind::Contract => "contract",
        }
    }
}

/// All entry points in a parsed file: `pub fn` items of `#[contractimpl]`
/// impl blocks (including impls nested inside modules).
pub fn entry_points(ast: &syn::File) -> Vec<&syn::ImplItemFn> {
    let mut collector = EntryPointCollector {
        methods: Vec::new(),
    };
    collector.visit_file(ast);
    collector.methods
}

struct EntryPointCollector<'ast> {
    methods: Vec<&'ast syn::ImplItemFn>,
}

impl<'ast> Visit<'ast> for EntryPointCollector<'ast> {
    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if is_contractimpl_impl(node) {
            for item in &node.items {
                if let syn::ImplItem::Fn(method) = item {
                    if is_public(&method.vis) {
                        self.methods.push(method);
                    }
                }
            }
        }
        syn::visit::visit_item_impl(self, node);
    }
}

pub fn is_contractimpl_impl(node: &syn::ItemImpl) -> bool {
    node.attrs.iter().any(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "contractimpl")
    })
}

pub fn is_public(vis: &syn::Visibility) -> bool {
    matches!(vis, syn::Visibility::Public(_))
}

/// Events collected from one function body, with their source line numbers.
#[derive(Debug, Default)]
pub struct BodyEvents {
    /// Lines of `require_auth()` / `require_auth_for_args()` calls.
    pub auth_lines: Vec<usize>,
    /// Storage-mutating calls reached through `env.storage()`.
    pub mutations: Vec<StorageMutation>,
    /// Lines of cross-contract calls (`env.invoke_contract[_...]`, clients).
    pub external_call_lines: Vec<usize>,
}

/// A storage-mutating call found in a function body.
#[derive(Debug, Clone, Copy)]
pub struct StorageMutation {
    pub line: usize,
    pub kind: StorageKind,
}

/// Walks a function body and records auth calls, storage mutations, and
/// external contract calls with their line numbers. The walk is flat: nested
/// expressions (branches, loops, closures) are all attributed to the
/// enclosing function (see `LIMITATIONS.md`).
pub fn collect_body_events(block: &syn::Block) -> BodyEvents {
    let mut visitor = BodyVisitor::default();
    visitor.visit_block(block);
    visitor.events
}

#[derive(Default)]
struct BodyVisitor {
    events: BodyEvents,
}

impl Visit<'_> for BodyVisitor {
    fn visit_expr_method_call(&mut self, node: &syn::ExprMethodCall) {
        let method = node.method.to_string();

        if AUTH_METHODS.contains(&method.as_str()) {
            self.events.auth_lines.push(line_of(&node.method));
        }
        if let Some(kind) = storage_mutation_of(node) {
            self.events.mutations.push(StorageMutation {
                line: line_of(&node.method),
                kind,
            });
        }
        if EXTERNAL_CALL_METHODS.contains(&method.as_str()) || is_client_call(node) {
            self.events.external_call_lines.push(line_of(&node.method));
        }

        syn::visit::visit_expr_method_call(self, node);
    }
}

pub fn line_of(spanned: &impl syn::spanned::Spanned) -> usize {
    spanned.span().start().line
}

/// Returns the storage kind targeted by `call` if it is a mutating method
/// reached through an `env.storage()` chain, else `None`.
pub fn storage_mutation_of(call: &syn::ExprMethodCall) -> Option<StorageKind> {
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
pub fn is_env_storage(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::MethodCall(call)
            if call.method == "storage"
                && matches!(&*call.receiver, syn::Expr::Path(path) if path.path.is_ident("env"))
    )
}

/// True when `call` is a chained generated-client call such as
/// `XxxClient::new(&env, &addr).method(...)` or
/// `contract_a::Client::new(&env, &addr).method(...)`. Generated contract
/// clients are thin wrappers around `env.invoke_contract`, so the chained
/// form counts as an external call. Calls through a stored client variable
/// (`let c = XxxClient::new(...); c.method(...)`) are not detected — no
/// dataflow analysis (see `LIMITATIONS.md`).
fn is_client_call(call: &syn::ExprMethodCall) -> bool {
    // `XxxClient::new(&env, &addr)` parses as an `Expr::Call` whose callee is
    // the path `XxxClient::new`, so the receiver of the outer method call is
    // that call expression, not a method call.
    let syn::Expr::Call(ctor) = &*call.receiver else {
        return false;
    };
    let syn::Expr::Path(path) = &*ctor.func else {
        return false;
    };
    let segments: Vec<&syn::PathSegment> = path.path.segments.iter().collect();
    let Some((last, parent)) = segments.split_last() else {
        return false;
    };
    if last.ident != "new" {
        return false;
    }
    let parent = parent
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::");
    parent.ends_with("Client")
}
