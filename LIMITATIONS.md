# Limitations

`stellar-guard` v1 ships two rules — SG001 (storage mutation without
authorization) and SG002 (storage mutation after an external contract call)
— implemented as a **syntax-level, pattern-based** analysis over the parsed
Rust AST (`syn`). It is deliberately **not** a control-flow or dataflow
analysis. The following constraints are known and accepted for this
milestone; addressing them requires a richer analysis engine.

## SG001-specific limitations

1. **No control-flow analysis.** The rule walks every method call in the
   function body regardless of whether it is reachable or under which
   conditions it runs. An auth check that only executes on some branches
   (e.g. inside an `if` that the mutation path skips) is still counted as
   covering the whole function → possible **false negatives**.
2. **No dataflow analysis.** Storage handles stored in variables are not
   tracked. `let s = env.storage().persistent(); s.set(...)` is **not**
   flagged. Likewise, `require_auth` results are not tracked across
   variables, calls, or clones.
3. **Auth in helper functions is invisible.** If `require_auth()` happens in
   a function that the entry point calls, the entry point is still flagged
   (false positive).
4. **Ordering is by line number.** An auth call must appear on a strictly
   earlier line than the mutation. Auth and mutation on the same line, or
   auth in a multi-line expression that starts after the mutation, are
   treated as "not earlier".
5. **Receiver types are not resolved.** Any method call named
   `require_auth` / `require_auth_for_args` counts as authorization, and any
   mutating call whose chain *lexically* starts at `env.storage()` counts as
   a storage mutation. Aliases, imports under different names, and
   re-exports are not resolved.
6. **Only the literal identifier `env` is recognized** as the storage
   receiver base (`env.storage()`). A parameter named differently
   (`e.storage()`) is not flagged.
7. **Only `pub fn` in `#[contractimpl]` impl blocks are entry points.**
   Private helpers, trait methods, and functions outside contract impls are
   not analyzed.
8. **`__constructor` is treated like any other entry point.** Constructors
   that write storage without `require_auth` are flagged, even though that
   is a legitimate pattern during deployment.
9. **Nested closures / callbacks.** Auth or mutations inside closures are
   attributed to the enclosing entry point (flat walk), matching
   limitation 1.
10. **Parse errors abort the scan.** A file that `syn` cannot parse produces
    an error for the whole scan rather than partial results.

## SG002-specific limitations

1. **Statement-order / line-based, like SG001.** Branches, loops, and
   conditionals are walked flat: an external call that only runs on some
   paths is still treated as if it always runs, and the mutation that runs
   after it on other paths is still flagged → **false positives**. The
   converse (call and mutation that can never run in the same invocation)
   is also not understood.
2. **No dataflow analysis.** A cross-contract call performed through a
   stored client variable is invisible: `let c = PoolClient::new(&env,
   &pool); c.swap(&amount);` is **not** detected, and neither is
   `client.try_swap(...)` on such a variable. Only the chained form
   `PoolClient::new(&env, &pool).swap(...)` is recognized.
3. **External calls in helper functions are invisible.** If the
   `invoke_contract` call (or the storage mutation) happens in a function
   the entry point calls, the entry point is not flagged (false negative).
4. **`...Client::new(...)` is a heuristic.** Any method call whose receiver
   chain is `SomethingClient::new(...)` is treated as an external call,
   even if the type is not a generated contract client (false positive
   possible). It is a best-effort approximation of the generated-client
   pattern.
5. **Env-level APIs matched by name.** `invoke_contract` and
   `try_invoke_contract` are matched by method name on any receiver, not
   verified to be `env`. The spec-assumed `invoke_contract_check_args` does
   **not** exist in the current `soroban-sdk` and is not (and cannot be)
   detected.
6. **Ordering is by line number.** An external call must appear on a
   strictly earlier line than the mutation to trigger the finding; same-line
   ordering is not detected.
7. **Only the two `Env` invocation APIs and the chained client pattern are
   recognized.** Other cross-contract mechanisms (e.g. deferred calls or
   `env.deployer()` flows) are out of scope for v1.
8. **Only `pub fn` in `#[contractimpl]` impl blocks are entry points**, same
   as SG001; private helpers and trait methods are not analyzed.
9. **Nested closures / callbacks** inside the body are attributed to the
   enclosing entry point (flat walk), matching limitation 1.
10. **Parse errors abort the scan**, same as SG001.

## Engine-wide limitations (future milestones)

- Two rules are implemented (SG001, SG002). Gas usage and other rules are
  out of scope for v1.
- Findings are emitted as JSON only; no SARIF format or GitHub Action
  integration yet.
- No configuration file or rule toggling.
