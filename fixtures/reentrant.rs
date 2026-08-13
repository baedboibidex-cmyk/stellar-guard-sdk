//! Reentrancy-risk fixture for rule SG002.
//!
//! Entry point `swap` calls out to an external contract FIRST and mutates
//! its own persistent storage AFTER the call returns — the
//! "interaction-then-effect" ordering that can let a malicious or
//! upgradeable callee re-enter before state is finalized. Rule SG002 must
//! flag it.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol, Vec};

#[contract]
pub struct RouterContract;

#[contractimpl]
impl RouterContract {
    /// Swaps tokens via an external pool, then records the trade.
    pub fn swap(env: Env, caller: Address, pool: Address, amount: i128) -> i128 {
        caller.require_auth();

        // INTERACTION first: call out to the external pool contract.
        let received = env.invoke_contract::<i128>(
            &pool,
            &Symbol::new(&env, "swap"),
            vec![&env, amount.into_val(&env)],
        );

        // EFFECT second: mutate our own storage AFTER the external call.
        let total_key = Symbol::new(&env, "total_swapped");
        env.storage().persistent().set(&total_key, &received);

        received
    }
}
