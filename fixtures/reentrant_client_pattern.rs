//! Reentrancy-risk fixture for rule SG002 — generated-client pattern.
//!
//! Entry point `swap` calls out to an external contract via a
//! `let client = PoolClient::new(...)` binding FIRST and mutates its own
//! persistent storage AFTER the call returns. Rule SG002 must flag it.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

mod pool {
    soroban_sdk::contractimport!(
        file = "../pool/target/wasm32v1-none/release/soroban_pool_contract.wasm"
    );
}

#[contract]
pub struct RouterContract;

#[contractimpl]
impl RouterContract {
    /// Swaps tokens via an external pool, then records the trade.
    pub fn swap(env: Env, caller: Address, pool: Address, amount: i128) -> i128 {
        caller.require_auth();

        // INTERACTION first: call out to the external pool contract.
        let client = pool::Client::new(&env, &pool);
        let received = client.swap(&amount);

        // EFFECT second: mutate our own storage AFTER the external call.
        let total_key = Symbol::new(&env, "total_swapped");
        env.storage().persistent().set(&total_key, &received);

        received
    }
}
