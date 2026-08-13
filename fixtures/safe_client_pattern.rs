//! Safe-ordering fixture for rule SG002 — generated-client pattern.
//!
//! Entry point `swap` finalizes its own storage state BEFORE making the
//! external contract call via a `let client = PoolClient::new(...)` binding
//! (checks-effects-interactions). Rule SG002 must NOT flag it.

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
    /// Swaps tokens via an external pool, recording the trade first.
    pub fn swap(env: Env, caller: Address, pool: Address, amount: i128) -> i128 {
        caller.require_auth();

        // EFFECT first: finalize our own storage before interacting.
        let total_key = Symbol::new(&env, "total_swapped");
        let current = env
            .storage()
            .persistent()
            .get::<Symbol, i128>(&total_key)
            .unwrap_or(0);
        env.storage().persistent().set(&total_key, &(current + amount));

        // INTERACTION second: call out to the external pool contract.
        let client = pool::Client::new(&env, &pool);
        client.swap(&amount)
    }
}
