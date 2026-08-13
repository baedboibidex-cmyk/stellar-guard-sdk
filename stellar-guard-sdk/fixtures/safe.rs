//! Safe fixture for rule SG001.
//!
//! Entry point `withdraw` calls `require_auth()` on the caller before
//! mutating persistent storage, so the scanner must NOT flag it.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    /// Withdraws `amount` from the vault after authenticating `caller`.
    pub fn withdraw(env: Env, caller: Address, amount: i128) -> i128 {
        caller.require_auth();

        let balance_key = Symbol::new(&env, "balance");
        let current = env
            .storage()
            .persistent()
            .get::<Symbol, i128>(&balance_key)
            .unwrap_or(0);

        let new_balance = current - amount;

        env.storage().persistent().set(&balance_key, &new_balance);

        new_balance
    }
}
