//! Vulnerable fixture for rule SG001.
//!
//! Entry point `withdraw` mutates persistent storage without calling
//! `require_auth()` (or `require_auth_for_args()`) on the caller, so the
//! scanner must flag it.

#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

#[contract]
pub struct VaultContract;

#[contractimpl]
impl VaultContract {
    /// Withdraws `amount` from the vault. MISSING require_auth().
    pub fn withdraw(env: Env, caller: Address, amount: i128) -> i128 {
        let balance_key = Symbol::new(&env, "balance");
        let current = env
            .storage()
            .persistent()
            .get::<Symbol, i128>(&balance_key)
            .unwrap_or(0);

        let new_balance = current - amount;

        // VULNERABILITY: no require_auth() before this write.
        env.storage().persistent().set(&balance_key, &new_balance);

        new_balance
    }
}
