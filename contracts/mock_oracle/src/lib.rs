#![no_std]
//! Deployable mock Reflector oracle for testnet/dev.
//!
//! Mirrors the subset of the Reflector SEP-40 interface that `lending` consumes:
//! `lastprice(Asset) -> Option<PriceData>` with `PriceData { price: i128,
//! timestamp: u64 }`. The admin sets a price via `set_price`; every asset
//! returns the same configured price (sufficient for LTV / liquidation tests).
//!
//! NOT for mainnet — `m8-deploy.sh` wires the real Reflector contract instead.

use soroban_sdk::{contract, contracterror, contractimpl, contracttype, symbol_short, Address, Env, Symbol};

const PRICE: Symbol = symbol_short!("PRICE");
const TS: Symbol = symbol_short!("TS");

#[contracttype]
#[derive(Clone)]
pub enum Asset {
    Stellar(Address),
    Other(Symbol),
}

#[contracttype]
#[derive(Clone)]
pub struct PriceData {
    pub price: i128,
    pub timestamp: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OracleError {
    NotSet = 1,
}

#[contract]
pub struct MockOracle;

#[contractimpl]
impl MockOracle {
    /// Set the price returned for every asset, with an explicit timestamp so
    /// staleness behavior can be exercised by the lending tests.
    pub fn set_price(env: Env, price: i128, timestamp: u64) {
        env.storage().instance().set(&PRICE, &price);
        env.storage().instance().set(&TS, &timestamp);
    }

    /// SEP-40-shaped read. Returns the configured price for any asset, or
    /// `None` if no price has been set yet.
    pub fn lastprice(env: Env, _asset: Asset) -> Option<PriceData> {
        let price: i128 = env.storage().instance().get(&PRICE)?;
        let timestamp: u64 = env.storage().instance().get(&TS).unwrap_or(0u64);
        Some(PriceData { price, timestamp })
    }
}
