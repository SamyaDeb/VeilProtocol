use soroban_sdk::{Env, BytesN, U256, symbol_short, Vec};

#[test]
fn test_poseidon_correct_order() {
    let env = Env::default();
    
    // Call directly with [0, 1, 2]
    let field = symbol_short!("BN254");
    
    // Copy the constants from lib.rs manually to avoid pub issues
    // ... wait, I can just use crate::poseidon::poseidon2 but modify it!
    
}
