//! Groth16 verifier wrapper for veil_core.
//!
//! Parses a serialized verification key and proof, performs the Groth16
//! pairing check via the BN254 host functions (CAP-0074).
//!
//! VK serialization format (written by tools/vk-convert):
//!   - 64 bytes:  alpha_g1  (G1 uncompressed, X||Y big-endian)
//!   - 128 bytes: beta_g2   (G2 uncompressed)
//!   - 128 bytes: gamma_g2  (G2 uncompressed)
//!   - 128 bytes: delta_g2  (G2 uncompressed)
//!   - 4 bytes:   n_ic (u32 big-endian)
//!   - n_ic * 64 bytes: IC points (G1 uncompressed)
//!
//! Groth16 pairing check (Ethereum convention, matches snarkjs):
//!   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
//!
//! VERIFY: argument order against CAP-0074 docs before mainnet.

use soroban_sdk::{
    crypto::bn254::{Bn254Fr, Bn254G1Affine, Bn254G2Affine},
    Bytes, BytesN, Env, Vec,
};

use crate::Proof;

pub enum VerifyError {
    MalformedVk,
    MalformedProof,
}

pub fn groth16_verify(
    env: &Env,
    vk_bytes: &Bytes,
    proof: &Proof,
    public_inputs: &Vec<BytesN<32>>,
) -> Result<bool, VerifyError> {
    let vk = parse_vk(env, vk_bytes)?;

    let proof_a = Bn254G1Affine::from_bytes(proof.a.clone());
    let proof_b = Bn254G2Affine::from_bytes(proof.b.clone());
    let proof_c = Bn254G1Affine::from_bytes(proof.c.clone());

    let bn254 = env.crypto().bn254();

    let n_pub = public_inputs.len() as usize;
    if n_pub + 1 != vk.ic.len() as usize {
        return Err(VerifyError::MalformedVk);
    }

    // vk_x = IC[0] + Σ IC[i+1] * scalar_i
    let mut vk_x = vk.ic.get(0).unwrap().clone();
    for i in 0..n_pub {
        let scalar_bytes: BytesN<32> = public_inputs.get(i as u32).unwrap();
        let scalar = Bn254Fr::from_bytes(scalar_bytes);
        let ic_i = vk.ic.get((i + 1) as u32).unwrap();
        let term = bn254.g1_mul(&ic_i, &scalar);
        vk_x = bn254.g1_add(&vk_x, &term);
    }

    // Negate A (field modulus q for BN254 base field)
    let neg_a = g1_negate(env, &proof_a);

    let mut g1_vec: Vec<Bn254G1Affine> = Vec::new(env);
    g1_vec.push_back(neg_a);
    g1_vec.push_back(vk.alpha_g1);
    g1_vec.push_back(vk_x);
    g1_vec.push_back(proof_c);

    let mut g2_vec: Vec<Bn254G2Affine> = Vec::new(env);
    g2_vec.push_back(proof_b);
    g2_vec.push_back(vk.beta_g2);
    g2_vec.push_back(vk.gamma_g2);
    g2_vec.push_back(vk.delta_g2);

    Ok(bn254.pairing_check(g1_vec, g2_vec))
}

struct Vk {
    alpha_g1: Bn254G1Affine,
    beta_g2:  Bn254G2Affine,
    gamma_g2: Bn254G2Affine,
    delta_g2: Bn254G2Affine,
    ic:       Vec<Bn254G1Affine>,
}

fn parse_vk(env: &Env, bytes: &Bytes) -> Result<Vk, VerifyError> {
    let len = bytes.len() as usize;
    if len < 64 + 128 * 3 + 4 {
        return Err(VerifyError::MalformedVk);
    }
    let mut off = 0usize;

    let alpha_g1 = Bn254G1Affine::from_bytes(read_bytes64(bytes, off)?);
    off += 64;
    let beta_g2  = Bn254G2Affine::from_bytes(read_bytes128(bytes, off)?);
    off += 128;
    let gamma_g2 = Bn254G2Affine::from_bytes(read_bytes128(bytes, off)?);
    off += 128;
    let delta_g2 = Bn254G2Affine::from_bytes(read_bytes128(bytes, off)?);
    off += 128;

    if off + 4 > len { return Err(VerifyError::MalformedVk); }
    let n_ic = {
        let b = [
            bytes.get(off as u32).unwrap(),
            bytes.get(off as u32 + 1).unwrap(),
            bytes.get(off as u32 + 2).unwrap(),
            bytes.get(off as u32 + 3).unwrap(),
        ];
        ((b[0] as u32) << 24) | ((b[1] as u32) << 16) | ((b[2] as u32) << 8) | (b[3] as u32)
    } as usize;
    off += 4;

    if off + n_ic * 64 > len { return Err(VerifyError::MalformedVk); }

    let mut ic: Vec<Bn254G1Affine> = Vec::new(env);
    for _ in 0..n_ic {
        ic.push_back(Bn254G1Affine::from_bytes(read_bytes64(bytes, off)?));
        off += 64;
    }

    Ok(Vk { alpha_g1, beta_g2, gamma_g2, delta_g2, ic })
}

fn read_bytes64(bytes: &Bytes, off: usize) -> Result<BytesN<64>, VerifyError> {
    if off + 64 > bytes.len() as usize { return Err(VerifyError::MalformedVk); }
    let s = bytes.slice(off as u32..off as u32 + 64);
    s.try_into().map_err(|_| VerifyError::MalformedVk)
}

fn read_bytes128(bytes: &Bytes, off: usize) -> Result<BytesN<128>, VerifyError> {
    if off + 128 > bytes.len() as usize { return Err(VerifyError::MalformedVk); }
    let s = bytes.slice(off as u32..off as u32 + 128);
    s.try_into().map_err(|_| VerifyError::MalformedVk)
}

/// Negate a G1 affine point: negate the Y coordinate mod the BN254 base field q.
/// q = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
fn g1_negate(env: &Env, p: &Bn254G1Affine) -> Bn254G1Affine {
    // BN254 base field modulus q
    const Q: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
        0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];

    // Read X (bytes 0..32) and Y (bytes 32..64) from the 64-byte G1 serialization
    let raw: [u8; 64] = p.to_array();
    let x = &raw[..32];
    let y = &raw[32..];

    // Check for point at infinity
    if raw.iter().all(|&b| b == 0) {
        return p.clone();
    }

    // y_neg = q - y  (big-endian subtraction)
    let mut y_neg = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = (Q[i] as i16) - (y[i] as i16) - borrow;
        if diff < 0 {
            y_neg[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            y_neg[i] = diff as u8;
            borrow = 0;
        }
    }

    let mut neg_raw = [0u8; 64];
    neg_raw[..32].copy_from_slice(x);
    neg_raw[32..].copy_from_slice(&y_neg);
    Bn254G1Affine::from_array(env, &neg_raw)
}
