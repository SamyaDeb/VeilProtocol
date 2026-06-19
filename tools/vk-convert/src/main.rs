//! vk-convert: convert a snarkjs Groth16 vk.json to the binary format expected
//! by veil_core's verifier (vk_bytes argument to verify_groth16 / init_vk).
//!
//! Binary layout (matches verifier.rs parse_vk):
//!   64 B  alpha_g1    G1 uncompressed: X_be || Y_be
//!  128 B  beta_g2     G2 uncompressed: X_c1_be || X_c0_be || Y_c1_be || Y_c0_be
//!  128 B  gamma_g2
//!  128 B  delta_g2
//!    4 B  n_ic        u32 big-endian (= nPublic + 1)
//!   64 B  IC[i]       per IC point, G1 uncompressed
//!
//! snarkjs convention for G2 elements:
//!   [[x_c1_dec, x_c0_dec], [y_c1_dec, y_c0_dec], [z_c1, z_c0]]
//! z should equal [1, 0] for affine points.
//!
//! VERIFY: confirm argument order of Bn254G2Affine::from_bytes in the Soroban
//! SDK before locking circuit keys. (CIRCUITS.md §8)

use num_bigint::BigUint;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

// ─── snarkjs JSON structure ──────────────────────────────────────────────────

type DecStr = String;

#[derive(Deserialize)]
struct VkJson {
    #[serde(rename = "nPublic")]
    n_public: u32,
    vk_alpha_1: Vec<DecStr>,
    vk_beta_2:  Vec<Vec<DecStr>>,
    vk_gamma_2: Vec<Vec<DecStr>>,
    vk_delta_2: Vec<Vec<DecStr>>,
    #[serde(rename = "IC")]
    ic:         Vec<Vec<DecStr>>,
}

// ─── conversion helpers ──────────────────────────────────────────────────────

fn dec_to_be32(s: &str) -> [u8; 32] {
    let n = s.trim().parse::<BigUint>().unwrap_or_else(|_| {
        panic!("cannot parse decimal '{s}'");
    });
    let mut bytes = n.to_bytes_be();
    assert!(bytes.len() <= 32, "field element too large: {s}");
    let mut out = [0u8; 32];
    let off = 32 - bytes.len();
    out[off..].copy_from_slice(&bytes);
    bytes.zeroize_stub();
    out
}

trait ZeroizeStub { fn zeroize_stub(&mut self); }
impl ZeroizeStub for Vec<u8> { fn zeroize_stub(&mut self) { self.clear(); } }

/// Serialize G1 affine point (3-element projective Vec, Z == "1") → 64 bytes.
fn g1_to_bytes(v: &[DecStr]) -> [u8; 64] {
    assert!(v.len() == 3 && v[2] == "1", "G1 point must be affine (Z=1)");
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&dec_to_be32(&v[0]));
    out[32..].copy_from_slice(&dec_to_be32(&v[1]));
    out
}

/// Serialize G2 affine point (3-element Vec of 2-element Vec, Z == ["1","0"]) → 128 bytes.
/// Layout: X_c0 || X_c1 || Y_c0 || Y_c1
fn g2_to_bytes(v: &[Vec<DecStr>]) -> [u8; 128] {
    assert!(
        v.len() == 3 && v[2][0] == "1" && v[2][1] == "0",
        "G2 point must be affine (Z=[1,0])"
    );
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&dec_to_be32(&v[0][1]));   // X_c0
    out[32..64].copy_from_slice(&dec_to_be32(&v[0][0]));  // X_c1
    out[64..96].copy_from_slice(&dec_to_be32(&v[1][1]));  // Y_c0
    out[96..128].copy_from_slice(&dec_to_be32(&v[1][0])); // Y_c1
    out
}

// ─── main ────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: vk-convert <vk.json> <output.bin>");
        std::process::exit(1);
    }
    let input_path = PathBuf::from(&args[1]);
    let output_path = PathBuf::from(&args[2]);

    let json_str = fs::read_to_string(&input_path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", input_path.display()));
    let vk: VkJson = serde_json::from_str(&json_str)
        .unwrap_or_else(|e| panic!("JSON parse error: {e}"));

    let n_ic = vk.ic.len() as u32;
    let expected_n_ic = vk.n_public + 1;
    assert_eq!(n_ic, expected_n_ic, "IC length {n_ic} != nPublic+1 {expected_n_ic}");

    let mut out: Vec<u8> = Vec::new();

    // alpha_g1 (64 bytes)
    out.extend_from_slice(&g1_to_bytes(&vk.vk_alpha_1));
    // beta_g2 (128 bytes)
    out.extend_from_slice(&g2_to_bytes(&vk.vk_beta_2));
    // gamma_g2 (128 bytes)
    out.extend_from_slice(&g2_to_bytes(&vk.vk_gamma_2));
    // delta_g2 (128 bytes)
    out.extend_from_slice(&g2_to_bytes(&vk.vk_delta_2));
    // n_ic (4 bytes, u32 BE)
    out.extend_from_slice(&n_ic.to_be_bytes());
    // IC points (n_ic * 64 bytes)
    for ic_point in &vk.ic {
        out.extend_from_slice(&g1_to_bytes(ic_point));
    }

    // Validate total size
    let expected_size = 64 + 128 * 3 + 4 + n_ic as usize * 64;
    assert_eq!(out.len(), expected_size, "output size mismatch");

    // Write output
    write_and_verify(&output_path, &out);

    // Print sha256 for manifest
    let sha256 = hex::encode(Sha256::digest(&out));
    println!("{sha256}  {}", output_path.display());
    println!("Wrote {} bytes to {}", out.len(), output_path.display());
    println!("nPublic={}, n_ic={}", vk.n_public, n_ic);
}

fn write_and_verify(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|e| panic!("write error: {e}"));
    // Re-read to confirm no truncation
    let verify = fs::read(path).unwrap();
    assert_eq!(verify.len(), bytes.len(), "write/read size mismatch — disk issue?");
}
