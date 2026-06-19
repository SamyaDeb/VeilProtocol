/**
 * Browser WASM Groth16 prover for the deposit circuit.
 *
 * Generates a Groth16 proof that:
 *   - cm is correctly derived from (amount, asset_id, blinding, owner_pk)
 *   - amount is in range [0, 2^64)
 *   - amount == public_amount
 *   - credential_leaf ∈ asp_approved_root  (Merkle membership)
 *   - credential_leaf ∉ asp_blocked_root   (non-membership)
 *
 * All inputs are BigInt or BigInt[]. Returns { proof, publicSignals }.
 */

import * as snarkjs from 'snarkjs';

let WASM_PATH = '/circuits/build/deposit_js/deposit.wasm';
let ZKEY_PATH = '/circuit-keys/dev/deposit_final.zkey';

if (typeof window === 'undefined') {
    const path = await import('path');
    const rootDir = process.cwd();
    WASM_PATH = path.resolve(rootDir, 'circuits/build/deposit_js/deposit.wasm');
    ZKEY_PATH = path.resolve(rootDir, 'circuit-keys/dev/deposit_final.zkey');
}

/**
 * @param {object} note - { amount, asset_id, blinding, owner_pk } (all BigInt)
 * @param {object} credential - { cred_secret, issuer_pk } (BigInt)
 * @param {object} aspProof - membership+non-membership witness:
 *   { asp_path: BigInt[], asp_idx: number[],
 *     blocked_lower_leaf, blocked_upper_leaf: BigInt,
 *     blocked_lower_path, blocked_lower_idx,
 *     blocked_upper_path, blocked_upper_idx,
 *     asp_approved_root, asp_blocked_root: BigInt }
 * @param {BigInt} publicAmount - amount being deposited (must equal note.amount)
 * @returns {{ proof, publicSignals }}
 */
export async function proveDeposit(note, credential, aspProof, publicAmount) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Derive cm = Poseidon(amount, asset_id, blinding, owner_pk)
    const cm = F.toObject(poseidon([
        note.amount, note.asset_id, note.blinding, note.owner_pk,
    ]));

    const input = {
        // private
        amount:   note.amount.toString(),
        asset_id: note.asset_id.toString(),
        blinding: note.blinding.toString(),
        owner_pk: note.owner_pk.toString(),
        cred_secret: credential.cred_secret.toString(),
        issuer_pk:   credential.issuer_pk.toString(),
        asp_path: aspProof.asp_path.map(String),
        asp_idx:  aspProof.asp_idx.map(String),
        blocked_lower_leaf: aspProof.blocked_lower_leaf.toString(),
        blocked_upper_leaf: aspProof.blocked_upper_leaf.toString(),
        blocked_lower_path: aspProof.blocked_lower_path.map(String),
        blocked_lower_idx:  aspProof.blocked_lower_idx.map(String),
        blocked_upper_path: aspProof.blocked_upper_path.map(String),
        blocked_upper_idx:  aspProof.blocked_upper_idx.map(String),
        // public
        cm:               cm.toString(),
        public_amount:    publicAmount.toString(),
        asp_approved_root: aspProof.asp_approved_root.toString(),
        asp_blocked_root:  aspProof.asp_blocked_root.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, WASM_PATH, ZKEY_PATH,
    );

    return { proof, publicSignals, cm };
}

/**
 * Serialize a snarkjs proof to the binary layout expected by veil_core.verify_groth16:
 *   A: G1 (64 bytes), B: G2 (128 bytes), C: G1 (64 bytes)
 *
 * snarkjs G1 format: [x_dec, y_dec, "1"]
 * snarkjs G2 format: [[x_c1, x_c0], [y_c1, y_c0], ["1","0"]]
 *
 * VERIFY: confirm G2 byte order against CAP-0074 / verifier.rs before mainnet.
 */
export function serializeProof(proof) {
    return {
        a: serializeG1(proof.pi_a),   // BytesN<64>
        b: serializeG2(proof.pi_b),   // BytesN<128>
        c: serializeG1(proof.pi_c),   // BytesN<64>
    };
}

function decToBe32(dec) {
    let hex = BigInt(dec).toString(16).padStart(64, '0');
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

function serializeG1(point) {
    const out = new Uint8Array(64);
    out.set(decToBe32(point[0]), 0);
    out.set(decToBe32(point[1]), 32);
    return Buffer.from(out).toString('hex');
}

function serializeG2(point) {
    // point = [[x_c1, x_c0], [y_c1, y_c0], [z_c1, z_c0]]
    // verifier.rs expects: X_c0 || X_c1 || Y_c0 || Y_c1
    const out = new Uint8Array(128);
    out.set(decToBe32(point[0][1]), 0);   // X_c0
    out.set(decToBe32(point[0][0]), 32);  // X_c1
    out.set(decToBe32(point[1][1]), 64);  // Y_c0
    out.set(decToBe32(point[1][0]), 96);  // Y_c1
    return Buffer.from(out).toString('hex');
}

/**
 * Serialize the 4 public signals for deposit into Vec<BytesN<32>>.
 * Order MUST match circuit header: [cm, public_amount, asp_approved_root, asp_blocked_root].
 */
export function serializePublicInputs(publicSignals) {
    return publicSignals.map(s => {
        const hex = BigInt(s).toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex').toString('hex');
    });
}
