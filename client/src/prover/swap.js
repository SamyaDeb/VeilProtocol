import * as snarkjs from 'snarkjs';

let WASM_PATH = '/circuits/build/swap_js/swap.wasm';
let ZKEY_PATH = '/circuit-keys/dev/swap_final.zkey';

if (typeof window === 'undefined') {
    const path = await import('path');
    const { fileURLToPath } = await import('url');
    const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    WASM_PATH = path.resolve(rootDir, 'circuits/build/swap_js/swap.wasm');
    ZKEY_PATH = path.resolve(rootDir, 'circuit-keys/dev/swap_final.zkey');
}

/**
 * Generate a Groth16 proof for a shielded swap order.
 *
 * @param {object} inputNote   { amount, asset_id, blinding, owner_sk, leaf_index,
 *                               path: BigInt[], idx: number[] }
 * @param {object} intent      { asset_out, min_out, out_blinding, out_owner_pk }
 * @param {BigInt} root        Current Merkle root
 * @param {BigInt} committeePk Committee BN254 field scalar (public)
 * @param {BigInt} rEnc        Encryption randomness (private)
 * @returns {{ proof, publicSignals, nf_in, enc_order_hash }}
 */
export async function proveSwap(inputNote, intent, root, committeePk, rEnc) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const owner_pk = F.toObject(poseidon([inputNote.owner_sk]));
    const cm_in = F.toObject(poseidon([
        inputNote.amount, inputNote.asset_id, inputNote.blinding, owner_pk,
    ]));
    const nf_in = F.toObject(poseidon([inputNote.owner_sk, inputNote.leaf_index, cm_in]));

    // enc_order_hash = Poseidon(amount_in, asset_out, min_out, out_blinding,
    //                           out_owner_pk, committee_pk, r_enc)
    const enc_order_hash = F.toObject(poseidon([
        inputNote.amount,
        intent.asset_out,
        intent.min_out,
        intent.out_blinding,
        intent.out_owner_pk,
        committeePk,
        rEnc,
    ]));

    const circuitInput = {
        // public (circuit order: root, nf_in, enc_order_hash, committee_pk)
        root:            root.toString(),
        nf_in:           nf_in.toString(),
        enc_order_hash:  enc_order_hash.toString(),
        committee_pk:    committeePk.toString(),

        // private: input note
        amount_in:    inputNote.amount.toString(),
        asset_in:     inputNote.asset_id.toString(),
        blinding_in:  inputNote.blinding.toString(),
        owner_sk:     inputNote.owner_sk.toString(),
        leaf_index:   inputNote.leaf_index.toString(),
        path:         inputNote.path.map(String),
        idx:          inputNote.idx.map(String),

        // private: intent
        asset_out:    intent.asset_out.toString(),
        min_out:      intent.min_out.toString(),
        out_blinding: intent.out_blinding.toString(),
        out_owner_pk: intent.out_owner_pk.toString(),
        r_enc:        rEnc.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput, WASM_PATH, ZKEY_PATH,
    );

    return { proof, publicSignals, nf_in, enc_order_hash };
}

/**
 * Compute the enc_order_hash off-chain (for the mock committee to verify).
 * Mirrors the in-circuit computation: Poseidon(amount_in, asset_out, min_out,
 * out_blinding, out_owner_pk, committee_pk, r_enc).
 */
export async function computeEncOrderHash(amountIn, intent, committeePk, rEnc) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    return F.toObject(poseidon([
        amountIn,
        intent.asset_out,
        intent.min_out,
        intent.out_blinding,
        intent.out_owner_pk,
        committeePk,
        rEnc,
    ]));
}

// ─── proof serialisation (same conventions as withdraw.js) ───────────────────

export function serializeProof(proof) {
    return {
        a: serializeG1(proof.pi_a),
        b: serializeG2(proof.pi_b),
        c: serializeG1(proof.pi_c),
    };
}

export function serializePublicInputs(publicSignals) {
    return publicSignals.map(s => {
        const hex = BigInt(s).toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex').toString('hex');
    });
}

function decToBe32(dec) {
    const hex = BigInt(dec).toString(16).padStart(64, '0');
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
    // verifier.rs expects: X_c0 || X_c1 || Y_c0 || Y_c1
    const out = new Uint8Array(128);
    out.set(decToBe32(point[0][1]), 0);   // X_c0
    out.set(decToBe32(point[0][0]), 32);  // X_c1
    out.set(decToBe32(point[1][1]), 64);  // Y_c0
    out.set(decToBe32(point[1][0]), 96);  // Y_c1
    return Buffer.from(out).toString('hex');
}
