import * as snarkjs from 'snarkjs';

let WASM_PATH = '/circuits/build/withdraw_js/withdraw.wasm';
let ZKEY_PATH = '/circuit-keys/dev/withdraw_final.zkey';

if (typeof window === 'undefined') {
    const path = await import('path');
    const rootDir = process.cwd();
    WASM_PATH = path.resolve(rootDir, 'circuits/build/withdraw_js/withdraw.wasm');
    ZKEY_PATH = path.resolve(rootDir, 'circuit-keys/dev/withdraw_final.zkey');
}

/**
 * Generate a Groth16 proof for a shielded withdraw.
 *
 * @param {object} input0  { amount, asset_id, blinding, owner_sk, leaf_index, path: BigInt[], idx: number[] }
 * @param {object} input1  Same shape; set amount=0n for a dummy (single-input) withdraw
 * @param {object} change  { amount, asset_id, blinding, owner_pk } — set amount=0n if no change
 * @param {BigInt} root    Current Merkle root
 * @param {BigInt} publicAmount  Amount exiting to recipient (must be > 0)
 * @param {BigInt} assetId Field element identifying the asset
 * @param {BigInt} recipientHash Poseidon(recipient_address_as_field)
 * @returns {{ proof, publicSignals, nf_in_0, nf_in_1, cm_change }}
 */
export async function proveWithdraw(input0, input1, change, root, publicAmount, assetId, recipientHash) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const getCmNf = (inp) => {
        if (inp.amount === 0n) return { cm: 0n, nf: 0n };
        const owner_pk = F.toObject(poseidon([inp.owner_sk]));
        const cm = F.toObject(poseidon([inp.amount, inp.asset_id, inp.blinding, owner_pk]));
        const nf = F.toObject(poseidon([inp.owner_sk, inp.leaf_index, cm]));
        return { cm, nf };
    };

    const in0 = getCmNf(input0);
    const in1 = getCmNf(input1);

    const cm_change = change.amount === 0n
        ? 0n
        : F.toObject(poseidon([change.amount, change.asset_id, change.blinding, change.owner_pk]));

    const circuitInput = {
        // public (circuit order: root, nf_in_0, nf_in_1, cm_change, public_amount, asset_id, recipient_hash)
        root: root.toString(),
        nf_in_0: in0.nf.toString(),
        nf_in_1: in1.nf.toString(),
        cm_change: cm_change.toString(),
        public_amount: publicAmount.toString(),
        asset_id: assetId.toString(),
        recipient_hash: recipientHash.toString(),

        // private in0
        amount_in_0: input0.amount.toString(),
        asset_in_0: input0.asset_id.toString(),
        blinding_in_0: input0.blinding.toString(),
        owner_sk_0: input0.owner_sk.toString(),
        leaf_index_0: input0.leaf_index.toString(),
        path_0: input0.path.map(String),
        idx_0: input0.idx.map(String),

        // private in1
        amount_in_1: input1.amount.toString(),
        asset_in_1: input1.asset_id.toString(),
        blinding_in_1: input1.blinding.toString(),
        owner_sk_1: input1.owner_sk.toString(),
        leaf_index_1: input1.leaf_index.toString(),
        path_1: input1.path.map(String),
        idx_1: input1.idx.map(String),

        // private change
        amount_change: change.amount.toString(),
        asset_change: change.asset_id.toString(),
        blinding_change: change.blinding.toString(),
        owner_pk_change: change.owner_pk.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput, WASM_PATH, ZKEY_PATH,
    );

    return { proof, publicSignals, nf_in_0: in0.nf, nf_in_1: in1.nf, cm_change };
}

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
    // verifier.rs expects: X_c0 || X_c1 || Y_c0 || Y_c1
    const out = new Uint8Array(128);
    out.set(decToBe32(point[0][1]), 0);   // X_c0
    out.set(decToBe32(point[0][0]), 32);  // X_c1
    out.set(decToBe32(point[1][1]), 64);  // Y_c0
    out.set(decToBe32(point[1][0]), 96);  // Y_c1
    return Buffer.from(out).toString('hex');
}
