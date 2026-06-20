import * as snarkjs from 'snarkjs';

let WASM_PATH = '/circuits/build/transfer_js/transfer.wasm';
let ZKEY_PATH = '/circuit-keys/dev/transfer_final.zkey';

if (typeof window === 'undefined') {
    const path = await import('path');
    const { fileURLToPath } = await import('url');
    const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    WASM_PATH = path.resolve(rootDir, 'circuits/build/transfer_js/transfer.wasm');
    ZKEY_PATH = path.resolve(rootDir, 'circuit-keys/dev/transfer_final.zkey');
}

/**
 * @param {object} input0 - { amount, asset_id, blinding, owner_sk, leaf_index, path: BigInt[], idx: number[] }
 * @param {object} input1 - { amount, asset_id, blinding, owner_sk, leaf_index, path: BigInt[], idx: number[] }
 * @param {object} output0 - { amount, asset_id, blinding, owner_pk }
 * @param {object} output1 - { amount, asset_id, blinding, owner_pk }
 * @param {BigInt} root - Current Merkle root
 * @param {BigInt} publicAmount - Must be 0 for internal transfer
 * @returns {{ proof, publicSignals, nf_in_0, nf_in_1, cm_out_0, cm_out_1 }}
 */
export async function proveTransfer(input0, input1, output0, output1, root, publicAmount) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Helper to derive cm and nf for an input
    const getCmNf = (inp) => {
        if (inp.amount === 0n) {
            return { cm: 0n, nf: 0n };
        }
        const owner_pk = F.toObject(poseidon([inp.owner_sk]));
        const cm = F.toObject(poseidon([inp.amount, inp.asset_id, inp.blinding, owner_pk]));
        const nf = F.toObject(poseidon([inp.owner_sk, inp.leaf_index, cm]));
        return { cm, nf };
    };

    // Helper to derive cm for an output
    const getCmOut = (out) => {
        if (out.amount === 0n) {
            return 0n; // dummy output
        }
        return F.toObject(poseidon([out.amount, out.asset_id, out.blinding, out.owner_pk]));
    };

    const in0 = getCmNf(input0);
    const in1 = getCmNf(input1);
    const cm_out_0 = getCmOut(output0);
    const cm_out_1 = getCmOut(output1);

    const input = {
        // public
        root: root.toString(),
        nf_in_0: in0.nf.toString(),
        nf_in_1: in1.nf.toString(),
        cm_out_0: cm_out_0.toString(),
        cm_out_1: cm_out_1.toString(),
        public_amount: publicAmount.toString(),

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

        // private out0
        amount_out_0: output0.amount.toString(),
        asset_out_0: output0.asset_id.toString(),
        blinding_out_0: output0.blinding.toString(),
        owner_pk_out_0: output0.owner_pk.toString(),

        // private out1
        amount_out_1: output1.amount.toString(),
        asset_out_1: output1.asset_id.toString(),
        blinding_out_1: output1.blinding.toString(),
        owner_pk_out_1: output1.owner_pk.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input, WASM_PATH, ZKEY_PATH,
    );

    return { 
        proof, 
        publicSignals, 
        nf_in_0: in0.nf, 
        nf_in_1: in1.nf, 
        cm_out_0, 
        cm_out_1 
    };
}

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

export function serializePublicInputs(publicSignals) {
    return publicSignals.map(s => {
        const hex = BigInt(s).toString(16).padStart(64, '0');
        return Buffer.from(hex, 'hex').toString('hex');
    });
}
