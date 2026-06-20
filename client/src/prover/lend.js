import * as snarkjs from 'snarkjs';

let WASM_PATH = '/circuits/build/lend_js/lend.wasm';
let ZKEY_PATH = '/circuit-keys/dev/lend_final.zkey';

if (typeof window === 'undefined') {
    const path = await import('path');
    const { fileURLToPath } = await import('url');
    const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    WASM_PATH = path.resolve(rootDir, 'circuits/build/lend_js/lend.wasm');
    ZKEY_PATH = path.resolve(rootDir, 'circuit-keys/dev/lend_final.zkey');
}

/**
 * Generate a Groth16 proof for a private RWA-collateralized borrow.
 *
 * The oracle prices MUST be fetched immediately before calling this function
 * and passed in directly — the contract will re-read them on-chain and reject
 * any proof built against a stale or mismatched price.
 *
 * @param {object} collatNote  { amount: BigInt, asset_id: BigInt, blinding: BigInt,
 *                               owner_sk: BigInt, leaf_index: BigInt,
 *                               path: BigInt[32], idx: number[32] }
 * @param {object} borrowNote  { amount: BigInt, asset_id: BigInt, blinding: BigInt }
 *                             (owner_pk is derived from collatNote.owner_sk)
 * @param {BigInt} root        Current Merkle root (from veil_core.current_root())
 * @param {BigInt} oraclePrice Collateral oracle price (freshly read from Reflector)
 * @param {BigInt} oracleDecimals  Oracle price decimals (e.g. 7n)
 * @param {BigInt} ltvMaxBps   Max LTV in basis points (e.g. 7500n = 75%)
 * @param {BigInt} borrowPrice Borrow-asset oracle price (freshly read from Reflector)
 * @returns {{ proof, publicSignals, collat_nf, borrow_cm }}
 */
export async function proveLend(
    collatNote,
    borrowNote,
    root,
    oraclePrice,
    oracleDecimals,
    ltvMaxBps,
    borrowPrice,
) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const owner_pk  = F.toObject(poseidon([collatNote.owner_sk]));
    const collat_cm = F.toObject(poseidon([
        collatNote.amount,
        collatNote.asset_id,
        collatNote.blinding,
        owner_pk,
    ]));
    const collat_nf = F.toObject(poseidon([collatNote.owner_sk, collatNote.leaf_index, collat_cm]));

    const borrow_cm = F.toObject(poseidon([
        borrowNote.amount,
        borrowNote.asset_id,
        borrowNote.blinding,
        owner_pk,
    ]));

    const circuitInput = {
        // public — order must match circuit header: root, collat_nf, borrow_cm,
        // oracle_price, oracle_decimals, ltv_max_bps, borrow_price
        root:            root.toString(),
        collat_nf:       collat_nf.toString(),
        borrow_cm:       borrow_cm.toString(),
        oracle_price:    oraclePrice.toString(),
        oracle_decimals: oracleDecimals.toString(),
        ltv_max_bps:     ltvMaxBps.toString(),
        borrow_price:    borrowPrice.toString(),

        // private: collateral note
        collat_amount:   collatNote.amount.toString(),
        collat_asset:    collatNote.asset_id.toString(),
        collat_blinding: collatNote.blinding.toString(),
        owner_sk:        collatNote.owner_sk.toString(),
        leaf_index:      collatNote.leaf_index.toString(),
        path:            collatNote.path.map(String),
        idx:             collatNote.idx.map(String),

        // private: borrow note
        borrow_amount:   borrowNote.amount.toString(),
        borrow_asset:    borrowNote.asset_id.toString(),
        borrow_blinding: borrowNote.blinding.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput, WASM_PATH, ZKEY_PATH,
    );

    return { proof, publicSignals, collat_nf, borrow_cm };
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
