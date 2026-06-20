import * as snarkjs from 'snarkjs';

let WASM_PATH_ADD = '/circuits/build/add_liquidity_js/add_liquidity.wasm';
let ZKEY_PATH_ADD = '/circuit-keys/dev/add_liquidity_final.zkey';
let WASM_PATH_REM = '/circuits/build/remove_liquidity_js/remove_liquidity.wasm';
let ZKEY_PATH_REM = '/circuit-keys/dev/remove_liquidity_final.zkey';

if (typeof window === 'undefined') {
    const path = await import('path');
    const { fileURLToPath } = await import('url');
    const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
    WASM_PATH_ADD = path.resolve(rootDir, 'circuits/build/add_liquidity_js/add_liquidity.wasm');
    ZKEY_PATH_ADD = path.resolve(rootDir, 'circuit-keys/dev/add_liquidity_final.zkey');
    WASM_PATH_REM = path.resolve(rootDir, 'circuits/build/remove_liquidity_js/remove_liquidity.wasm');
    ZKEY_PATH_REM = path.resolve(rootDir, 'circuit-keys/dev/remove_liquidity_final.zkey');
}

export async function proveAddLiquidity(
    inputNote0, inputNote1,
    preReserves, preTotalShares, reserveBlinding,
    root
) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const owner_pk_0 = F.toObject(poseidon([inputNote0.owner_sk]));
    const cm_in_0 = F.toObject(poseidon([
        inputNote0.amount, inputNote0.asset_id, inputNote0.blinding, owner_pk_0,
    ]));
    const nf_in_0 = F.toObject(poseidon([inputNote0.owner_sk, inputNote0.leaf_index, cm_in_0]));

    const owner_pk_1 = F.toObject(poseidon([inputNote1.owner_sk]));
    const cm_in_1 = F.toObject(poseidon([
        inputNote1.amount, inputNote1.asset_id, inputNote1.blinding, owner_pk_1,
    ]));
    const nf_in_1 = F.toObject(poseidon([inputNote1.owner_sk, inputNote1.leaf_index, cm_in_1]));

    const pre_reserve_cm = F.toObject(poseidon([
        preReserves[0], preReserves[1], preTotalShares, reserveBlinding
    ]));

    // Compute shares and post reserves
    let shares = 0n;
    if (BigInt(preTotalShares) === 0n) {
        shares = BigInt(inputNote0.amount);
    } else {
        shares = (BigInt(inputNote0.amount) * BigInt(preTotalShares)) / BigInt(preReserves[0]);
    }

    const lp_commit = F.toObject(poseidon([
        shares, 99999n, inputNote0.blinding, owner_pk_0 // Using dummy LP_ASSET 99999n, owner is owner of note 0
    ]));

    const post_reserves = [
        BigInt(preReserves[0]) + BigInt(inputNote0.amount),
        BigInt(preReserves[1]) + BigInt(inputNote1.amount)
    ];
    const post_total_shares = BigInt(preTotalShares) + shares;

    const post_reserve_cm = F.toObject(poseidon([
        post_reserves[0], post_reserves[1], post_total_shares, reserveBlinding
    ]));

    const circuitInput = {
        root: root.toString(),
        nf_in_0: nf_in_0.toString(),
        nf_in_1: nf_in_1.toString(),
        lp_commit: lp_commit.toString(),
        reserve_pre_commit: pre_reserve_cm.toString(),
        reserve_post_commit: post_reserve_cm.toString(),

        amount_in_0: inputNote0.amount.toString(),
        asset_in_0: inputNote0.asset_id.toString(),
        blinding_in_0: inputNote0.blinding.toString(),
        owner_sk_in_0: inputNote0.owner_sk.toString(),
        leaf_index_0: inputNote0.leaf_index.toString(),
        path_0: inputNote0.path.map(String),
        idx_0: inputNote0.idx.map(String),

        amount_in_1: inputNote1.amount.toString(),
        asset_in_1: inputNote1.asset_id.toString(),
        blinding_in_1: inputNote1.blinding.toString(),
        owner_sk_in_1: inputNote1.owner_sk.toString(),
        leaf_index_1: inputNote1.leaf_index.toString(),
        path_1: inputNote1.path.map(String),
        idx_1: inputNote1.idx.map(String),

        shares: shares.toString(),
        lp_asset: '99999',
        lp_blinding: inputNote0.blinding.toString(),

        pre_reserves: [preReserves[0].toString(), preReserves[1].toString()],
        pre_total_shares: preTotalShares.toString(),
        reserve_blinding: reserveBlinding.toString()
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput, WASM_PATH_ADD, ZKEY_PATH_ADD
    );

    return { proof, publicSignals, nf_in_0, nf_in_1, lp_commit, post_reserve_cm };
}

export async function proveRemoveLiquidity(
    lpNote, intent, preReserves, preTotalShares, reserveBlinding, root
) {
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const owner_pk = F.toObject(poseidon([lpNote.owner_sk]));
    const cm_in = F.toObject(poseidon([
        lpNote.amount, lpNote.asset_id, lpNote.blinding, owner_pk,
    ]));
    const lp_nf = F.toObject(poseidon([lpNote.owner_sk, lpNote.leaf_index, cm_in]));

    const pre_reserve_cm = F.toObject(poseidon([
        preReserves[0], preReserves[1], preTotalShares, reserveBlinding
    ]));

    const amount_out_0 = (BigInt(lpNote.amount) * BigInt(preReserves[0])) / BigInt(preTotalShares);
    const amount_out_1 = (BigInt(lpNote.amount) * BigInt(preReserves[1])) / BigInt(preTotalShares);

    const out_owner_pk_0 = F.toObject(poseidon([intent.out_owner_sk_0]));
    const cm_out_0 = F.toObject(poseidon([
        amount_out_0, intent.asset_0, intent.out_blinding_0, out_owner_pk_0
    ]));

    const out_owner_pk_1 = F.toObject(poseidon([intent.out_owner_sk_1]));
    const cm_out_1 = F.toObject(poseidon([
        amount_out_1, intent.asset_1, intent.out_blinding_1, out_owner_pk_1
    ]));

    const post_reserves = [
        BigInt(preReserves[0]) - amount_out_0,
        BigInt(preReserves[1]) - amount_out_1
    ];
    const post_total_shares = BigInt(preTotalShares) - BigInt(lpNote.amount);

    const post_reserve_cm = F.toObject(poseidon([
        post_reserves[0], post_reserves[1], post_total_shares, reserveBlinding
    ]));

    const circuitInput = {
        root: root.toString(),
        lp_nf: lp_nf.toString(),
        cm_out_0: cm_out_0.toString(),
        cm_out_1: cm_out_1.toString(),
        reserve_pre_commit: pre_reserve_cm.toString(),
        reserve_post_commit: post_reserve_cm.toString(),

        shares: lpNote.amount.toString(),
        lp_asset: lpNote.asset_id.toString(),
        lp_blinding: lpNote.blinding.toString(),
        owner_sk: lpNote.owner_sk.toString(),
        leaf_index: lpNote.leaf_index.toString(),
        path: lpNote.path.map(String),
        idx: lpNote.idx.map(String),

        amount_out_0: amount_out_0.toString(),
        asset_out_0: intent.asset_0.toString(),
        blinding_out_0: intent.out_blinding_0.toString(),
        owner_pk_out_0: out_owner_pk_0.toString(),

        amount_out_1: amount_out_1.toString(),
        asset_out_1: intent.asset_1.toString(),
        blinding_out_1: intent.out_blinding_1.toString(),
        owner_pk_out_1: out_owner_pk_1.toString(),

        pre_reserves: [preReserves[0].toString(), preReserves[1].toString()],
        pre_total_shares: preTotalShares.toString(),
        reserve_blinding: reserveBlinding.toString()
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput, WASM_PATH_REM, ZKEY_PATH_REM
    );

    return { proof, publicSignals, lp_nf, cm_out_0, cm_out_1, post_reserve_cm };
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
    const out = new Uint8Array(128);
    out.set(decToBe32(point[0][1]), 0);
    out.set(decToBe32(point[0][0]), 32);
    out.set(decToBe32(point[1][1]), 64);
    out.set(decToBe32(point[1][0]), 96);
    return Buffer.from(out).toString('hex');
}
