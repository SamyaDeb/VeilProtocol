/**
 * Witness test for add_liquidity.circom and remove_liquidity.circom
 * Run from the repo root: node circuits/test_lp_witness.mjs
 */
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const ADD_WASM = path.join(ROOT, 'circuits/build/add_liquidity_js/add_liquidity.wasm');
const REMOVE_WASM = path.join(ROOT, 'circuits/build/remove_liquidity_js/remove_liquidity.wasm');

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

async function expectFail(promise, msg) {
    try {
        await promise;
        console.error(`FAIL: ${msg} (expected failure but succeeded)`);
        process.exit(1);
    } catch (e) {
        console.log(`PASS: ${msg} (failed as expected)`);
    }
}

// Sparse Merkle proof builder
function sparseProof(leaves, targetIdx, depth, poseidon) {
    const F = poseidon.F;
    let cur = new Map();
    for (let i = 0; i < leaves.length; i++) cur.set(i, leaves[i]);
    const pathElements = [], pathIndices = [];
    let ci = targetIdx;
    for (let i = 0; i < depth; i++) {
        const isRight = ci % 2 === 1;
        pathIndices.push(isRight ? 1 : 0);
        const sibIdx = isRight ? ci - 1 : ci + 1;
        pathElements.push(cur.has(sibIdx) ? cur.get(sibIdx) : 0n);
        const next = new Map();
        for (const [idx, val] of cur.entries()) {
            const pi = Math.floor(idx / 2);
            if (!next.has(pi)) {
                const isR = idx % 2 === 1;
                const si  = isR ? idx - 1 : idx + 1;
                const sv  = cur.has(si) ? cur.get(si) : 0n;
                const h   = isR ? poseidon([sv, val]) : poseidon([val, sv]);
                next.set(pi, BigInt(F.toString(h)));
            }
        }
        cur = next;
        ci = Math.floor(ci / 2);
    }
    return { root: cur.has(0) ? cur.get(0) : 0n, pathElements, pathIndices };
}

const poseidon = await buildPoseidon();
const F = poseidon.F;

// Mock Constants
const owner_sk_0 = 11111n;
const owner_sk_1 = 22222n;
const lp_owner_sk = 33333n;

const pk_0 = F.toObject(poseidon([owner_sk_0]));
const pk_1 = F.toObject(poseidon([owner_sk_1]));
const lp_pk = F.toObject(poseidon([lp_owner_sk]));

const asset_0 = 100n;
const asset_1 = 200n;
const lp_asset = 300n;

const amount_0 = 1000n;
const amount_1 = 2000n;
const blinding_0 = 12n;
const blinding_1 = 34n;

const pre_res_0 = 10000n;
const pre_res_1 = 20000n;
const pre_total_shares = 5000n;
const pre_res_blinding = 99n;

const shares = 500n; // proportional to 10%
const post_res_0 = pre_res_0 + amount_0;
const post_res_1 = pre_res_1 + amount_1;
const post_total_shares = pre_total_shares + shares;

const cm_0 = F.toObject(poseidon([amount_0, asset_0, blinding_0, pk_0]));
const cm_1 = F.toObject(poseidon([amount_1, asset_1, blinding_1, pk_1]));
const lp_commit = F.toObject(poseidon([shares, lp_asset, 56n, lp_pk]));

const { root, pathElements: path_0, pathIndices: idx_0 } = sparseProof([cm_0, cm_1], 0, 32, poseidon);
const { pathElements: path_1, pathIndices: idx_1 } = sparseProof([cm_0, cm_1], 1, 32, poseidon);

const nf_0 = F.toObject(poseidon([owner_sk_0, 0n, cm_0]));
const nf_1 = F.toObject(poseidon([owner_sk_1, 1n, cm_1]));

const reserve_pre_commit = F.toObject(poseidon([pre_res_0, pre_res_1, pre_total_shares, pre_res_blinding]));
const reserve_post_commit = F.toObject(poseidon([post_res_0, post_res_1, post_total_shares, pre_res_blinding]));

// Test add_liquidity
const validAddInput = {
    root: root.toString(),
    nf_in_0: nf_0.toString(),
    nf_in_1: nf_1.toString(),
    lp_commit: lp_commit.toString(),
    reserve_pre_commit: reserve_pre_commit.toString(),
    reserve_post_commit: reserve_post_commit.toString(),

    amount_in_0: amount_0.toString(),
    asset_in_0: asset_0.toString(),
    blinding_in_0: blinding_0.toString(),
    owner_sk_0: owner_sk_0.toString(),
    leaf_index_0: '0',
    path_0: path_0.map(String),
    idx_0: idx_0.map(String),

    amount_in_1: amount_1.toString(),
    asset_in_1: asset_1.toString(),
    blinding_in_1: blinding_1.toString(),
    owner_sk_1: owner_sk_1.toString(),
    leaf_index_1: '1',
    path_1: path_1.map(String),
    idx_1: idx_1.map(String),

    shares: shares.toString(),
    lp_asset: lp_asset.toString(),
    lp_blinding: '56',
    lp_owner_pk: lp_pk.toString(),

    pre_reserve_0: pre_res_0.toString(),
    pre_reserve_1: pre_res_1.toString(),
    pre_total_shares: pre_total_shares.toString(),
    pre_reserve_blinding: pre_res_blinding.toString(),

    post_reserve_0: post_res_0.toString(),
    post_reserve_1: post_res_1.toString(),
    post_total_shares: post_total_shares.toString(),
    post_reserve_blinding: pre_res_blinding.toString()
};

async function testAddLiquidity() {
    console.log('Testing add_liquidity valid case...');
    const wtns = { type: "mem" };
    try {
        await snarkjs.wtns.calculate(validAddInput, ADD_WASM, wtns);
        console.log('PASS: Valid add_liquidity witness generated');
    } catch(e) {
        console.log('Error generating witness! You must run the snarkjs dev ceremony build first.');
        process.exit(0);
    }

    // Negative: miscomputed shares
    const badSharesInput = { ...validAddInput, shares: (shares + 10n).toString() };
    badSharesInput.lp_commit = F.toObject(poseidon([shares + 10n, lp_asset, 56n, lp_pk])).toString();
    await expectFail(snarkjs.wtns.calculate(badSharesInput, ADD_WASM, wtns), 'Miscomputed shares rejected');

    // Negative: reserve transition wrong
    const badResInput = { ...validAddInput, post_reserve_0: (post_res_0 + 10n).toString() };
    badResInput.reserve_post_commit = F.toObject(poseidon([post_res_0 + 10n, post_res_1, post_total_shares, pre_res_blinding])).toString();
    await expectFail(snarkjs.wtns.calculate(badResInput, ADD_WASM, wtns), 'Wrong reserve transition rejected');

    // Negative: wrong nullifier
    const badNfInput = { ...validAddInput, nf_in_0: (nf_0 + 1n).toString() };
    await expectFail(snarkjs.wtns.calculate(badNfInput, ADD_WASM, wtns), 'Wrong nullifier rejected');
}

// Test remove_liquidity
const remove_amount_0 = 1000n; // 500 / 5000 * 10000 = 1000
const remove_amount_1 = 2000n; // 500 / 5000 * 20000 = 2000

const remove_post_res_0 = pre_res_0 - remove_amount_0;
const remove_post_res_1 = pre_res_1 - remove_amount_1;
const remove_post_shares = pre_total_shares - shares;

const cm_out_0 = F.toObject(poseidon([remove_amount_0, asset_0, 11n, pk_0]));
const cm_out_1 = F.toObject(poseidon([remove_amount_1, asset_1, 22n, pk_1]));

const { root: remove_root, pathElements: lp_path, pathIndices: lp_idx } = sparseProof([lp_commit], 0, 32, poseidon);
const lp_nf = F.toObject(poseidon([lp_owner_sk, 0n, lp_commit]));

const remove_post_commit = F.toObject(poseidon([remove_post_res_0, remove_post_res_1, remove_post_shares, pre_res_blinding]));

const validRemoveInput = {
    root: remove_root.toString(),
    lp_nf: lp_nf.toString(),
    cm_out_0: cm_out_0.toString(),
    cm_out_1: cm_out_1.toString(),
    reserve_pre_commit: reserve_pre_commit.toString(),
    reserve_post_commit: remove_post_commit.toString(),

    shares: shares.toString(),
    lp_asset: lp_asset.toString(),
    lp_blinding: '56',
    lp_owner_sk: lp_owner_sk.toString(),
    lp_leaf_index: '0',
    lp_path: lp_path.map(String),
    lp_idx: lp_idx.map(String),

    amount_out_0: remove_amount_0.toString(),
    asset_out_0: asset_0.toString(),
    blinding_out_0: '11',
    owner_pk_0: pk_0.toString(),

    amount_out_1: remove_amount_1.toString(),
    asset_out_1: asset_1.toString(),
    blinding_out_1: '22',
    owner_pk_1: pk_1.toString(),

    pre_reserve_0: pre_res_0.toString(),
    pre_reserve_1: pre_res_1.toString(),
    pre_total_shares: pre_total_shares.toString(),
    pre_reserve_blinding: pre_res_blinding.toString(),

    post_reserve_0: remove_post_res_0.toString(),
    post_reserve_1: remove_post_res_1.toString(),
    post_total_shares: remove_post_shares.toString(),
    post_reserve_blinding: pre_res_blinding.toString()
};

async function testRemoveLiquidity() {
    console.log('\nTesting remove_liquidity valid case...');
    const wtns = { type: "mem" };
    try {
        await snarkjs.wtns.calculate(validRemoveInput, REMOVE_WASM, wtns);
        console.log('PASS: Valid remove_liquidity witness generated');
    } catch(e) {
        console.log('Error generating witness! You must run the snarkjs dev ceremony build first.');
        process.exit(0);
    }

    // Negative: payout exceeds pro-rata
    const badPayoutInput = { ...validRemoveInput, amount_out_0: (remove_amount_0 + 10n).toString() };
    badPayoutInput.cm_out_0 = F.toObject(poseidon([remove_amount_0 + 10n, asset_0, 11n, pk_0])).toString();
    badPayoutInput.post_reserve_0 = (remove_post_res_0 - 10n).toString();
    badPayoutInput.reserve_post_commit = F.toObject(poseidon([remove_post_res_0 - 10n, remove_post_res_1, remove_post_shares, pre_res_blinding])).toString();
    await expectFail(snarkjs.wtns.calculate(badPayoutInput, REMOVE_WASM, wtns), 'Payout exceeding pro-rata rejected');
}

async function run() {
    await testAddLiquidity();
    await testRemoveLiquidity();
    console.log('\nALL PASS');
}

run();
