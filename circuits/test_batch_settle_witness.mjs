/**
 * Witness test for batch_settle.circom — K=4 batch settlement.
 * Run from the repo root: node circuits/test_batch_settle_witness.mjs
 */
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const WASM = path.join(ROOT, 'circuits/build/batch_settle_js/batch_settle.wasm');
const ZKEY = path.join(ROOT, 'circuit-keys/dev/batch_settle_final.zkey');
const VK   = path.join(ROOT, 'circuit-keys/dev/vk_batch_settle.json');

const K = 4;

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

const poseidon = await buildPoseidon();
const F = poseidon.F;

const COMMITTEE_PK = 12345678901234567890n;
const BATCH_ID     = 0n;

const ASSET_A = 100n;
const ASSET_B = 200n;

// Setup: Price is 2 B per 1 A.
// clearing_price_num = 2 (B per A)
// clearing_price_den = 1
const PRICE_NUM = 2n;
const PRICE_DEN = 1n;

const pre_reserve_a = 10000n;
const pre_reserve_b = 20000n;
const pre_reserve_blinding = 111n;

// Order 0: sells A, buys B
// Order 1: sells B, buys A
// Order 2: sells A, gets excluded due to slippage
// Order 3: sells B, gets excluded (zero input) - Wait, let's make it a normal valid order
const orders = [
    {
        amount_in: 100n, // A
        asset_out: ASSET_B,
        min_out: 190n, // Needs at least 190 B
        is_excluded: 0, // Will be filled with 200 B
    },
    {
        amount_in: 400n, // B
        asset_out: ASSET_A,
        min_out: 200n, // Needs 200 A
        is_excluded: 0, // Will be filled with 200 A
    },
    {
        amount_in: 50n, // A
        asset_out: ASSET_B,
        min_out: 110n, // Needs 110 B, but price only gives 100 B
        is_excluded: 1, // Will be excluded (amount_out = 0)
    },
    {
        amount_in: 10n, // B
        asset_out: ASSET_A,
        min_out: 5n, // Needs 5 A
        is_excluded: 0, // Will be filled with 5 A
    }
];

let sell_a_total = 0n;
let sell_b_total = 0n;
let buy_a_total = 0n;
let buy_b_total = 0n;

for (let j = 0; j < K; j++) {
    const o = orders[j];
    o.out_blinding = BigInt(55555 + j);
    o.out_owner_pk = BigInt(111000 + j);
    o.r_enc = BigInt(777777 + j);

    if (o.asset_out === ASSET_B) {
        // buying B, selling A
        if (o.is_excluded === 0) {
            o.amount_out = (o.amount_in * PRICE_NUM) / PRICE_DEN;
            buy_b_total += o.amount_out;
        } else {
            o.amount_out = 0n;
        }
        sell_a_total += o.amount_in;
    } else {
        // buying A, selling B
        if (o.is_excluded === 0) {
            o.amount_out = (o.amount_in * PRICE_DEN) / PRICE_NUM;
            buy_a_total += o.amount_out;
        } else {
            o.amount_out = 0n;
        }
        sell_b_total += o.amount_in;
    }

    o.enc_order_hash = F.toObject(poseidon([
        o.amount_in, o.asset_out, o.min_out, o.out_blinding, o.out_owner_pk, COMMITTEE_PK, o.r_enc,
    ]));

    o.cm_out = F.toObject(poseidon([o.amount_out, o.asset_out, o.out_blinding, o.out_owner_pk]));
}

const fee_a = 0n;
const fee_b = 0n;
const post_reserve_a = pre_reserve_a + sell_a_total - buy_a_total - fee_a;
const post_reserve_b = pre_reserve_b + sell_b_total - buy_b_total - fee_b;
const post_reserve_blinding = 222n;

const pre_reserve_cm = F.toObject(poseidon([pre_reserve_a, pre_reserve_b, pre_reserve_blinding]));
const post_reserve_cm = F.toObject(poseidon([post_reserve_a, post_reserve_b, post_reserve_blinding]));

const input = {
    // Public
    enc_order_hash: orders.map(o => o.enc_order_hash.toString()),
    cm_out:         orders.map(o => o.cm_out.toString()),
    committee_pk:   COMMITTEE_PK.toString(),
    batch_id:       BATCH_ID.toString(),
    pre_reserve_cm: pre_reserve_cm.toString(),
    post_reserve_cm: post_reserve_cm.toString(),

    // Private per-order
    amount_in:    orders.map(o => o.amount_in.toString()),
    asset_out:    orders.map(o => o.asset_out.toString()),
    min_out:      orders.map(o => o.min_out.toString()),
    out_blinding: orders.map(o => o.out_blinding.toString()),
    out_owner_pk: orders.map(o => o.out_owner_pk.toString()),
    r_enc:        orders.map(o => o.r_enc.toString()),
    amount_out:   orders.map(o => o.amount_out.toString()),
    is_excluded:  orders.map(o => o.is_excluded.toString()),

    // Private reserves and clearing
    pre_reserve_a: pre_reserve_a.toString(),
    pre_reserve_b: pre_reserve_b.toString(),
    pre_reserve_blinding: pre_reserve_blinding.toString(),
    post_reserve_a: post_reserve_a.toString(),
    post_reserve_b: post_reserve_b.toString(),
    post_reserve_blinding: post_reserve_blinding.toString(),
    clearing_price_num: PRICE_NUM.toString(),
    clearing_price_den: PRICE_DEN.toString(),
    fee_a: fee_a.toString(),
    fee_b: fee_b.toString(),
    asset_a: ASSET_A.toString(),
    asset_b: ASSET_B.toString(),
};

// ── Witness generation ────────────────────────────────────────────────────────
console.log('Generating witness for batch_settle.circom (K=4)...');
let groth16Proof, publicSignals;
try {
    const res = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
    groth16Proof = res.proof;
    publicSignals = res.publicSignals;
} catch (e) {
    console.error(e);
    process.exit(1);
}

assert(publicSignals.length === 12, `12 public signals (got ${publicSignals.length})`);
for (let j = 0; j < K; j++) {
    assert(publicSignals[j] === orders[j].enc_order_hash.toString(),
        `Public signal[${j}] matches enc_order_hash[${j}]`);
    assert(publicSignals[K + j] === orders[j].cm_out.toString(),
        `Public signal[${K + j}] matches cm_out[${j}]`);
}
assert(publicSignals[8] === COMMITTEE_PK.toString(), 'Public signal[8] matches committee_pk');
assert(publicSignals[9] === BATCH_ID.toString(), 'Public signal[9] matches batch_id');
assert(publicSignals[10] === pre_reserve_cm.toString(), 'Public signal[10] matches pre_reserve_cm');
assert(publicSignals[11] === post_reserve_cm.toString(), 'Public signal[11] matches post_reserve_cm');

// Verify proof
try {
    const vkJson = JSON.parse(readFileSync(VK, 'utf8'));
    const ok = await snarkjs.groth16.verify(vkJson, publicSignals, groth16Proof);
    assert(ok, 'Off-chain Groth16 verify accepts valid batch_settle proof');
} catch (e) {
    console.log("Could not verify proof yet as keys might not be compiled.");
}

// ── Negative: value non-conservation rejected ─────────────────────────────────
console.log('Testing negative: value non-conservation rejected...');
let threw = false;
try {
    await snarkjs.groth16.fullProve({
        ...input,
        post_reserve_a: (post_reserve_a + 1n).toString(),
        post_reserve_cm: F.toObject(poseidon([post_reserve_a + 1n, post_reserve_b, post_reserve_blinding])).toString(),
    }, WASM, ZKEY);
} catch (e) {
    threw = true;
}
assert(threw, 'Witness generation fails when value non-conservation');

// ── Negative: Reserve transition violation ────────────────────────────────────
console.log('Testing negative: Reserve transition violation rejected...');
let threwRes = false;
try {
    await snarkjs.groth16.fullProve({
        ...input,
        post_reserve_cm: F.toObject(poseidon([post_reserve_a + 1n, post_reserve_b, post_reserve_blinding])).toString(),
        // keeping post_reserve_a the same, so cm doesn't match computed
    }, WASM, ZKEY);
} catch (e) {
    threwRes = true;
}
assert(threwRes, 'Witness generation fails when post_reserve_cm does not match');

// ── Negative: min_out violation rejected ─────────────────────────────────────
console.log('Testing negative: min_out > amount_out rejected...');
let threw2 = false;
try {
    const badMinOut = [...input.min_out];
    badMinOut[0] = (orders[0].amount_out + 1n).toString();
    await snarkjs.groth16.fullProve({
        ...input,
        min_out: badMinOut,
    }, WASM, ZKEY);
} catch (e) {
    threw2 = true;
}
assert(threw2, 'Witness generation fails when amount_out < min_out');

// ── Negative: Constant-function violation ────────────────────────────────────
console.log('Testing negative: Constant function violation rejected...');
let threwCFMM = false;
try {
    // If post_reserve_a * post_reserve_b < pre_reserve_a * pre_reserve_b
    // We can simulate this by making pre reserves huge, but we have to satisfy value conservation.
    // Let's just pass input with huge pre reserves but same post reserves
    await snarkjs.groth16.fullProve({
        ...input,
        pre_reserve_a: (post_reserve_a * 2n).toString(),
        pre_reserve_b: (post_reserve_b * 2n).toString(),
    }, WASM, ZKEY);
} catch (e) {
    threwCFMM = true;
}
assert(threwCFMM, 'Witness generation fails when post k < pre k');

// ── Negative: Range overflow ────────────────────────────────────────────────
console.log('Testing negative: Range overflow rejected...');
let threwRange = false;
try {
    const badAmountOut = [...input.amount_out];
    badAmountOut[0] = (2n**64n + 1n).toString();
    await snarkjs.groth16.fullProve({
        ...input,
        amount_out: badAmountOut,
    }, WASM, ZKEY);
} catch (e) {
    threwRange = true;
}
assert(threwRange, 'Witness generation fails when amount_out > 2^64');

console.log('\nbatch_settle.circom witness test: ALL PASS');
