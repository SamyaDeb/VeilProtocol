/**
 * Witness test for lend.circom — verifies the circuit is satisfiable with
 * valid inputs and that negative cases correctly fail.
 *
 * Run from the repo root:
 *   node circuits/test_lend_witness.mjs
 *
 * Requires: npm install (circomlibjs, snarkjs); circuit compiled + keyed.
 *   circom circuits/lend.circom --r1cs --wasm -o circuits/build
 *   snarkjs groth16 setup circuits/build/lend.r1cs circuit-keys/pot17.ptau circuit-keys/dev/lend_0000.zkey
 *   snarkjs zkey contribute circuit-keys/dev/lend_0000.zkey circuit-keys/dev/lend_final.zkey --name="M6 dev" -v -e="$(openssl rand -hex 32)"
 *   snarkjs zkey export verificationkey circuit-keys/dev/lend_final.zkey circuit-keys/dev/vk_lend.json
 *
 * Phase 1 test plan (T1.1): see assertions below.
 */

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const WASM = path.join(ROOT, 'circuits/build/lend_js/lend.wasm');
const ZKEY = path.join(ROOT, 'circuit-keys/dev/lend_final.zkey');
const VK   = path.join(ROOT, 'circuit-keys/dev/vk_lend.json');

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

// ── Sparse Merkle helper (same as test_swap_witness.mjs) ────────────────────
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
        for (const [k, v] of cur.entries()) {
            const pi = Math.floor(k / 2);
            if (!next.has(pi)) {
                const isR = k % 2 === 1;
                const si  = isR ? k - 1 : k + 1;
                const sv  = cur.has(si) ? cur.get(si) : 0n;
                const h   = isR ? poseidon([sv, v]) : poseidon([v, sv]);
                next.set(pi, BigInt(F.toString(h)));
            }
        }
        cur = next;
        ci = Math.floor(ci / 2);
    }
    return { root: cur.has(0) ? cur.get(0) : 0n, pathElements, pathIndices };
}

// ── Common helpers ────────────────────────────────────────────────────────────

async function tryWitness(input, expectFail = false) {
    try {
        const result = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
        if (expectFail) return { ok: false, reason: 'expected failure but proof succeeded' };
        return { ok: true, result };
    } catch (e) {
        if (expectFail) return { ok: true };
        return { ok: false, reason: e.message };
    }
}

// ── Build base valid state ────────────────────────────────────────────────────

const poseidon = await buildPoseidon();
const F = poseidon.F;

const owner_sk      = 999999n;
const collat_amount = 10_000n;     // 10,000 units of collateral
const collat_asset  = 1n;
const collat_blinding = 111111n;

const oracle_price    = 100n;    // collateral price = 100 (same unit as borrow_price)
const oracle_decimals = 6n;      // 10^6 scale (public, not used in circuit arithmetic)
const ltv_max_bps     = 7500n;   // 75% LTV
const borrow_price    = 100n;    // borrow asset price = 100 (same units)

// max borrow: collat_amount * oracle_price * ltv_max_bps / (borrow_price * 10000)
//           = 10000 * 100 * 7500 / (100 * 10000) = 7500
const borrow_amount   = 7000n;   // 7000 < 7500 — within LTV
const borrow_asset    = 2n;
const borrow_blinding = 222222n;

const owner_pk = F.toObject(poseidon([owner_sk]));
const collat_cm = F.toObject(poseidon([collat_amount, collat_asset, collat_blinding, owner_pk]));

const DEPTH = 32;
const { root, pathElements, pathIndices } = sparseProof([collat_cm], 0, DEPTH, poseidon);

const collat_nf = F.toObject(poseidon([owner_sk, 0n, collat_cm]));
const borrow_cm_val = F.toObject(poseidon([borrow_amount, borrow_asset, borrow_blinding, owner_pk]));

function makeInput(overrides = {}) {
    const base = {
        // public
        root:            root.toString(),
        collat_nf:       collat_nf.toString(),
        borrow_cm:       borrow_cm_val.toString(),
        oracle_price:    oracle_price.toString(),
        oracle_decimals: oracle_decimals.toString(),
        ltv_max_bps:     ltv_max_bps.toString(),
        borrow_price:    borrow_price.toString(),
        // private: collateral
        collat_amount:   collat_amount.toString(),
        collat_asset:    collat_asset.toString(),
        collat_blinding: collat_blinding.toString(),
        owner_sk:        owner_sk.toString(),
        leaf_index:      '0',
        path:            pathElements.map(String),
        idx:             pathIndices.map(String),
        // private: borrow
        borrow_amount:   borrow_amount.toString(),
        borrow_asset:    borrow_asset.toString(),
        borrow_blinding: borrow_blinding.toString(),
    };
    return { ...base, ...overrides };
}

// ── Test 1: valid proof ───────────────────────────────────────────────────────

console.log('=== lend.circom witness tests ===\n');

console.log('Generating valid proof...');
const { proof: groth16Proof, publicSignals } = await snarkjs.groth16.fullProve(
    makeInput(), WASM, ZKEY
);

// Verify public signal ordering matches circuit header
assert(publicSignals[0] === root.toString(),            'Signal[0] = root');
assert(publicSignals[1] === collat_nf.toString(),       'Signal[1] = collat_nf');
assert(publicSignals[2] === borrow_cm_val.toString(),   'Signal[2] = borrow_cm');
assert(publicSignals[3] === oracle_price.toString(),    'Signal[3] = oracle_price');
assert(publicSignals[4] === oracle_decimals.toString(), 'Signal[4] = oracle_decimals');
assert(publicSignals[5] === ltv_max_bps.toString(),     'Signal[5] = ltv_max_bps');
assert(publicSignals[6] === borrow_price.toString(),    'Signal[6] = borrow_price');

console.log('\nVerifying off-chain...');
const vkJson = JSON.parse(readFileSync(VK, 'utf8'));
const ok = await snarkjs.groth16.verify(vkJson, publicSignals, groth16Proof);
assert(ok, 'Off-chain Groth16 verify accepts valid lend proof');

// ── Test 2: Exact-LTV boundary (borrow_amount = max) ─────────────────────────
// max = collat_amount * oracle_price * ltv_max_bps / (borrow_price * 10000)
//     = 10000 * 100 * 7500 / (100 * 10000) = 7500

const max_borrow = 7500n;
const max_borrow_cm = F.toObject(poseidon([max_borrow, borrow_asset, borrow_blinding, owner_pk]));

const exactLtvResult = await tryWitness(makeInput({
    borrow_amount: max_borrow.toString(),
    borrow_cm:     max_borrow_cm.toString(),
}));
assert(exactLtvResult.ok, 'Exact-LTV boundary borrow (7500) succeeds');

// ── Negative: T1.1 — over-LTV borrow (borrow_amount > max) ──────────────────
console.log('\n--- Negative tests (T1.1) ---');

const over_borrow = 7501n;
const over_borrow_cm = F.toObject(poseidon([over_borrow, borrow_asset, borrow_blinding, owner_pk]));

const overLtv = await tryWitness(makeInput({
    borrow_amount: over_borrow.toString(),
    borrow_cm:     over_borrow_cm.toString(),
}), /*expectFail=*/true);
assert(overLtv.ok, 'Over-LTV borrow (7501 > 7500 max) correctly rejected');

// ── Negative: wrong collat_nf (tampered) ────────────────────────────────────
const wrongNf = await tryWitness(makeInput({
    collat_nf: (collat_nf + 1n).toString(),
}), /*expectFail=*/true);
assert(wrongNf.ok, 'Wrong collat_nf correctly rejected');

// ── Negative: tampered Merkle path ──────────────────────────────────────────
const badPath = [...pathElements];
badPath[0] = (BigInt(badPath[0]) + 1n).toString();
const badMerkle = await tryWitness(makeInput({
    path: badPath,
}), /*expectFail=*/true);
assert(badMerkle.ok, 'Tampered Merkle path correctly rejected');

// ── Negative: collat_amount out of range (2^64 would fail range check) ──────
// 2^64 = 18446744073709551616
const tooBig = (2n ** 64n).toString();
const bigCm  = F.toObject(poseidon([2n ** 64n, collat_asset, collat_blinding, owner_pk]));
const bigNf  = F.toObject(poseidon([owner_sk, 0n, bigCm]));
const badRange = await tryWitness(makeInput({
    collat_amount: tooBig,
    collat_nf:     bigNf.toString(),
    borrow_cm:     borrow_cm_val.toString(),
}), /*expectFail=*/true);
assert(badRange.ok, 'Out-of-range collat_amount (2^64) correctly rejected');

// ── Negative: borrow_cm mismatch (wrong borrow note) ────────────────────────
const fakeCm = F.toObject(poseidon([9999n, 99n, 99n, owner_pk]));
const cmMismatch = await tryWitness(makeInput({
    borrow_cm: fakeCm.toString(),
}), /*expectFail=*/true);
assert(cmMismatch.ok, 'Borrow_cm mismatch correctly rejected');

// ── Negative: tampered public signal (off-chain verify rejects) ──────────────
const tampered = [...publicSignals];
tampered[2] = (BigInt(publicSignals[2]) + 1n).toString();
const notOk = await snarkjs.groth16.verify(vkJson, tampered, groth16Proof);
assert(!notOk, 'Off-chain verify rejects tampered borrow_cm public signal');

console.log('\n=== lend.circom witness test: ALL PASS ===');
