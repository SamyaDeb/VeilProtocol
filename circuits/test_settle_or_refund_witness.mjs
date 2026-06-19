/**
 * Witness test for settle_or_refund.circom — verifies the circuit is satisfiable
 * with valid inputs and that negative cases correctly fail (M7 Phase 1A).
 *
 * Run from the repo root:
 *   node circuits/test_settle_or_refund_witness.mjs
 *
 * Requires: npm install (circomlibjs, snarkjs); circuit compiled + keyed.
 *   circom circuits/settle_or_refund.circom --r1cs --wasm -o circuits/build
 *   snarkjs groth16 setup circuits/build/settle_or_refund.r1cs circuit-keys/pot17.ptau circuit-keys/dev/settle_or_refund_0000.zkey
 *   snarkjs zkey contribute circuit-keys/dev/settle_or_refund_0000.zkey circuit-keys/dev/settle_or_refund_final.zkey --name="M7 dev" -v -e="$(openssl rand -hex 32)"
 *   snarkjs zkey export verificationkey circuit-keys/dev/settle_or_refund_final.zkey circuit-keys/dev/vk_settle_or_refund.json
 */

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const WASM = path.join(ROOT, 'circuits/build/settle_or_refund_js/settle_or_refund.wasm');
const ZKEY = path.join(ROOT, 'circuit-keys/dev/settle_or_refund_final.zkey');
const VK   = path.join(ROOT, 'circuit-keys/dev/vk_settle_or_refund.json');

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

// ── Sparse Merkle helper (same pattern as test_lend_witness.mjs) ─────────────
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

const owner_sk  = 12345678n;
const amount    = 5000n;
const asset_id  = 1n;
const blinding  = 987654n;

const owner_pk  = BigInt(F.toString(poseidon([owner_sk])));
const cm_in     = BigInt(F.toString(poseidon([amount, asset_id, blinding, owner_pk])));

const DEPTH = 32;
const { root, pathElements, pathIndices } = sparseProof([cm_in], 0, DEPTH, poseidon);

const nf_in     = BigInt(F.toString(poseidon([owner_sk, 0n, cm_in])));

// Refund output note: same amount/asset, fresh blinding + same pk (can differ)
const out_blinding  = 111111n;
const out_owner_pk  = owner_pk;
const cm_refund_val = BigInt(F.toString(poseidon([amount, asset_id, out_blinding, out_owner_pk])));

const batch_id       = 7n;
const batch_deadline = 1000n;

function makeInput(overrides = {}) {
    return {
        // public
        batch_id:       batch_id.toString(),
        nf_in:          nf_in.toString(),
        cm_refund:      cm_refund_val.toString(),
        root:           root.toString(),
        batch_deadline: batch_deadline.toString(),
        // private: original note
        amount:         amount.toString(),
        asset_id:       asset_id.toString(),
        blinding:       blinding.toString(),
        owner_sk:       owner_sk.toString(),
        leaf_index:     '0',
        path:           pathElements.map(String),
        idx:            pathIndices.map(String),
        // private: refund output
        out_blinding:   out_blinding.toString(),
        out_owner_pk:   out_owner_pk.toString(),
        ...overrides,
    };
}

// ── Test 1: valid refund proof ─────────────────────────────────────────────────

console.log('=== settle_or_refund.circom witness tests ===\n');
console.log('Generating valid proof...');

const { proof: groth16Proof, publicSignals } = await snarkjs.groth16.fullProve(
    makeInput(), WASM, ZKEY
);

// Verify public signal ordering matches circuit header comment
assert(publicSignals[0] === batch_id.toString(),       'Signal[0] = batch_id');
assert(publicSignals[1] === nf_in.toString(),          'Signal[1] = nf_in');
assert(publicSignals[2] === cm_refund_val.toString(),  'Signal[2] = cm_refund');
assert(publicSignals[3] === root.toString(),           'Signal[3] = root');
assert(publicSignals[4] === batch_deadline.toString(), 'Signal[4] = batch_deadline');

console.log('\nVerifying off-chain...');
const vkJson = JSON.parse(readFileSync(VK, 'utf8'));
const ok = await snarkjs.groth16.verify(vkJson, publicSignals, groth16Proof);
assert(ok, 'Off-chain Groth16 verify accepts valid settle_or_refund proof');

// ── Negative tests ────────────────────────────────────────────────────────────

console.log('\n--- Negative tests ---');

// Wrong owner_sk → wrong nf_in → circuit rejects
const wrongOwnerSk  = owner_sk + 1n;
const wrongOwnerPk  = BigInt(F.toString(poseidon([wrongOwnerSk])));
const wrongCmIn     = BigInt(F.toString(poseidon([amount, asset_id, blinding, wrongOwnerPk])));
const wrongNf       = BigInt(F.toString(poseidon([wrongOwnerSk, 0n, wrongCmIn])));
const { root: wrongRoot, pathElements: wpe, pathIndices: wpi } = sparseProof([wrongCmIn], 0, DEPTH, poseidon);

const wrongSk = await tryWitness(makeInput({
    owner_sk: wrongOwnerSk.toString(),
    nf_in:    wrongNf.toString(),   // this matches wrongOwnerSk but root doesn't match original
}), /*expectFail=*/true);
assert(wrongSk.ok, 'Wrong owner_sk (root mismatch) correctly rejected');

// Tampered nf_in (doesn't match owner_sk + leaf_index + cm_in)
const tamperedNf = await tryWitness(makeInput({
    nf_in: (nf_in + 1n).toString(),
}), /*expectFail=*/true);
assert(tamperedNf.ok, 'Tampered nf_in correctly rejected');

// Tampered cm_refund (different amount — doesn't match out_blinding/out_owner_pk)
const wrong_cm_refund = BigInt(F.toString(poseidon([amount + 1n, asset_id, out_blinding, out_owner_pk])));
const tamperedCmRefund = await tryWitness(makeInput({
    cm_refund: wrong_cm_refund.toString(),
}), /*expectFail=*/true);
assert(tamperedCmRefund.ok, 'Tampered cm_refund (amount mismatch) correctly rejected');

// Tampered Merkle path
const badPath = [...pathElements];
badPath[0] = (BigInt(String(badPath[0])) + 1n).toString();
const badMerkle = await tryWitness(makeInput({
    path: badPath,
}), /*expectFail=*/true);
assert(badMerkle.ok, 'Tampered Merkle path correctly rejected');

// Out-of-range amount (2^64)
const tooBig = (2n ** 64n).toString();
const bigPk  = owner_pk;
const bigCm  = BigInt(F.toString(poseidon([2n ** 64n, asset_id, blinding, bigPk])));
const bigNf  = BigInt(F.toString(poseidon([owner_sk, 0n, bigCm])));
const { root: bigRoot, pathElements: bpe, pathIndices: bpi } = sparseProof([bigCm], 0, DEPTH, poseidon);
const bigCmRefund = BigInt(F.toString(poseidon([2n ** 64n, asset_id, out_blinding, out_owner_pk])));

const badRange = await tryWitness({
    batch_id:       batch_id.toString(),
    nf_in:          bigNf.toString(),
    cm_refund:      bigCmRefund.toString(),
    root:           bigRoot.toString(),
    batch_deadline: batch_deadline.toString(),
    amount:         tooBig,
    asset_id:       asset_id.toString(),
    blinding:       blinding.toString(),
    owner_sk:       owner_sk.toString(),
    leaf_index:     '0',
    path:           bpe.map(String),
    idx:            bpi.map(String),
    out_blinding:   out_blinding.toString(),
    out_owner_pk:   out_owner_pk.toString(),
}, /*expectFail=*/true);
assert(badRange.ok, 'Out-of-range amount (2^64) correctly rejected');

// Off-chain tampered public signal
const tampered = [...publicSignals];
tampered[1] = (BigInt(publicSignals[1]) + 1n).toString(); // tamper nf_in
const notOk = await snarkjs.groth16.verify(vkJson, tampered, groth16Proof);
assert(!notOk, 'Off-chain verify rejects tampered nf_in public signal');

console.log('\n=== settle_or_refund.circom witness tests: ALL PASS ===');
