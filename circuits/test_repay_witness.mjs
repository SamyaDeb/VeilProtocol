/**
 * Witness test for repay.circom — verifies the circuit is satisfiable with valid
 * inputs and that negative cases correctly fail (M7 Phase 1B).
 *
 * Run from the repo root:
 *   node circuits/test_repay_witness.mjs
 *
 * Requires: npm install (circomlibjs, snarkjs); circuit compiled + keyed.
 *   circom circuits/repay.circom --r1cs --wasm -o circuits/build
 *   snarkjs groth16 setup circuits/build/repay.r1cs circuit-keys/pot17.ptau circuit-keys/dev/repay_0000.zkey
 *   snarkjs zkey contribute circuit-keys/dev/repay_0000.zkey circuit-keys/dev/repay_final.zkey --name="M7 dev" -v -e="$(openssl rand -hex 32)"
 *   snarkjs zkey export verificationkey circuit-keys/dev/repay_final.zkey circuit-keys/dev/vk_repay.json
 */

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const WASM = path.join(ROOT, 'circuits/build/repay_js/repay.wasm');
const ZKEY = path.join(ROOT, 'circuit-keys/dev/repay_final.zkey');
const VK   = path.join(ROOT, 'circuit-keys/dev/vk_repay.json');

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

// ── Sparse Merkle helper ──────────────────────────────────────────────────────
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

// The borrow note — this is what the borrower must spend when repaying.
// In practice this note is held by the borrower (received when the loan was opened).
const owner_sk  = 99887766n;
const amount    = 3000n;
const asset_id  = 2n;   // borrow asset (e.g. USDC)
const blinding  = 555555n;

const owner_pk  = BigInt(F.toString(poseidon([owner_sk])));
const borrow_cm = BigInt(F.toString(poseidon([amount, asset_id, blinding, owner_pk])));

const DEPTH = 32;
const { root, pathElements, pathIndices } = sparseProof([borrow_cm], 0, DEPTH, poseidon);

// repay_nf: nullifier of the borrow note — proves the borrower owns it
const repay_nf = BigInt(F.toString(poseidon([owner_sk, 0n, borrow_cm])));

function makeInput(overrides = {}) {
    return {
        // public inputs (order must match circuit header: root, repay_nf, borrow_cm)
        root:      root.toString(),
        repay_nf:  repay_nf.toString(),
        borrow_cm: borrow_cm.toString(),
        // private inputs
        amount:    amount.toString(),
        asset_id:  asset_id.toString(),
        blinding:  blinding.toString(),
        owner_sk:  owner_sk.toString(),
        leaf_index: '0',
        path:      pathElements.map(String),
        idx:       pathIndices.map(String),
        ...overrides,
    };
}

// ── Test 1: valid repay proof ─────────────────────────────────────────────────

console.log('=== repay.circom witness tests ===\n');
console.log('Generating valid proof...');

const { proof: groth16Proof, publicSignals } = await snarkjs.groth16.fullProve(
    makeInput(), WASM, ZKEY
);

// Verify public signal ordering matches circuit header comment
assert(publicSignals[0] === root.toString(),      'Signal[0] = root');
assert(publicSignals[1] === repay_nf.toString(),  'Signal[1] = repay_nf');
assert(publicSignals[2] === borrow_cm.toString(), 'Signal[2] = borrow_cm');

console.log('\nVerifying off-chain...');
const vkJson = JSON.parse(readFileSync(VK, 'utf8'));
const ok = await snarkjs.groth16.verify(vkJson, publicSignals, groth16Proof);
assert(ok, 'Off-chain Groth16 verify accepts valid repay proof');

// ── Negative tests ────────────────────────────────────────────────────────────

console.log('\n--- Negative tests ---');

// Wrong owner_sk → correct nullifier computation but wrong borrow_cm in tree
const wrongOwnerSk = owner_sk + 1n;
const wrongOwnerPk = BigInt(F.toString(poseidon([wrongOwnerSk])));
const wrongBorrowCm = BigInt(F.toString(poseidon([amount, asset_id, blinding, wrongOwnerPk])));
const wrongRepayNf  = BigInt(F.toString(poseidon([wrongOwnerSk, 0n, wrongBorrowCm])));
const { root: wrongRoot, pathElements: wpe, pathIndices: wpi } = sparseProof([wrongBorrowCm], 0, DEPTH, poseidon);

const wrongSk = await tryWitness(makeInput({
    owner_sk:  wrongOwnerSk.toString(),
    repay_nf:  wrongRepayNf.toString(),
    borrow_cm: wrongBorrowCm.toString(),
    // root still points to original tree — Merkle check will fail
}), /*expectFail=*/true);
assert(wrongSk.ok, 'Wrong owner_sk (Merkle root mismatch) correctly rejected');

// Tampered repay_nf (doesn't match owner_sk + leaf_index + borrow_cm)
const badNf = await tryWitness(makeInput({
    repay_nf: (repay_nf + 1n).toString(),
}), /*expectFail=*/true);
assert(badNf.ok, 'Tampered repay_nf correctly rejected');

// Wrong borrow_cm (attacker claims a different commitment — closes M6 soundness gap:
// contract passes stored borrow_cm as public input, so this cannot be forged,
// but the circuit must also enforce it independently)
const falseBorrowCm = BigInt(F.toString(poseidon([amount + 500n, asset_id, blinding, owner_pk])));
const badBorrowCm = await tryWitness(makeInput({
    borrow_cm: falseBorrowCm.toString(),
    // private inputs still reflect the real note — cm derivation won't match
}), /*expectFail=*/true);
assert(badBorrowCm.ok, 'Wrong borrow_cm (private inputs mismatch) correctly rejected');

// Tampered Merkle path
const badPath = [...pathElements];
badPath[0] = (BigInt(String(badPath[0])) + 1n).toString();
const badMerkle = await tryWitness(makeInput({
    path: badPath,
}), /*expectFail=*/true);
assert(badMerkle.ok, 'Tampered Merkle path correctly rejected');

// Out-of-range amount (2^64) — range check must catch it
const bigAmount = 2n ** 64n;
const bigPk     = owner_pk;
const bigCm     = BigInt(F.toString(poseidon([bigAmount, asset_id, blinding, bigPk])));
const bigNf     = BigInt(F.toString(poseidon([owner_sk, 0n, bigCm])));
const { root: bigRoot, pathElements: bpe, pathIndices: bpi } = sparseProof([bigCm], 0, DEPTH, poseidon);

const badRange = await tryWitness({
    root:       bigRoot.toString(),
    repay_nf:   bigNf.toString(),
    borrow_cm:  bigCm.toString(),
    amount:     bigAmount.toString(),
    asset_id:   asset_id.toString(),
    blinding:   blinding.toString(),
    owner_sk:   owner_sk.toString(),
    leaf_index: '0',
    path:       bpe.map(String),
    idx:        bpi.map(String),
}, /*expectFail=*/true);
assert(badRange.ok, 'Out-of-range amount (2^64) correctly rejected');

// Off-chain tampered public signal — borrow_cm flipped; proof still for original
const tampered = [...publicSignals];
tampered[2] = (BigInt(publicSignals[2]) + 1n).toString();
const notOk = await snarkjs.groth16.verify(vkJson, tampered, groth16Proof);
assert(!notOk, 'Off-chain verify rejects tampered borrow_cm public signal');

console.log('\n=== repay.circom witness tests: ALL PASS ===');
