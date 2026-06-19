/**
 * Witness test for swap.circom — verifies the circuit is satisfiable with
 * valid inputs. Run from the repo root: node circuits/test_swap_witness.mjs
 */
import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const WASM = path.join(ROOT, 'circuits/build/swap_js/swap.wasm');
const ZKEY = path.join(ROOT, 'circuit-keys/dev/swap_final.zkey');
const VK   = path.join(ROOT, 'circuit-keys/dev/vk_swap.json');

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

// Sparse Merkle proof: does not allocate 2^depth array.
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

// ── Build a valid note ────────────────────────────────────────────────────────
const owner_sk  = 99999n;
const amount_in = 1000n;
const asset_in  = 1n;
const blinding  = 12345n;

const owner_pk = F.toObject(poseidon([owner_sk]));
const cm       = F.toObject(poseidon([amount_in, asset_in, blinding, owner_pk]));

// Sparse proof for a depth-32 tree with one leaf at index 0
const { root, pathElements, pathIndices } = sparseProof([cm], 0, 32, poseidon);

const nf_in = F.toObject(poseidon([owner_sk, 0n, cm]));

const COMMITTEE_PK  = 12345678901234567890n;
const r_enc         = 7777777n;
const asset_out     = 2n;
const min_out       = 900n;
const out_blinding  = 55555n;
const out_owner_pk  = F.toObject(poseidon([owner_sk + 1n]));

const enc_order_hash = F.toObject(poseidon([
    amount_in, asset_out, min_out, out_blinding, out_owner_pk, COMMITTEE_PK, r_enc,
]));

const input = {
    root:            root.toString(),
    nf_in:           nf_in.toString(),
    enc_order_hash:  enc_order_hash.toString(),
    committee_pk:    COMMITTEE_PK.toString(),

    amount_in:    amount_in.toString(),
    asset_in:     asset_in.toString(),
    blinding_in:  blinding.toString(),
    owner_sk:     owner_sk.toString(),
    leaf_index:   '0',
    path:         pathElements.map(String),
    idx:          pathIndices.map(String),

    asset_out:    asset_out.toString(),
    min_out:      min_out.toString(),
    out_blinding: out_blinding.toString(),
    out_owner_pk: out_owner_pk.toString(),
    r_enc:        r_enc.toString(),
};

// ── Witness + proof ───────────────────────────────────────────────────────────
console.log('Generating witness for swap.circom...');
const { proof: groth16Proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);

assert(publicSignals[0] === root.toString(),           'Public signal[0] matches root');
assert(publicSignals[1] === nf_in.toString(),          'Public signal[1] matches nf_in');
assert(publicSignals[2] === enc_order_hash.toString(), 'Public signal[2] matches enc_order_hash');
assert(publicSignals[3] === COMMITTEE_PK.toString(),   'Public signal[3] matches committee_pk');

console.log('Verifying proof off-chain...');
const vkJson = JSON.parse(readFileSync(VK, 'utf8'));
const ok = await snarkjs.groth16.verify(vkJson, publicSignals, groth16Proof);
assert(ok, 'Off-chain Groth16 verify accepts valid swap proof');

// ── Negative: tampered nf_in rejected ────────────────────────────────────────
console.log('Testing negative: tampered public signal rejected...');
const tampered = [...publicSignals];
tampered[1] = (BigInt(publicSignals[1]) + 1n).toString();
const notOk = await snarkjs.groth16.verify(vkJson, tampered, groth16Proof);
assert(!notOk, 'Off-chain verify rejects tampered nf_in');

console.log('\nswap.circom witness test: ALL PASS');
