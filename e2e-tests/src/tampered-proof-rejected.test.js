/**
 * tampered-proof-rejected.test.js — M7 Phase 3B soundness gate
 *
 * For each circuit that has a dev key pinned in circuit-keys/dev/, this test:
 *   1. Builds a valid Groth16 proof using the circuit's WASM + final zkey.
 *   2. Verifies it passes off-chain (snarkjs.groth16.verify).
 *   3. Byte-flips one coordinate in pi_a[0][0]+1 to produce a tampered proof.
 *   4. Asserts the tampered proof is rejected off-chain.
 *   5. If VEIL_CORE + SOROBAN_RPC are set, also submits to veil_core.verify_groth16
 *      on-chain and asserts the result is false (on-chain soundness check).
 *
 * Run locally (off-chain only):
 *   node e2e-tests/src/tampered-proof-rejected.test.js
 *
 * Run with on-chain check (testnet):
 *   VEIL_CORE=<contract-id> SOROBAN_RPC=<url> SECRET=<signing-key> \
 *     node e2e-tests/src/tampered-proof-rejected.test.js
 *
 * M7 exit-gate requirement: all circuits listed below must produce "TAMPERED
 * REJECTED" for the test to exit 0.
 */

import * as snarkjs from 'snarkjs';
import { buildPoseidon } from 'circomlibjs';
import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk';
import path from 'path';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../../..');
const KEYS = path.join(ROOT, 'circuit-keys/dev');
const BUILD = path.join(ROOT, 'circuits/build');

const CORE_ID  = process.env.VEIL_CORE ?? '';
const RPC_URL  = process.env.SOROBAN_RPC ?? '';
const SECRET   = process.env.SECRET ?? '';
const NETWORK  = process.env.NETWORK ?? 'testnet';

const ON_CHAIN = !!(CORE_ID && RPC_URL && SECRET);

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

// ── Poseidon helper ───────────────────────────────────────────────────────────
const poseidon = await buildPoseidon();
const F = poseidon.F;

function pos(...args) { return BigInt(F.toString(poseidon(args))); }

function sparseProof(leaf, targetIdx, depth) {
    let cur = new Map([[targetIdx, leaf]]);
    const pe = [], pi = [];
    let ci = targetIdx;
    for (let d = 0; d < depth; d++) {
        const isR = ci % 2 === 1;
        pi.push(isR ? 1 : 0);
        const sib = isR ? ci - 1 : ci + 1;
        pe.push(cur.has(sib) ? cur.get(sib) : 0n);
        const next = new Map();
        for (const [k, v] of cur.entries()) {
            const p = Math.floor(k / 2);
            if (!next.has(p)) {
                const ir = k % 2 === 1;
                const s = ir ? k - 1 : k + 1;
                const sv = cur.has(s) ? cur.get(s) : 0n;
                next.set(p, pos(...(ir ? [sv, v] : [v, sv])));
            }
        }
        cur = next;
        ci = Math.floor(ci / 2);
    }
    return { root: cur.get(0) ?? 0n, pe, pi };
}

// ── Circuit definitions — inputs factory + file paths ─────────────────────────
//
// Each entry provides:
//   name:   circuit name (must match build/ and circuit-keys/dev/ naming)
//   vkId:   VkId variant name expected by veil_core (on-chain check only)
//   inputs: function returning a valid input object for snarkjs.groth16.fullProve

const D = 32;

// Shared note for circuits that spend a note
const SK   = 12345n;
const AMT  = 1000n;
const AID  = 1n;
const BLI  = 9999n;
const PK   = pos(SK);
const CM   = pos(AMT, AID, BLI, PK);
const { root: TREE_ROOT, pe: TREE_PE, pi: TREE_PI } = sparseProof(CM, 0, D);
const NF   = pos(SK, 0n, CM);

const CIRCUITS = [
    {
        name: 'swap',
        vkId: 'Swap',
        inputs: () => {
            // enc_order_hash: pos(amount_in, asset_out, min_out, out_blinding, out_owner_pk, committee_pk, r_enc)
            const committee_pk = 77777n;
            const r_enc        = 888n;
            const asset_out    = 2n;
            const min_out      = 500n;
            const out_blinding = 111n;
            const enc = pos(AMT, asset_out, min_out, out_blinding, PK, committee_pk, r_enc);
            return {
                root:           TREE_ROOT.toString(),
                nf_in:          NF.toString(),
                enc_order_hash: enc.toString(),
                committee_pk:   committee_pk.toString(),
                amount_in:      AMT.toString(),
                asset_in:       AID.toString(),
                blinding_in:    BLI.toString(),
                owner_sk:       SK.toString(),
                leaf_index:     '0',
                path:           TREE_PE.map(String),
                idx:            TREE_PI.map(String),
                asset_out:      asset_out.toString(),
                min_out:        min_out.toString(),
                out_blinding:   out_blinding.toString(),
                out_owner_pk:   PK.toString(),
                r_enc:          r_enc.toString(),
            };
        },
    },
    {
        name: 'lend',
        vkId: 'Lend',
        inputs: () => {
            const borrow_amt = 500n, borrow_asset = 2n, borrow_bli = 222n;
            const borrow_cm  = pos(borrow_amt, borrow_asset, borrow_bli, PK);
            const oracle_price = 1000n, oracle_dec = 7n, ltv = 7500n, borrow_price = 1000n;
            return {
                root:           TREE_ROOT.toString(),
                collat_nf:      NF.toString(),
                borrow_cm:      borrow_cm.toString(),
                oracle_price:   oracle_price.toString(),
                oracle_decimals: oracle_dec.toString(),
                ltv_max_bps:    ltv.toString(),
                borrow_price:   borrow_price.toString(),
                collat_amount:  AMT.toString(),
                collat_asset:   AID.toString(),
                collat_blinding: BLI.toString(),
                owner_sk:       SK.toString(),
                leaf_index:     '0',
                path:           TREE_PE.map(String),
                idx:            TREE_PI.map(String),
                borrow_amount:  borrow_amt.toString(),
                borrow_asset:   borrow_asset.toString(),
                borrow_blinding: borrow_bli.toString(),
            };
        },
    },
    {
        name: 'repay',
        vkId: 'Repay',
        inputs: () => ({
            root:       TREE_ROOT.toString(),
            repay_nf:   NF.toString(),
            borrow_cm:  CM.toString(),
            amount:     AMT.toString(),
            asset_id:   AID.toString(),
            blinding:   BLI.toString(),
            owner_sk:   SK.toString(),
            leaf_index: '0',
            path:       TREE_PE.map(String),
            idx:        TREE_PI.map(String),
        }),
    },
    {
        name: 'settle_or_refund',
        vkId: 'SettleOrRefund',
        inputs: () => {
            const out_bli = 3333n;
            const cm_ref  = pos(AMT, AID, out_bli, PK);
            return {
                batch_id:       '7',
                nf_in:          NF.toString(),
                cm_refund:      cm_ref.toString(),
                root:           TREE_ROOT.toString(),
                batch_deadline: '1000',
                amount:         AMT.toString(),
                asset_id:       AID.toString(),
                blinding:       BLI.toString(),
                owner_sk:       SK.toString(),
                leaf_index:     '0',
                path:           TREE_PE.map(String),
                idx:            TREE_PI.map(String),
                out_blinding:   out_bli.toString(),
                out_owner_pk:   PK.toString(),
            };
        },
    },
];

// ── On-chain helper (only runs when env vars are present) ─────────────────────
async function verifyOnChain(circuitName, vkId, proof, publicSignals) {
    if (!ON_CHAIN) return null;

    const server  = new rpc.Server(RPC_URL);
    const kp      = Keypair.fromSecret(SECRET);
    const account = await server.getAccount(kp.publicKey());
    const core    = new Contract(CORE_ID);
    const network = NETWORK === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;

    // Serialize proof as bytes: pi_a (G1, 64 bytes) || pi_b (G2, 128 bytes) || pi_c (G1, 64 bytes)
    function hexToBytes32(hex) {
        const buf = Buffer.from(BigInt(hex).toString(16).padStart(64, '0'), 'hex');
        return xdr.ScVal.scvBytes(buf);
    }
    function encodeG1(pt) {
        const x = hexToBytes32('0x' + BigInt(pt[0]).toString(16));
        const y = hexToBytes32('0x' + BigInt(pt[1]).toString(16));
        return xdr.ScVal.scvVec([x, y]);
    }
    function encodeG2(pt) {
        const x0 = hexToBytes32('0x' + BigInt(pt[0][0]).toString(16));
        const x1 = hexToBytes32('0x' + BigInt(pt[0][1]).toString(16));
        const y0 = hexToBytes32('0x' + BigInt(pt[1][0]).toString(16));
        const y1 = hexToBytes32('0x' + BigInt(pt[1][1]).toString(16));
        return xdr.ScVal.scvVec([xdr.ScVal.scvVec([x0, x1]), xdr.ScVal.scvVec([y0, y1])]);
    }
    const proofArg = xdr.ScVal.scvMap([
        { key: xdr.ScVal.scvSymbol('pi_a'), val: encodeG1(proof.pi_a) },
        { key: xdr.ScVal.scvSymbol('pi_b'), val: encodeG2(proof.pi_b) },
        { key: xdr.ScVal.scvSymbol('pi_c'), val: encodeG1(proof.pi_c) },
    ].map(e => new xdr.ScMapEntry({ key: e.key, val: e.val })));

    const pubArgs = xdr.ScVal.scvVec(
        publicSignals.map(s => hexToBytes32('0x' + BigInt(s).toString(16)))
    );

    const vkArg = xdr.ScVal.scvMap([
        new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol(vkId),
            val: xdr.ScVal.scvVoid(),
        }),
    ]);

    const tx = new TransactionBuilder(account, { fee: '100000', networkPassphrase: network })
        .addOperation(core.call('verify_groth16', vkArg, proofArg, pubArgs))
        .setTimeout(30)
        .build();
    tx.sign(kp);

    const resp = await server.sendTransaction(tx);
    if (resp.status !== 'PENDING') throw new Error(`tx status: ${resp.status}`);
    // Poll for result
    for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 3000));
        const status = await server.getTransaction(resp.hash);
        if (status.status === 'SUCCESS') {
            const retval = status.returnValue;
            return retval?.value() === true;
        }
        if (status.status === 'FAILED') throw new Error('tx FAILED');
    }
    throw new Error('tx did not confirm in time');
}

// ── Byte-flip tamper utility ──────────────────────────────────────────────────
function tamperProof(proof) {
    const t = JSON.parse(JSON.stringify(proof));
    // Flip last bit of pi_a[0] (first G1 x-coordinate)
    const orig = BigInt(t.pi_a[0]);
    t.pi_a[0] = (orig + 1n).toString();
    return t;
}

// ── Main test loop ────────────────────────────────────────────────────────────

console.log('=== tampered-proof-rejected.test.js ===\n');
if (ON_CHAIN) {
    console.log(`On-chain checks enabled: VEIL_CORE=${CORE_ID} RPC=${RPC_URL}\n`);
} else {
    console.log('On-chain checks DISABLED (set VEIL_CORE + SOROBAN_RPC + SECRET to enable)\n');
}

let allPass = true;

for (const circuit of CIRCUITS) {
    console.log(`--- ${circuit.name} ---`);

    const wasm = path.join(BUILD, `${circuit.name}_js/${circuit.name}.wasm`);
    const zkey = path.join(KEYS,  `${circuit.name}_final.zkey`);
    const vkPath = path.join(KEYS, `vk_${circuit.name}.json`);
    const vkJson = JSON.parse(readFileSync(vkPath, 'utf8'));

    // 1. Generate valid proof
    let proof, publicSignals;
    try {
        ({ proof, publicSignals } = await snarkjs.groth16.fullProve(circuit.inputs(), wasm, zkey));
    } catch (e) {
        console.error(`FAIL: ${circuit.name} — proof generation failed: ${e.message}`);
        allPass = false;
        continue;
    }

    // 2. Valid proof passes off-chain
    const validOk = await snarkjs.groth16.verify(vkJson, publicSignals, proof);
    if (!validOk) {
        console.error(`FAIL: ${circuit.name} valid proof rejected (unexpected)`);
        allPass = false;
        continue;
    }
    console.log(`PASS: ${circuit.name} — valid proof accepted off-chain`);

    // 3. Tampered proof is rejected off-chain
    const tampered = tamperProof(proof);
    const tamperedOk = await snarkjs.groth16.verify(vkJson, publicSignals, tampered);
    if (tamperedOk) {
        console.error(`FAIL: ${circuit.name} — tampered proof NOT rejected (soundness hole!)`);
        allPass = false;
    } else {
        console.log(`PASS: ${circuit.name} — tampered proof rejected off-chain`);
    }

    // 4. On-chain check: tampered proof must return false from veil_core.verify_groth16
    if (ON_CHAIN) {
        try {
            const result = await verifyOnChain(circuit.name, circuit.vkId, tampered, publicSignals);
            if (result === false) {
                console.log(`PASS: ${circuit.name} — tampered proof rejected on-chain`);
            } else {
                console.error(`FAIL: ${circuit.name} — tampered proof NOT rejected on-chain (result=${result})`);
                allPass = false;
            }
        } catch (e) {
            console.error(`FAIL: ${circuit.name} — on-chain check error: ${e.message}`);
            allPass = false;
        }
    }

    console.log();
}

if (!allPass) {
    console.error('=== SOME TESTS FAILED ===');
    process.exit(1);
}
console.log('=== tampered-proof-rejected.test.js: ALL PASS ===');
