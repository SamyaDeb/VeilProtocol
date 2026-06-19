/**
 * tools/committee/index.js — M4 batch-auction committee
 *
 * For M4: real CFMM clearing and batch settlement proof generation.
 */

import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk';
import { buildPoseidon } from 'circomlibjs';
import * as snarkjs from 'snarkjs';
import { createRequire } from 'module';
import path from 'path';

// ─── M3/M4 committee configuration ───────────────────────────────────────────

const COMMITTEE_SK_SHARES = [
    12345678901234567890n,
    98765432109876543210n,
    11111111111111111111n,
];

export const COMMITTEE_PK = COMMITTEE_SK_SHARES[0]; 

const ROOT_DIR = path.resolve(import.meta.dirname, '../..');
const BATCH_SETTLE_WASM = path.join(ROOT_DIR, 'circuits/build/batch_settle_js/batch_settle.wasm');
const BATCH_SETTLE_ZKEY = path.join(ROOT_DIR, 'circuit-keys/dev/batch_settle_final.zkey');

// ─── Encryption / decryption ──────────────────────────────────────────────────

export function decryptOrder(encOrderBytes) {
    return JSON.parse(Buffer.from(encOrderBytes).toString('utf8'));
}

export async function encryptOrderIntent(amountIn, intent, committeePk, poseidon) {
    const F = poseidon.F;
    const rEnc = BigInt(Math.floor(Math.random() * 1e18)) % (
        21888242871839275222246405745257275088548364400416034343698204186575808495617n
    );

    const encOrderHash = F.toObject(poseidon([
        amountIn,
        intent.asset_out,
        intent.min_out,
        intent.out_blinding,
        intent.out_owner_pk,
        committeePk,
        rEnc,
    ]));

    const encOrderBytes = Buffer.from(JSON.stringify({
        amount_in:    amountIn.toString(),
        asset_out:    intent.asset_out.toString(),
        min_out:      intent.min_out.toString(),
        out_blinding: intent.out_blinding.toString(),
        out_owner_pk: intent.out_owner_pk.toString(),
        r_enc:        rEnc.toString(),
    }));

    return { encOrderBytes, rEnc, encOrderHash };
}

// ─── Clearing logic ───────────────────────────────────────────────────────────

export async function clearBatch(orders, committeePk, poseidon, clearingState) {
    const F = poseidon.F;
    const K = orders.length;
    const amountsOut = [];
    const isExcluded = [];
    const cmOuts = [];

    const {
        asset_a, asset_b,
        price_num, price_den,
        pre_reserve_a, pre_reserve_b,
    } = clearingState;

    let sell_a_total = 0n;
    let sell_b_total = 0n;
    let buy_a_total = 0n;
    let buy_b_total = 0n;

    for (let j = 0; j < K; j++) {
        const o = orders[j];
        let amountOut = 0n;
        let excluded = 0n;
        const amountIn = BigInt(o.amount_in);
        const minOut = BigInt(o.min_out);

        if (BigInt(o.asset_out) === BigInt(asset_b)) {
            // buying B, selling A
            const theoreticalOut = (amountIn * BigInt(price_num)) / BigInt(price_den);
            if (theoreticalOut >= minOut) {
                amountOut = theoreticalOut;
                buy_b_total += amountOut;
            } else {
                excluded = 1n;
            }
            sell_a_total += amountIn;
        } else if (BigInt(o.asset_out) === BigInt(asset_a)) {
            // buying A, selling B
            const theoreticalOut = (amountIn * BigInt(price_den)) / BigInt(price_num);
            if (theoreticalOut >= minOut) {
                amountOut = theoreticalOut;
                buy_a_total += amountOut;
            } else {
                excluded = 1n;
            }
            sell_b_total += amountIn;
        } else {
            // Invalid asset out, should never happen in valid setup but exclude just in case
            excluded = 1n;
        }

        const cm = F.toObject(poseidon([
            amountOut,
            BigInt(o.asset_out),
            BigInt(o.out_blinding),
            BigInt(o.out_owner_pk),
        ]));

        amountsOut.push(amountOut);
        isExcluded.push(excluded);
        cmOuts.push(cm);
    }

    const fee_a = BigInt(clearingState.fee_a || 0);
    const fee_b = BigInt(clearingState.fee_b || 0);

    const post_reserve_a = BigInt(pre_reserve_a) + sell_a_total - buy_a_total - fee_a;
    const post_reserve_b = BigInt(pre_reserve_b) + sell_b_total - buy_b_total - fee_b;

    return { amountsOut, isExcluded, cmOuts, post_reserve_a, post_reserve_b, fee_a, fee_b };
}

// ─── Proof generation ─────────────────────────────────────────────────────────

export async function proveBatchSettle(orders, clearingResult, committeePk, batchId, poseidonLib, clearingState) {
    const F = poseidonLib.F;
    
    const encOrderHashes = orders.map(o => {
        return F.toObject(poseidonLib([
            BigInt(o.amount_in),
            BigInt(o.asset_out),
            BigInt(o.min_out),
            BigInt(o.out_blinding),
            BigInt(o.out_owner_pk),
            committeePk,
            BigInt(o.r_enc),
        ]));
    });

    const pre_reserve_cm = F.toObject(poseidonLib([
        BigInt(clearingState.pre_reserve_a),
        BigInt(clearingState.pre_reserve_b),
        BigInt(clearingState.pre_reserve_blinding)
    ]));

    const post_reserve_cm = F.toObject(poseidonLib([
        BigInt(clearingResult.post_reserve_a),
        BigInt(clearingResult.post_reserve_b),
        BigInt(clearingState.post_reserve_blinding)
    ]));

    const circuitInput = {
        // public: enc_order_hash[0..K], cm_out[0..K], committee_pk, batch_id, pre_reserve_cm, post_reserve_cm
        enc_order_hash:  encOrderHashes.map(String),
        cm_out:          clearingResult.cmOuts.map(String),
        committee_pk:    committeePk.toString(),
        batch_id:        batchId.toString(),
        pre_reserve_cm:  pre_reserve_cm.toString(),
        post_reserve_cm: post_reserve_cm.toString(),

        // private: committee's decrypted knowledge
        amount_in:    orders.map(o => BigInt(o.amount_in).toString()),
        asset_out:    orders.map(o => BigInt(o.asset_out).toString()),
        min_out:      orders.map(o => BigInt(o.min_out).toString()),
        out_blinding: orders.map(o => BigInt(o.out_blinding).toString()),
        out_owner_pk: orders.map(o => BigInt(o.out_owner_pk).toString()),
        r_enc:        orders.map(o => BigInt(o.r_enc).toString()),
        amount_out:   clearingResult.amountsOut.map(String),
        is_excluded:  clearingResult.isExcluded.map(String),

        pre_reserve_a: clearingState.pre_reserve_a.toString(),
        pre_reserve_b: clearingState.pre_reserve_b.toString(),
        pre_reserve_blinding: clearingState.pre_reserve_blinding.toString(),
        post_reserve_a: clearingResult.post_reserve_a.toString(),
        post_reserve_b: clearingResult.post_reserve_b.toString(),
        post_reserve_blinding: clearingState.post_reserve_blinding.toString(),
        clearing_price_num: clearingState.price_num.toString(),
        clearing_price_den: clearingState.price_den.toString(),
        fee_a: clearingResult.fee_a.toString(),
        fee_b: clearingResult.fee_b.toString(),
        asset_a: clearingState.asset_a.toString(),
        asset_b: clearingState.asset_b.toString(),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        circuitInput, BATCH_SETTLE_WASM, BATCH_SETTLE_ZKEY,
    );

    return { proof, publicSignals, encOrderHashes, pre_reserve_cm, post_reserve_cm };
}

// ─── Proof serialisation ──────────────────────────────────────────────────────

function decToBe32(dec) {
    const hex = BigInt(dec).toString(16).padStart(64, '0');
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
}

function serializeG1(p) {
    const out = new Uint8Array(64);
    out.set(decToBe32(p[0]), 0); out.set(decToBe32(p[1]), 32);
    return Buffer.from(out).toString('hex');
}

function serializeG2(p) {
    const out = new Uint8Array(128);
    out.set(decToBe32(p[0][1]), 0);   // X_c0
    out.set(decToBe32(p[0][0]), 32);  // X_c1
    out.set(decToBe32(p[1][1]), 64);  // Y_c0
    out.set(decToBe32(p[1][0]), 96);  // Y_c1
    return Buffer.from(out).toString('hex');
}

export function serializeProof(proof) {
    return {
        a: serializeG1(proof.pi_a),
        b: serializeG2(proof.pi_b),
        c: serializeG1(proof.pi_c),
    };
}

// ─── Stellar helpers ──────────────────────────────────────────────────────────

function toBytesN(hex)    { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0'),  'hex')); }
function toBytesN64(hex)  { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(128, '0'), 'hex')); }
function toBytesN128(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(256, '0'), 'hex')); }
function toBytes(buf)     { return xdr.ScVal.scvBytes(buf); }
function toU64(v)         { return xdr.ScVal.scvU64(xdr.Uint64.fromString(v.toString())); }

function toStruct(obj) {
    const entries = Object.keys(obj).sort().map(k =>
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: obj[k] })
    );
    return xdr.ScVal.scvMap(entries);
}

function toVec(vals) { return xdr.ScVal.scvVec(vals); }

function toTuple(a, b) {
    return xdr.ScVal.scvVec([a, b]);
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function submitTx(contractId, method, args, kp, rpcUrl, passphrase) {
    const server = new rpc.Server(rpcUrl);
    const account = await server.getAccount(kp.publicKey());
    const contract = new Contract(contractId);

    const tx = new TransactionBuilder(account, { fee: '1000000', networkPassphrase: passphrase })
        .addOperation(contract.call(method, ...args))
        .setTimeout(30)
        .build();

    const prepared = await server.prepareTransaction(tx);
    prepared.sign(kp);
    const send = await server.sendTransaction(prepared);

    if (send.status === 'ERROR') throw new Error(`Tx failed: ${send.errorResultXdr}`);

    let res = send;
    while (res.status === 'PENDING' || res.status === 'NOT_FOUND') {
        await sleep(2000);
        res = await server.getTransaction(send.hash);
    }
    if (res.status !== 'SUCCESS') throw new Error(`Tx execution failed: ${res.status}`);
    return res;
}

// ─── Settle a batch (callable from tests) ────────────────────────────────────

export async function settleBatch(cfg, batchId, orders, auditorCtHex, clearingState) {
    const { ammPoolId, rpcUrl, network, committeeSecret } = cfg;
    const passphrase = network === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;
    const kp = Keypair.fromSecret(committeeSecret);
    const poseidon = await buildPoseidon();

    const clearingResult = await clearBatch(orders, COMMITTEE_PK, poseidon, clearingState);

    const useRealProof = Boolean(process.env.USE_REAL_PROOF);
    let serializedProof;
    let postReserveCm;
    
    // Always compute the post_reserve_cm for dummy proof too
    const F = poseidon.F;
    postReserveCm = F.toObject(poseidon([
        BigInt(clearingResult.post_reserve_a),
        BigInt(clearingResult.post_reserve_b),
        BigInt(clearingState.post_reserve_blinding)
    ]));

    if (useRealProof) {
        const res = await proveBatchSettle(
            orders, clearingResult, COMMITTEE_PK, BigInt(batchId), poseidon, clearingState
        );
        serializedProof = serializeProof(res.proof);
        postReserveCm = res.post_reserve_cm;
    } else {
        serializedProof = {
            a: '00'.repeat(64),
            b: '00'.repeat(128),
            c: '00'.repeat(64),
        };
    }

    const outputsScVal = toVec(
        clearingResult.cmOuts.map(cm => toTuple(
            toBytesN(cm.toString(16)),
            toBytes(Buffer.from(auditorCtHex, 'hex')),
        ))
    );

    const postEncReservesHex = clearingState.post_enc_reserves || '';

    await submitTx(
        ammPoolId, 'settle_batch',
        [
            toU64(batchId),
            toStruct({ a: toBytesN64(serializedProof.a), b: toBytesN128(serializedProof.b), c: toBytesN64(serializedProof.c) }),
            outputsScVal,
            toBytesN(postReserveCm.toString(16)),
            toBytes(Buffer.from(postEncReservesHex, 'hex')),
        ],
        kp, rpcUrl, passphrase,
    );

    return { cmOuts: clearingResult.cmOuts, amountsOut: clearingResult.amountsOut, postReserveCm };
}
