/**
 * e2e-tests/src/amm-settle.test.js — M4 E2E Test
 *
 * Verifies the M4 "Encrypted reserves + real clearing" criteria:
 * - Initialize reserves.
 * - Test 4 orders (2 buying A, 1 buying B, 1 excluded due to slippage).
 * - Assert the batch clears at the expected rational price and limits.
 */

import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk';
import { Address } from '@stellar/stellar-sdk';
const StellarSdk = { Address };
import { buildPoseidon } from 'circomlibjs';
import { proveSwap, serializeProof as serializeSwapProof } from '../../client/src/prover/swap.js';
import { encryptNoteForAuditor } from '../../client/src/viewkey/encrypt.js';
import { COMMITTEE_PK, encryptOrderIntent, settleBatch } from '../../tools/committee/index.js';

const NETWORK    = process.env.NETWORK || 'testnet';
const RPC_URL    = process.env.SOROBAN_RPC || 'https://soroban-testnet.stellar.org';
const PASSPHRASE = NETWORK === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;

const SECRET     = process.env.SECRET;
const CORE_ID    = process.env.VEIL_CORE;
const AMM_ID     = process.env.AMM_POOL;
const AUDITOR_PK = BigInt(`0x${process.env.AUDITOR_PK || '1b408dafebeddf0871388399b1e53bd065fd70f18580be5cdde15d7eb2c52743'}`);

const useRealProof = Boolean(process.env.USE_REAL_PROOF);

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}

function toBytes(buf) { return xdr.ScVal.scvBytes(buf); }
function toBytesN(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0'), 'hex')); }
function toBytesN64(hex)  { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(128, '0'), 'hex')); }
function toBytesN128(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(256, '0'), 'hex')); }
function toU64(v)         { return xdr.ScVal.scvU64(xdr.Uint64.fromString(v.toString())); }

function toStruct(obj) {
    const entries = Object.keys(obj).sort().map(k =>
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: obj[k] })
    );
    return xdr.ScVal.scvMap(entries);
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function scvalFromResult(res) {
    if (res.returnValue) return res.returnValue;
    const meta = typeof res.resultMetaXdr === 'string'
        ? xdr.TransactionMeta.fromXDR(res.resultMetaXdr, 'base64')
        : res.resultMetaXdr;
    return meta.v3().sorobanMeta().returnValue();
}

function readU32Result(res) {
    try { return Number(scvalFromResult(res).u32()); }
    catch { return null; }
}

function readU64Result(res) {
    try {
        const u64 = scvalFromResult(res).u64();
        return BigInt(u64.high) << 32n | BigInt(u64.low);
    } catch { return null; }
}

async function submitTx(contractId, method, args, kp) {
    const server = new rpc.Server(RPC_URL);
    const account = await server.getAccount(kp.publicKey());
    const contract = new Contract(contractId);

    const tx = new TransactionBuilder(account, { fee: '1000000', networkPassphrase: PASSPHRASE })
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

async function syncTreeLeaves(server, coreId) {
    const res = await server.getEvents({
        startLedger: Math.max(1, (await server.getLatestLedger()).sequence - 2000),
        filters: [{ type: 'contract', contractIds: [coreId] }],
        limit: 10000,
    });
    const leaves = [];
    for (const ev of res.events ?? []) {
        try {
            const t0 = typeof ev.topic[0] === 'string'
                ? xdr.ScVal.fromXDR(ev.topic[0], 'base64').sym().toString()
                : ev.topic[0].sym().toString();
            if (t0 === 'leaf') {
                const val = typeof ev.value === 'string'
                    ? xdr.ScVal.fromXDR(ev.value, 'base64')
                    : ev.value;
                const cmBytes = val.switch().name === 'scvVec' ? val.vec()[0].bytes() : val.bytes();
                leaves.push(BigInt(`0x${cmBytes.toString('hex')}`));
            }
        } catch {}
    }
    return leaves;
}

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
                const si = isR ? idx - 1 : idx + 1;
                const sv = cur.has(si) ? cur.get(si) : 0n;
                const h = isR ? poseidon([sv, val]) : poseidon([val, sv]);
                next.set(pi, BigInt(F.toString(h)));
            }
        }
        cur = next;
        ci = Math.floor(ci / 2);
    }
    return { root: cur.get(0) ?? 0n, pathElements, pathIndices };
}

function denseLeaves(arr) { return arr.map(BigInt); }

async function main() {
    if (!SECRET || !CORE_ID || !AMM_ID) {
        throw new Error('Missing environment variables. Did you `source deployments/testnet.env`?');
    }

    const kp = Keypair.fromSecret(SECRET);
    const server = new rpc.Server(RPC_URL);
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    console.log('=== M4 AMM Settle Test ===');
    console.log('Admin PK: ', kp.publicKey());
    console.log('Veil Core:', CORE_ID);
    console.log('AMM Pool: ', AMM_ID);

    // ── 0. Initialize Reserves ───────────────────────────────────────────────

    console.log('\n--- 0. Initializing Reserves ---');
    const ASSET_A = 100n;
    const ASSET_B = 200n;
    
    // Initial reserves
    const pre_reserve_a = 10000n;
    const pre_reserve_b = 20000n;
    const pre_reserve_blinding = 111n;

    const pre_reserve_cm = F.toObject(poseidon([
        pre_reserve_a, pre_reserve_b, pre_reserve_blinding
    ]));
    
    // Check if reserves are already initialized
    try {
        await submitTx(AMM_ID, 'initialize_reserves', [
            toBytesN(pre_reserve_cm.toString(16)),
            toBytes(Buffer.from('deadbeef', 'hex')),
        ], kp);
        assert(true, 'Reserves initialized');
    } catch (e) {
        console.log('Reserves already initialized or init failed (skipping): ' + e.message.slice(0, 50));
    }

    // ── 1. Create traders and input notes ─────────────────────────────────────
    
    console.log('\n--- 1. Creating 4 traders and input notes ---');
    
    let treeLeaves = await syncTreeLeaves(server, CORE_ID);
    const startIndex = BigInt(treeLeaves.length);
    
    const traders = Array.from({ length: 4 }, (_, i) => ({
        sk: BigInt(i + 1),
        pk: F.toObject(poseidon([BigInt(i + 1)])),
    }));

    // Orders: 2 buying A, 1 buying B, 1 excluded due to slippage.
    // Price will be 2 B per 1 A. (price_num = 2, price_den = 1)
    
    const testNotes = [
        { amount: 400n, asset_id: ASSET_B, blinding: 11111n, owner_pk: traders[0].pk }, // buys A
        { amount: 100n, asset_id: ASSET_A, blinding: 22222n, owner_pk: traders[1].pk }, // buys B
        { amount: 10n,  asset_id: ASSET_B, blinding: 33333n, owner_pk: traders[2].pk }, // buys A
        { amount: 50n,  asset_id: ASSET_A, blinding: 44444n, owner_pk: traders[3].pk }, // buys B (excluded, min_out=110)
    ];

    for (let i = 0; i < 4; i++) {
        const note = testNotes[i];
        note.cm = F.toObject(poseidon([note.amount, note.asset_id, note.blinding, note.owner_pk]));
        note.leaf_index = startIndex + BigInt(i);
        treeLeaves.push(note.cm);
        
        const auditorCt = await encryptNoteForAuditor(note, AUDITOR_PK, BigInt(i + 100));
        await submitTx(CORE_ID, 'insert_commitment', [
            new StellarSdk.Address(kp.publicKey()).toScVal(),
            toBytesN(note.cm.toString(16)),
            toBytes(Buffer.from(auditorCt, 'hex')),
        ], kp);
        console.log(`Inserted note ${i} at index ${note.leaf_index}`);
    }

    await sleep(4000);
    treeLeaves = await syncTreeLeaves(server, CORE_ID);
    
    // ── 2. Submit orders ──────────────────────────────────────────────────────
    
    console.log('\n--- 2. Submitting orders ---');

    const ordersSubmitted = [];
    const intents = [
        { asset_out: ASSET_A, min_out: 200n, out_blinding: 55555n, out_owner_pk: traders[0].pk }, // 400 B -> 200 A
        { asset_out: ASSET_B, min_out: 190n, out_blinding: 66666n, out_owner_pk: traders[1].pk }, // 100 A -> 200 B
        { asset_out: ASSET_A, min_out: 5n,   out_blinding: 77777n, out_owner_pk: traders[2].pk }, // 10 B  -> 5 A
        { asset_out: ASSET_B, min_out: 110n, out_blinding: 88888n, out_owner_pk: traders[3].pk }, // 50 A  -> 100 B (excluded, 100 < 110)
    ];

    let currentRoot;
    let batchId = 0n;

    for (let i = 0; i < 4; i++) {
        const note = testNotes[i];
        const intent = intents[i];
        
        const merkleProof = sparseProof(denseLeaves(treeLeaves), Number(note.leaf_index), 32, poseidon);
        currentRoot = merkleProof.root;

        const { encOrderBytes, encOrderHash, rEnc } = await encryptOrderIntent(
            note.amount, intent, COMMITTEE_PK, poseidon,
        );

        let swapProof, nfIn;
        if (useRealProof) {
            const swapResult = await proveSwap({
                amount: note.amount, asset_id: note.asset_id, blinding: note.blinding,
                owner_sk: traders[i].sk, leaf_index: note.leaf_index,
                path: merkleProof.pathElements, idx: merkleProof.pathIndices,
            }, intent, currentRoot, COMMITTEE_PK, rEnc);
            swapProof = serializeSwapProof(swapResult.proof);
            nfIn = swapResult.nf_in;
        } else {
            nfIn = F.toObject(poseidon([traders[i].sk, note.leaf_index, note.cm]));
            swapProof = { a: '00'.repeat(64), b: '00'.repeat(128), c: '00'.repeat(64) };
        }

        const res = await submitTx(AMM_ID, 'submit_order', [
            new StellarSdk.Address(kp.publicKey()).toScVal(),
            toStruct({
                a: toBytesN64(swapProof.a),
                b: toBytesN128(swapProof.b),
                c: toBytesN64(swapProof.c),
            }),
            toBytes(encOrderBytes),
            toBytesN(nfIn.toString(16)),
            toBytesN(encOrderHash.toString(16)),
            toBytesN(currentRoot.toString(16)),
        ], kp);

        const slot = readU32Result(res);
        assert(slot === i, `Order ${i} submitted to slot ${slot}`);
        
        if (i === 0) {
            const batchRes = await server.getContractData(AMM_ID, xdr.ScVal.scvSymbol('BATCH_SEQ'), 'persistent');
            if (batchRes && batchRes.val) {
                batchId = readU64Result({ resultMetaXdr: batchRes.val.toXDR('base64') }) ?? 0n;
            }
        }

        ordersSubmitted.push({
            decrypted: {
                amount_in:    note.amount.toString(),
                asset_out:    intent.asset_out.toString(),
                min_out:      intent.min_out.toString(),
                out_blinding: intent.out_blinding.toString(),
                out_owner_pk: intent.out_owner_pk.toString(),
                r_enc:        rEnc.toString(),
            }
        });
    }

    // ── 3. Committee settles the batch ────────────────────────────────────────

    console.log('\n--- 3. Committee settling batch ---');
    const auditorCt = await encryptNoteForAuditor(
        { amount: 0n, asset_id: ASSET_A, blinding: 0n, owner_pk: 0n }, AUDITOR_PK, 1n,
    );

    const clearingState = {
        asset_a: ASSET_A,
        asset_b: ASSET_B,
        price_num: 2n, // 2 B per 1 A
        price_den: 1n,
        pre_reserve_a: pre_reserve_a,
        pre_reserve_b: pre_reserve_b,
        pre_reserve_blinding: pre_reserve_blinding,
        post_reserve_blinding: 222n,
        fee_a: 0n,
        fee_b: 0n,
        post_enc_reserves: 'deadbeef'
    };

    const orders = ordersSubmitted.map(o => o.decrypted);
    
    // In order to avoid the BATCH_SEQ hack failing if other tests ran, we can just get current_batch
    const currentBatchTx = new TransactionBuilder(await server.getAccount(kp.publicKey()), { fee: '1000000', networkPassphrase: PASSPHRASE })
        .addOperation(new Contract(AMM_ID).call('current_batch'))
        .setTimeout(30).build();
    
    const preparedCurrentBatch = await server.prepareTransaction(currentBatchTx);
    preparedCurrentBatch.sign(kp);
    const cbSend = await server.sendTransaction(preparedCurrentBatch);
    let cbRes = cbSend;
    while (cbRes.status === 'PENDING' || cbRes.status === 'NOT_FOUND') {
        await sleep(2000);
        cbRes = await server.getTransaction(cbSend.hash);
    }
    batchId = readU64Result(cbRes) ?? 0n;

    console.log('Settling Batch ID:', batchId.toString());

    const { cmOuts, amountsOut } = await settleBatch(
        {
            ammPoolId:       AMM_ID,
            veilCoreId:      CORE_ID,
            rpcUrl:          RPC_URL,
            network:         NETWORK,
            committeeSecret: SECRET,
        },
        batchId,
        orders,
        Buffer.from(auditorCt, 'hex').toString('hex'),
        clearingState
    );

    assert(true, 'settle_batch succeeded on-chain');
    console.log('Output amounts:', amountsOut.map(a => a.toString()));
    
    // Verify amounts out match expected CFMM constraints
    assert(amountsOut[0] === 200n, "Order 0 gets 200 A");
    assert(amountsOut[1] === 200n, "Order 1 gets 200 B");
    assert(amountsOut[2] === 5n,   "Order 2 gets 5 A");
    assert(amountsOut[3] === 0n,   "Order 3 excluded due to slippage, gets 0 B");

    console.log('\n=== M4 AMM settle test complete ===');
}

main().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
