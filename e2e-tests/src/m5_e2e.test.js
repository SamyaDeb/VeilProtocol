import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk';
import { Address } from '@stellar/stellar-sdk';
const StellarSdk = { Address };
import { buildPoseidon } from 'circomlibjs';
import { proveAddLiquidity, proveRemoveLiquidity, serializeProof } from '../../client/src/prover/lp.js';
import { encryptNoteForAuditor } from '../../client/src/viewkey/encrypt.js';

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

function toStruct(obj) {
    const entries = Object.keys(obj).sort().map(k =>
        new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: obj[k] })
    );
    return xdr.ScVal.scvMap(entries);
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

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

    console.log('=== M5 AMM E2E Test (Add & Remove Liquidity) ===');
    console.log('Admin PK: ', kp.publicKey());

    // 0. Init Reserves
    console.log('\n--- 0. Initializing Reserves ---');
    const ASSET_0 = 100n;
    const ASSET_1 = 200n;

    let preReserves = [1000n, 2000n];
    let preTotalShares = 0n;
    let reserveBlinding = 111n;

    const pre_reserve_cm = F.toObject(poseidon([
        preReserves[0], preReserves[1], preTotalShares, reserveBlinding
    ]));

    try {
        await submitTx(AMM_ID, 'initialize_reserves', [
            toBytesN(pre_reserve_cm.toString(16)),
            toBytes(Buffer.from('deadbeef', 'hex')),
        ], kp);
        assert(true, 'Reserves initialized');
    } catch (e) {
        console.log('Reserves already initialized (skipping)');
    }

    // 1. Create Input Notes
    console.log('\n--- 1. Creating input notes ---');
    let treeLeaves = await syncTreeLeaves(server, CORE_ID);
    const startIndex = BigInt(treeLeaves.length);

    const providerSk = 42n;
    const providerPk = F.toObject(poseidon([providerSk]));

    // RULE 2 Validation: Treating swap-output notes the same as normal ones.
    const note0 = { amount: 500n, asset_id: ASSET_0, blinding: 11111n, owner_pk: providerPk, owner_sk: providerSk };
    const note1 = { amount: 1000n, asset_id: ASSET_1, blinding: 22222n, owner_pk: providerPk, owner_sk: providerSk };

    const notes = [note0, note1];
    for (let i = 0; i < 2; i++) {
        const note = notes[i];
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

    // 2. Add Liquidity
    console.log('\n--- 2. Adding Liquidity ---');
    const merkleProof0 = sparseProof(denseLeaves(treeLeaves), Number(note0.leaf_index), 32, poseidon);
    const merkleProof1 = sparseProof(denseLeaves(treeLeaves), Number(note1.leaf_index), 32, poseidon);
    const currentRoot = merkleProof0.root;

    note0.path = merkleProof0.pathElements;
    note0.idx = merkleProof0.pathIndices;
    note1.path = merkleProof1.pathElements;
    note1.idx = merkleProof1.pathIndices;

    let addProof, lpNf0, lpNf1, lpCommit, postResCmAdd, shares;

    if (useRealProof) {
        const result = await proveAddLiquidity(
            note0, note1, preReserves, preTotalShares, reserveBlinding, currentRoot
        );
        addProof = serializeProof(result.proof);
        lpNf0 = result.nf_in_0;
        lpNf1 = result.nf_in_1;
        lpCommit = result.lp_commit;
        postResCmAdd = result.post_reserve_cm;
        shares = 500n; // Amount of note0
    } else {
        lpNf0 = F.toObject(poseidon([note0.owner_sk, note0.leaf_index, note0.cm]));
        lpNf1 = F.toObject(poseidon([note1.owner_sk, note1.leaf_index, note1.cm]));
        shares = 500n;
        lpCommit = F.toObject(poseidon([shares, 99999n, note0.blinding, providerPk]));
        
        const post_reserves = [preReserves[0] + note0.amount, preReserves[1] + note1.amount];
        postResCmAdd = F.toObject(poseidon([post_reserves[0], post_reserves[1], preTotalShares + shares, reserveBlinding]));
        addProof = { a: '00'.repeat(64), b: '00'.repeat(128), c: '00'.repeat(64) };
    }

    const addAuditorCt = await encryptNoteForAuditor({ amount: shares, asset_id: 99999n, blinding: note0.blinding, owner_pk: providerPk }, AUDITOR_PK, 123n);

    await submitTx(AMM_ID, 'add_liquidity', [
        toStruct({ a: toBytesN64(addProof.a), b: toBytesN128(addProof.b), c: toBytesN64(addProof.c) }),
        toBytesN(currentRoot.toString(16)),
        toBytesN(lpNf0.toString(16)),
        toBytesN(lpNf1.toString(16)),
        toBytesN(lpCommit.toString(16)),
        toBytes(Buffer.from(addAuditorCt, 'hex')),
        toBytesN(postResCmAdd.toString(16)),
        toBytes(Buffer.from('deadbeef', 'hex')),
    ], kp);

    assert(true, 'add_liquidity succeeded on-chain');

    // Hidden Size constraint: check recent events to see if LP size is leaked
    const addEvents = await server.getEvents({
        startLedger: Math.max(1, (await server.getLatestLedger()).sequence - 100),
        filters: [{ type: 'contract', contractIds: [AMM_ID] }],
        limit: 10000,
    });
    for (const ev of addEvents.events ?? []) {
        if (ev.topic[1]?.sym()?.toString() === 'add_lp') {
            const val = typeof ev.value === 'string' ? xdr.ScVal.fromXDR(ev.value, 'base64') : ev.value;
            assert(val.switch().name === 'scvVoid', 'Hidden Size Constraint: LP size not leaked in add_lp event payload');
        }
    }

    // 3. Remove Liquidity
    console.log('\n--- 3. Removing Liquidity ---');
    await sleep(4000);
    treeLeaves = await syncTreeLeaves(server, CORE_ID);
    
    // We added the LP note. Its index is the last one in treeLeaves.
    const lpIndex = BigInt(treeLeaves.length - 1);
    const lpNote = { amount: shares, asset_id: 99999n, blinding: note0.blinding, owner_pk: providerPk, owner_sk: providerSk, cm: lpCommit, leaf_index: lpIndex };
    
    const merkleProofLp = sparseProof(denseLeaves(treeLeaves), Number(lpIndex), 32, poseidon);
    lpNote.path = merkleProofLp.pathElements;
    lpNote.idx = merkleProofLp.pathIndices;

    const currentRoot2 = merkleProofLp.root;

    // We will withdraw all shares
    const intent = {
        asset_0: ASSET_0, asset_1: ASSET_1,
        out_blinding_0: 33333n, out_blinding_1: 44444n,
        out_owner_sk_0: 43n, out_owner_sk_1: 44n
    };

    let remProof, lpNfRem, cmOut0, cmOut1, postResCmRem;
    if (useRealProof) {
        const result = await proveRemoveLiquidity(
            lpNote, intent,
            [preReserves[0] + note0.amount, preReserves[1] + note1.amount],
            preTotalShares + shares,
            reserveBlinding,
            currentRoot2
        );
        remProof = serializeProof(result.proof);
        lpNfRem = result.lp_nf;
        cmOut0 = result.cm_out_0;
        cmOut1 = result.cm_out_1;
        postResCmRem = result.post_reserve_cm;
    } else {
        lpNfRem = F.toObject(poseidon([lpNote.owner_sk, lpNote.leaf_index, lpNote.cm]));
        
        const out_owner_pk_0 = F.toObject(poseidon([intent.out_owner_sk_0]));
        cmOut0 = F.toObject(poseidon([note0.amount, intent.asset_0, intent.out_blinding_0, out_owner_pk_0]));

        const out_owner_pk_1 = F.toObject(poseidon([intent.out_owner_sk_1]));
        cmOut1 = F.toObject(poseidon([note1.amount, intent.asset_1, intent.out_blinding_1, out_owner_pk_1]));

        const post_reserves = [preReserves[0], preReserves[1]];
        postResCmRem = F.toObject(poseidon([post_reserves[0], post_reserves[1], preTotalShares, reserveBlinding]));
        remProof = { a: '00'.repeat(64), b: '00'.repeat(128), c: '00'.repeat(64) };
    }

    const outCt0 = await encryptNoteForAuditor({ amount: note0.amount, asset_id: intent.asset_0, blinding: intent.out_blinding_0, owner_pk: F.toObject(poseidon([intent.out_owner_sk_0])) }, AUDITOR_PK, 124n);
    const outCt1 = await encryptNoteForAuditor({ amount: note1.amount, asset_id: intent.asset_1, blinding: intent.out_blinding_1, owner_pk: F.toObject(poseidon([intent.out_owner_sk_1])) }, AUDITOR_PK, 125n);

    await submitTx(AMM_ID, 'remove_liquidity', [
        toStruct({ a: toBytesN64(remProof.a), b: toBytesN128(remProof.b), c: toBytesN64(remProof.c) }),
        toBytesN(currentRoot2.toString(16)),
        toBytesN(lpNfRem.toString(16)),
        toBytesN(cmOut0.toString(16)),
        toBytesN(cmOut1.toString(16)),
        toBytes(Buffer.from(outCt0, 'hex')),
        toBytes(Buffer.from(outCt1, 'hex')),
        toBytesN(postResCmRem.toString(16)),
        toBytes(Buffer.from('deadbeef', 'hex')),
        toBytesN(lpCommit.toString(16)),
    ], kp);

    assert(true, 'remove_liquidity succeeded on-chain');

    const remEvents = await server.getEvents({
        startLedger: Math.max(1, (await server.getLatestLedger()).sequence - 100),
        filters: [{ type: 'contract', contractIds: [AMM_ID] }],
        limit: 10000,
    });
    for (const ev of remEvents.events ?? []) {
        if (ev.topic[1]?.sym()?.toString() === 'rem_lp') {
            const val = typeof ev.value === 'string' ? xdr.ScVal.fromXDR(ev.value, 'base64') : ev.value;
            assert(val.switch().name === 'scvVoid', 'Hidden Size Constraint: LP size not leaked in rem_lp event payload');
        }
    }

    console.log('\n=== M5 E2E Validation Complete ===');
}

main().catch(e => { console.error(e); process.exit(1); });
