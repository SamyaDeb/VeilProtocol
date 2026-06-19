/**
 * M2 E2E test — shielded withdraw + auditor disclosure
 *
 * Verification command (TEST_PLAN M2):
 *   veil e2e withdraw-and-audit --network testnet
 *
 * Prerequisites (testnet):
 *   VEIL_CORE   — deployed veil_core contract ID
 *   ASP         — deployed asp contract ID
 *   TOKEN       — TEST-RWA or native XLM SAC contract ID
 *   SOROBAN_RPC — Soroban RPC endpoint
 *   SECRET      — deployer/user secret key (must hold TOKEN balance and be ASP-approved)
 *   NETWORK     — testnet (default) or mainnet
 *
 * What this tests:
 *   - withdraw to a public address succeeds (proof verifies, nullifiers spent) [US-2]
 *   - change note is inserted with auditor ciphertext (RULE 4)
 *   - auditor decrypts the in-scope note via request_disclosure [US-5]
 *   - auditor view key on an out-of-scope index returns empty (US-5 negative)
 *   - double-spend of the withdrawn nullifier is rejected (RULE 3)
 */

import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk';
import { Address } from '@stellar/stellar-sdk';
const StellarSdk = { Address };

import { buildPoseidon } from 'circomlibjs';
import { MerkleTree, buildNonMembershipProof } from './merkle.js';
import { proveWithdraw, serializeProof as serializeWithdrawProof } from '../../client/src/prover/withdraw.js';
import { proveDeposit, serializeProof as serializeDepositProof } from '../../client/src/prover/deposit.js';
import { encryptNoteForAuditor, decryptNoteAsAuditor } from '../../client/src/viewkey/encrypt.js';

// ─── config ──────────────────────────────────────────────────────────────────

const CORE_ID    = process.env.VEIL_CORE ?? '';
const ASP_ID     = process.env.ASP ?? '';
const TOKEN_ID   = process.env.TOKEN ?? '';
const RPC_URL    = process.env.SOROBAN_RPC ?? 'https://soroban-testnet.stellar.org';
const SECRET     = process.env.SECRET ?? '';
const NETWORK    = process.env.NETWORK ?? 'testnet';
const PASSPHRASE = NETWORK === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;

// ─── helpers (same as transfer.test.js) ──────────────────────────────────────

function assert(cond, msg) {
    if (!cond) { console.error(`FAIL: ${msg}`); process.exit(1); }
    console.log(`PASS: ${msg}`);
}
async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function toBytesN(hex)      { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0').slice(0, 64), 'hex')); }
function toBytesN128(hex)   { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(256, '0').slice(0, 256), 'hex')); }
function toBytesN64(hex)    { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(128, '0').slice(0, 128), 'hex')); }
function toBytes(hex)       { if (typeof hex !== 'string') hex = hex.toString('hex'); return xdr.ScVal.scvBytes(Buffer.from(hex, 'hex')); }
function toU32(val)         { return xdr.ScVal.scvU32(val); }
function toU64(val)         { return xdr.ScVal.scvU64(xdr.Uint64.fromString(val.toString())); }
function toVec(vals)        { return xdr.ScVal.scvVec(vals); }
function toStruct(obj) {
    const entries = Object.keys(obj).sort().map(key => new xdr.ScMapEntry({
        key: xdr.ScVal.scvSymbol(key),
        val: obj[key],
    }));
    return xdr.ScVal.scvMap(entries);
}

async function submitTx(contractId, method, args, kp) {
    const server  = new rpc.Server(RPC_URL);
    const account = await server.getAccount(kp.publicKey());
    const contract = new Contract(contractId);
    const tx = new TransactionBuilder(account, { fee: '1000000', networkPassphrase: PASSPHRASE })
        .addOperation(contract.call(method, ...args))
        .setTimeout(30)
        .build();
    let preparedTx = await server.prepareTransaction(tx);
    preparedTx.sign(kp);
    const send = await server.sendTransaction(preparedTx);
    if (send.errorResultXdr || send.status === 'ERROR') {
        throw new Error(`Tx submission failed: ${send.errorResultXdr ?? JSON.stringify(send)}`);
    }
    let status = send.status;
    let res = send;
    while (status === 'PENDING' || status === 'NOT_FOUND') {
        await sleep(2000);
        res = await server.getTransaction(send.hash);
        status = res.status;
    }
    if (status !== 'SUCCESS') throw new Error(`Tx failed: ${JSON.stringify(res)}`);
    return res;
}

async function readTx(contractId, method, args, kp) {
    const server  = new rpc.Server(RPC_URL);
    const account = await server.getAccount(kp.publicKey());
    const contract = new Contract(contractId);
    const tx = new TransactionBuilder(account, { fee: '1000000', networkPassphrase: PASSPHRASE })
        .addOperation(contract.call(method, ...args))
        .setTimeout(30)
        .build();
    const sim = await server.simulateTransaction(tx);
    if (!sim.result) throw new Error(`Simulate failed: ${JSON.stringify(sim)}`);
    return sim.result.retval;
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
    console.log('=== Veil Protocol M2 — withdraw-and-audit e2e test ===');
    console.log(`Network: ${NETWORK}, RPC: ${RPC_URL}`);

    const kp = Keypair.fromSecret(SECRET);
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const aliceSk  = 101n;
    const alicePk  = F.toObject(poseidon([aliceSk]));
    const auditorSk = 42n;
    const auditorPk = F.toObject(poseidon([auditorSk]));

    // ── 0. Deposit Alice's note ───────────────────────────────────────────────

    console.log('\n--- 0. Deposit: Alice deposits 1000 ---');

    const noteA = { amount: 1000n, asset_id: 999n, blinding: 11111n, owner_pk: alicePk };

    const cred_secret = 1n;
    const issuer_pk   = 456n;
    const credLeafHash = poseidon([cred_secret, issuer_pk]);
    const credLeaf     = BigInt(F.toString(credLeafHash));

    const approvedTree = new MerkleTree(20, poseidon, [credLeaf]);
    const MAX          = (1n << 252n) - 1n;
    const blockedTree  = new MerkleTree(20, poseidon, [1n, MAX]);

    await submitTx(ASP_ID, 'update_approved', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toBytesN(approvedTree.root.toString(16)), toBytes('00'),
    ], kp);
    await submitTx(ASP_ID, 'update_blocked', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toBytesN(blockedTree.root.toString(16)), toBytes('00'),
    ], kp);

    const approvedProof = approvedTree.getProof(0);
    const nmProof       = buildNonMembershipProof(blockedTree, credLeaf);
    const aspProof      = {
        asp_path: approvedProof.pathElements, asp_idx: approvedProof.pathIndices,
        blocked_lower_leaf: nmProof.lower_leaf, blocked_upper_leaf: nmProof.upper_leaf,
        blocked_lower_path: nmProof.lower_path, blocked_lower_idx:  nmProof.lower_idx,
        blocked_upper_path: nmProof.upper_path, blocked_upper_idx:  nmProof.upper_idx,
        asp_approved_root: approvedTree.root, asp_blocked_root: blockedTree.root,
    };

    const { proof: depProof, cm: cmA } = await proveDeposit(noteA, { cred_secret, issuer_pk }, aspProof, noteA.amount);
    const serializedDepProof = serializeDepositProof(depProof);
    // RULE 4: encrypt for auditor (blinding 777)
    const auditorCtDep = await encryptNoteForAuditor(noteA, auditorPk, 777n);

    await submitTx(CORE_ID, 'deposit', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),   // depositor
        new StellarSdk.Address(TOKEN_ID).toScVal(),         // token_contract
        new StellarSdk.Address(ASP_ID).toScVal(),
        toStruct({ a: toBytesN64(serializedDepProof.a), b: toBytesN128(serializedDepProof.b), c: toBytesN64(serializedDepProof.c) }),
        toStruct({
            cm: toBytesN(BigInt(cmA).toString(16)),
            public_amount: toBytesN(noteA.amount.toString(16)),
            asp_approved_root: toBytesN(approvedTree.root.toString(16)),
            asp_blocked_root:  toBytesN(blockedTree.root.toString(16)),
        }),
        toStruct({
            approved_idx:       toVec(approvedProof.pathIndices.map(toU32)),
            approved_path:      toVec(approvedProof.pathElements.map(x => toBytesN(x.toString(16)))),
            approved_root:      toBytesN(approvedTree.root.toString(16)),
            blocked_lower_idx:  toVec(nmProof.lower_idx.map(toU32)),
            blocked_lower_leaf: toBytesN(nmProof.lower_leaf.toString(16)),
            blocked_lower_path: toVec(nmProof.lower_path.map(x => toBytesN(x.toString(16)))),
            blocked_root:       toBytesN(blockedTree.root.toString(16)),
            blocked_upper_idx:  toVec(nmProof.upper_idx.map(toU32)),
            blocked_upper_leaf: toBytesN(nmProof.upper_leaf.toString(16)),
            blocked_upper_path: toVec(nmProof.upper_path.map(x => toBytesN(x.toString(16)))),
            credential_leaf:    toBytesN(credLeaf.toString(16)),
        }),
        toBytes(auditorCtDep),
    ], kp);

    console.log('PASS: Deposit successful (idx 0)');
    console.log('Waiting for RPC to index events...');
    await sleep(5000);

    // ── 1. Sync tree from RPC events ─────────────────────────────────────────

    console.log('\n--- 1. Sync Merkle tree ---');
    const server = new rpc.Server(RPC_URL);
    const latestLedger = await server.getLatestLedger();
    const startLedger  = Math.max(1, latestLedger.sequence - 500);

    const eventsResp = await server.getEvents({
        startLedger,
        filters: [{ type: 'contract', contractIds: [CORE_ID] }],
        limit: 10000,
    });

    let parsedLeaves = [];
    for (const ev of eventsResp.events ?? []) {
        if (!ev.topic || ev.topic.length < 2) continue;
        try {
            let t0, t1, vec;
            if (typeof ev.topic[0] === 'string') {
                t0  = xdr.ScVal.fromXDR(ev.topic[0], 'base64').sym().toString();
                t1  = xdr.ScVal.fromXDR(ev.topic[1], 'base64').sym().toString();
                vec = xdr.ScVal.fromXDR(ev.value.xdr ?? ev.value, 'base64').vec();
            } else {
                t0  = ev.topic[0].sym().toString();
                t1  = ev.topic[1].sym().toString();
                vec = ev.value.vec();
            }
            if (t0 === 'leaf' && t1 === 'inserted') {
                const cmBytes = vec[0].bytes();
                const idx     = vec[1].u64().low;
                parsedLeaves[idx] = BigInt('0x' + cmBytes.toString('hex'));
            }
        } catch (_) {}
    }

    const leaves      = Array.from({ length: parsedLeaves.length }, (_, i) => parsedLeaves[i] ?? 0n);
    const cmABigInt   = BigInt(cmA);
    const leafIndexA  = leaves.indexOf(cmABigInt);
    assert(leafIndexA !== -1, "Alice's deposit leaf found in on-chain tree");

    function getSparseProof(leavesArr, targetIndex, depth, poseidon) {
        const F = poseidon.F;
        let currentLevel = new Map(leavesArr.map((v, i) => [i, v]));
        let pathElements = [], pathIndices = [], currentIndex = targetIndex;
        for (let i = 0; i < depth; i++) {
            const isRight   = currentIndex % 2 === 1;
            const sibIdx    = isRight ? currentIndex - 1 : currentIndex + 1;
            const sibling   = currentLevel.get(sibIdx) ?? 0n;
            pathIndices.push(isRight ? 1 : 0);
            pathElements.push(sibling);
            let nextLevel = new Map();
            for (const [idx, val] of currentLevel) {
                const pIdx = Math.floor(idx / 2);
                if (!nextLevel.has(pIdx)) {
                    const sIdx  = idx % 2 === 1 ? idx - 1 : idx + 1;
                    const sVal  = currentLevel.get(sIdx) ?? 0n;
                    const hash  = idx % 2 === 1 ? poseidon([sVal, val]) : poseidon([val, sVal]);
                    nextLevel.set(pIdx, BigInt(F.toString(hash)));
                }
            }
            currentLevel  = nextLevel;
            currentIndex  = Math.floor(currentIndex / 2);
        }
        const root = currentLevel.get(0) ?? 0n;
        return { root, pathElements, pathIndices };
    }

    const treeProofA = getSparseProof(leaves, leafIndexA, 32, poseidon);
    const root = treeProofA.root;

    // ── 2. Alice withdraws 700, keeps 300 as change ───────────────────────────

    console.log('\n--- 2. Alice withdraws 700 to recipient, change 300 ---');

    const withdrawAmount = 700n;
    const changeAmount   = 300n;
    const changeBlinding = 55555n;

    const inputNote = {
        amount: noteA.amount, asset_id: noteA.asset_id, blinding: noteA.blinding,
        owner_sk: aliceSk, leaf_index: BigInt(leafIndexA),
        path: treeProofA.pathElements, idx: treeProofA.pathIndices,
    };
    const dummyNote = {
        amount: 0n, asset_id: 0n, blinding: 0n, owner_sk: aliceSk,
        leaf_index: 0n, path: Array(32).fill(0n), idx: Array(32).fill(0),
    };
    const changeNote = { amount: changeAmount, asset_id: noteA.asset_id, blinding: changeBlinding, owner_pk: alicePk };

    // recipient_hash = Poseidon(recipient field encoding)
    // VERIFY: canonical field encoding of G.../Stellar address for Poseidon before mainnet
    const recipientField = BigInt('0x' + Buffer.from(kp.publicKey(), 'utf8').toString('hex')) % (2n ** 253n);
    const recipientHash  = F.toObject(poseidon([recipientField]));

    console.log('Generating withdraw proof (this may take ~15s)...');
    const { proof: wdProof, nf_in_0, nf_in_1, cm_change } = await proveWithdraw(
        inputNote, dummyNote, changeNote,
        root, withdrawAmount, noteA.asset_id, recipientHash,
    );

    // RULE 4: encrypt change note for auditor (blinding 888)
    const auditorCtChange = await encryptNoteForAuditor(changeNote, auditorPk, 888n);

    const serializedWdProof = serializeWithdrawProof(wdProof);

    const wdResult = await submitTx(CORE_ID, 'withdraw', [
        new StellarSdk.Address(TOKEN_ID).toScVal(),          // token_contract
        new StellarSdk.Address(kp.publicKey()).toScVal(),    // recipient
        toStruct({
            a: toBytesN64(serializedWdProof.a),
            b: toBytesN128(serializedWdProof.b),
            c: toBytesN64(serializedWdProof.c),
        }),
        toStruct({
            root:           toBytesN(root.toString(16)),
            nf_in_0:        toBytesN(nf_in_0.toString(16)),
            nf_in_1:        toBytesN(nf_in_1.toString(16)),
            cm_change:      toBytesN(cm_change.toString(16)),
            public_amount:  toBytesN(withdrawAmount.toString(16)),
            asset_id:       toBytesN(noteA.asset_id.toString(16)),
            recipient_hash: toBytesN(recipientHash.toString(16)),
        }),
        toBytes(auditorCtChange),
    ], kp);

    assert(true, 'Withdraw transaction submitted successfully');

    // ── 3. Verify on-chain state (RULE 3 + RULE 4) ───────────────────────────

    console.log('\n--- 3. Verify on-chain state ---');

    const isSpentVal = await readTx(CORE_ID, 'is_spent', [toBytesN(nf_in_0.toString(16))], kp);
    assert(isSpentVal.b() === true, 'Withdrawn nullifier (nf_in_0) is marked spent (RULE 3)');

    const isSpentDummy = await readTx(CORE_ID, 'is_spent', [toBytesN('00')], kp);
    assert(isSpentDummy.b() === false, 'Dummy nullifier (zero) is NOT spent');

    // Change note was inserted at index 1 (deposit was idx 0)
    const changeIdx = 1n;
    const storedCtVal = await readTx(CORE_ID, 'ciphertext_at', [toU64(changeIdx)], kp);
    const storedCt = Buffer.from(storedCtVal.bytes());
    assert(storedCt.length > 0, 'Change note auditor ciphertext stored at idx 1 (RULE 4)');

    // ── 4. Auditor decrypts in-scope notes ───────────────────────────────────

    console.log('\n--- 4. Auditor selectively discloses ---');

    // Deposit note (idx 0)
    const ctIdx0Val = await readTx(CORE_ID, 'request_disclosure', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toU64(0n),
    ], kp);
    const ct0 = Buffer.from(ctIdx0Val.bytes());
    assert(ct0.length > 0, 'request_disclosure(idx=0) returns ciphertext');

    const decrypted0 = decryptNoteAsAuditor(ct0, auditorSk);
    assert(decrypted0.amount === noteA.amount, 'Auditor decrypts deposit amount correctly (idx 0)');
    assert(decrypted0.owner_pk === noteA.owner_pk, 'Auditor decrypts deposit owner_pk correctly (idx 0)');

    // Change note (idx 1)
    const ctIdx1Val = await readTx(CORE_ID, 'request_disclosure', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toU64(changeIdx),
    ], kp);
    const ct1 = Buffer.from(ctIdx1Val.bytes());
    assert(ct1.length > 0, 'request_disclosure(idx=1) returns change note ciphertext');

    const decrypted1 = decryptNoteAsAuditor(ct1, auditorSk);
    assert(decrypted1.amount === changeAmount, 'Auditor decrypts change amount (300) correctly (idx 1)');
    assert(decrypted1.owner_pk === alicePk,   'Auditor decrypts change owner_pk correctly (idx 1)');

    // Out-of-scope index — should return empty bytes (US-5 negative)
    const ctOutVal = await readTx(CORE_ID, 'request_disclosure', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toU64(99999n),
    ], kp);
    const ctOut = Buffer.from(ctOutVal.bytes());
    assert(ctOut.length === 0, 'request_disclosure on out-of-scope index returns empty (US-5 negative)');

    // ── 5. Double-spend rejected (RULE 3) ─────────────────────────────────────

    console.log('\n--- 5. Double-spend rejected ---');

    try {
        await submitTx(CORE_ID, 'withdraw', [
            new StellarSdk.Address(TOKEN_ID).toScVal(),
            new StellarSdk.Address(kp.publicKey()).toScVal(),
            toStruct({
                a: toBytesN64(serializedWdProof.a),
                b: toBytesN128(serializedWdProof.b),
                c: toBytesN64(serializedWdProof.c),
            }),
            toStruct({
                root: toBytesN(root.toString(16)),
                nf_in_0: toBytesN(nf_in_0.toString(16)),
                nf_in_1: toBytesN(nf_in_1.toString(16)),
                cm_change: toBytesN(cm_change.toString(16)),
                public_amount: toBytesN(withdrawAmount.toString(16)),
                asset_id: toBytesN(noteA.asset_id.toString(16)),
                recipient_hash: toBytesN(recipientHash.toString(16)),
            }),
            toBytes(auditorCtChange),
        ], kp);
        assert(false, 'Double-spend should have been rejected');
    } catch (e) {
        console.log('Expected error:', e.message);
        assert(true, 'Double-spend correctly rejected (RULE 3)');
    }

    console.log('\n=== M2 withdraw-and-audit test COMPLETE ===');
    console.log('All TEST_PLAN M2 assertions satisfied: US-2, US-5, RULE 3, RULE 4');
}

main().catch(e => { console.error(e); process.exit(1); });
