import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr } from '@stellar/stellar-sdk';
import { Address } from '@stellar/stellar-sdk';
const StellarSdk = { Address };
import { buildPoseidon } from 'circomlibjs';
import { MerkleTree, buildNonMembershipProof } from './merkle.js';
import { proveTransfer, serializeProof, serializePublicInputs } from '../../app/src/prover/transfer.js';
import { proveDeposit, serializeProof as serializeDepositProof } from '../../app/src/prover/deposit.js';
import { encryptNoteForAuditor, decryptNoteAsAuditor } from '../../app/src/viewkey/encrypt.js';

// ─── config ──────────────────────────────────────────────────────────────────

const CORE_ID  = process.env.VEIL_CORE ?? '';
const ASP_ID   = process.env.ASP ?? '';
const RPC_URL  = process.env.SOROBAN_RPC ?? 'https://soroban-testnet.stellar.org';
const SECRET   = process.env.SECRET ?? '';
const NETWORK  = process.env.NETWORK ?? 'testnet';
const PASSPHRASE = NETWORK === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;

// ─── helpers ──────────────────────────────────────────────────────────────────

function assert(cond, msg) {
    if (!cond) {
        console.error(`FAIL: ${msg}`);
        process.exit(1);
    }
    console.log(`PASS: ${msg}`);
}

async function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function toBytesN(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0').slice(0, 64), 'hex')); }
function toBytesN128(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(256, '0').slice(0, 256), 'hex')); }
function toBytesN64(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(128, '0').slice(0, 128), 'hex')); }
function toBytes(hex) {
    if (typeof hex !== 'string') hex = hex.toString('hex');
    return xdr.ScVal.scvBytes(Buffer.from(hex, 'hex'));
}
function toU32(val) { return xdr.ScVal.scvU32(val); }
function toVec(vals) { return xdr.ScVal.scvVec(vals); }
function toStruct(obj) {
    const entries = Object.keys(obj).sort().map(key => {
        return new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol(key),
            val: obj[key]
        });
    });
    return xdr.ScVal.scvMap(entries);
}

async function submitTx(contractId, method, args, kp) {
    const server = new rpc.Server(RPC_URL);
    const account = await server.getAccount(kp.publicKey());
    const contract = new Contract(contractId);
    
    const tx = new TransactionBuilder(account, { fee: '1000000', networkPassphrase: PASSPHRASE })
        .addOperation(contract.call(method, ...args))
        .setTimeout(30)
        .build();
    
    let preparedTx = await server.prepareTransaction(tx);
    preparedTx.sign(kp);
    
    const send = await server.sendTransaction(preparedTx);
    if (send.errorResultXdr) {
        throw new Error(`Tx submission failed: ${send.errorResultXdr}`);
    }
    if (send.status === 'ERROR') {
        throw new Error(`Tx failed: ${JSON.stringify(send)}`);
    }

    let status = send.status;
    let res = send;
    while (status === 'PENDING' || status === 'NOT_FOUND') {
        await sleep(2000);
        res = await server.getTransaction(send.hash);
        status = res.status;
    }
    
    if (status !== 'SUCCESS') {
        throw new Error(`Tx execution failed: ${JSON.stringify(res)}`);
    }
    
    return res;
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
    console.log('=== Veil Protocol M1 — transfer e2e test ===');
    console.log(`Network: ${NETWORK}, RPC: ${RPC_URL}`);

    const kp = Keypair.fromSecret(SECRET);
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const aliceSk = 101n;
    const alicePk = F.toObject(poseidon([aliceSk]));
    const bobSk = 202n;
    const bobPk = F.toObject(poseidon([bobSk]));
    const auditorSk = 42n;
    const auditorPk = F.toObject(poseidon([auditorSk]));

    console.log('\n--- 0. Setup: Alice deposits 1000 ---');
    const noteA = {
        amount: 1000n,
        asset_id: 999n,
        blinding: 11111n,
        owner_pk: alicePk,
    };

    const cred_secret = 1n;
    const issuer_pk = 456n;
    const credLeafHash = poseidon([cred_secret, issuer_pk]);
    const credLeaf = BigInt(F.toString(credLeafHash));

    const approvedTree = new MerkleTree(20, poseidon, [credLeaf]);
    const MAX = (1n << 252n) - 1n;
    const blockedTree = new MerkleTree(20, poseidon, [1n, MAX]);

    await submitTx(ASP_ID, 'update_approved', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toBytesN(approvedTree.root.toString(16)),
        toBytes("00")
    ], kp);
    await submitTx(ASP_ID, 'update_blocked', [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        toBytesN(blockedTree.root.toString(16)),
        toBytes("00")
    ], kp);

    const approvedProof = approvedTree.getProof(0);
    const nmProof = buildNonMembershipProof(blockedTree, credLeaf);
    
    const aspProof = {
        asp_path: approvedProof.pathElements,
        asp_idx: approvedProof.pathIndices,
        blocked_lower_leaf: nmProof.lower_leaf,
        blocked_upper_leaf: nmProof.upper_leaf,
        blocked_lower_path: nmProof.lower_path,
        blocked_lower_idx: nmProof.lower_idx,
        blocked_upper_path: nmProof.upper_path,
        blocked_upper_idx: nmProof.upper_idx,
        asp_approved_root: approvedTree.root,
        asp_blocked_root: blockedTree.root
    };

    const { proof: depProof, cm: cmA, publicSignals: depPub } = await proveDeposit(noteA, { cred_secret, issuer_pk }, aspProof, noteA.amount);
    const serializedDepProof = serializeDepositProof(depProof);
    const auditorCtDep = await encryptNoteForAuditor(noteA, auditorPk, 777n);

    await submitTx(CORE_ID, 'deposit', [
        new StellarSdk.Address(ASP_ID).toScVal(),
        toStruct({ a: toBytesN64(serializedDepProof.a), b: toBytesN128(serializedDepProof.b), c: toBytesN64(serializedDepProof.c) }),
        toStruct({
            cm: toBytesN(BigInt(cmA).toString(16)),
            public_amount: toBytesN(noteA.amount.toString(16)),
            asp_approved_root: toBytesN(approvedTree.root.toString(16)),
            asp_blocked_root: toBytesN(blockedTree.root.toString(16))
        }),
        toStruct({
            approved_idx: toVec(approvedProof.pathIndices.map(toU32)),
            approved_path: toVec(approvedProof.pathElements.map(x => toBytesN(x.toString(16)))),
            approved_root: toBytesN(approvedTree.root.toString(16)),
            blocked_lower_idx: toVec(nmProof.lower_idx.map(toU32)),
            blocked_lower_leaf: toBytesN(nmProof.lower_leaf.toString(16)),
            blocked_lower_path: toVec(nmProof.lower_path.map(x => toBytesN(x.toString(16)))),
            blocked_root: toBytesN(blockedTree.root.toString(16)),
            blocked_upper_idx: toVec(nmProof.upper_idx.map(toU32)),
            blocked_upper_leaf: toBytesN(nmProof.upper_leaf.toString(16)),
            blocked_upper_path: toVec(nmProof.upper_path.map(x => toBytesN(x.toString(16)))),
            credential_leaf: toBytesN(credLeaf.toString(16))
        }),
        toBytes(auditorCtDep)
    ], kp);

    console.log(`PASS: Deposit successful.`);
    console.log(`Waiting for RPC to index events...`);
    await sleep(5000);

    console.log('\n--- 1. Sync Tree from RPC ---');
    const server = new rpc.Server(RPC_URL);
    const latestLedgerResp = await server.getLatestLedger();
    const startLedger = Math.max(1, latestLedgerResp.sequence - 500);
    
    let eventsResp;
    try {
        eventsResp = await server.getEvents({
            startLedger,
            filters: [{ type: 'contract', contractIds: [CORE_ID] }],
            limit: 10000,
        });
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
    
    let parsedLeaves = [];
    console.log(`Fetched ${eventsResp.events?.length || 0} events.`);
    if (eventsResp.events && eventsResp.events.length > 0) {
        console.log(`First event sample:`, JSON.stringify(eventsResp.events[0], null, 2));
    }
    
    for (const ev of eventsResp.events ?? []) {
        if (!ev.topic || ev.topic.length < 2) continue;
        try {
            // Let's try parsing both ways just in case
            let t0, t1, vec;
            if (typeof ev.topic[0] === 'string') {
                t0 = xdr.ScVal.fromXDR(ev.topic[0], 'base64').sym().toString();
                t1 = xdr.ScVal.fromXDR(ev.topic[1], 'base64').sym().toString();
                vec = xdr.ScVal.fromXDR(ev.value.xdr ?? ev.value, 'base64').vec();
            } else {
                t0 = ev.topic[0].sym().toString();
                t1 = ev.topic[1].sym().toString();
                vec = ev.value.vec();
            }
            if (t0 === 'leaf' && t1 === 'inserted') {
                const cmBytes = vec[0].bytes();
                const idx = vec[1].u64().low;
                parsedLeaves[idx] = BigInt('0x' + cmBytes.toString('hex'));
                console.log(`Found leaf ${idx}:`, parsedLeaves[idx].toString());
            }
        } catch(e) {}
    }
    
    // Fill gaps with 0n
    let numLeaves = parsedLeaves.length;
    let leaves = [];
    for (let i = 0; i < numLeaves; i++) {
        leaves[i] = parsedLeaves[i] ?? 0n;
    }
    
    const cmABigInt = BigInt(cmA);
    const leafIndexA = leaves.indexOf(cmABigInt);
    if (leafIndexA === -1) {
        console.error(`Expected cmA: ${cmABigInt.toString()}`);
        console.error(`Parsed leaves: ${leaves.map(l => l.toString())}`);
    }
    assert(leafIndexA !== -1, "Alice's deposit leaf found in tree");

    function getSparseProof(leavesArr, targetIndex, depth, poseidon) {
        const F = poseidon.F;
        let currentLevel = new Map();
        for (let i = 0; i < leavesArr.length; i++) {
            currentLevel.set(i, leavesArr[i]);
        }

        let pathElements = [];
        let pathIndices = [];
        let currentIndex = targetIndex;

        for (let i = 0; i < depth; i++) {
            const isRightChild = currentIndex % 2 === 1;
            pathIndices.push(isRightChild ? 1 : 0);

            const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;
            const sibling = currentLevel.has(siblingIndex) ? currentLevel.get(siblingIndex) : 0n;
            pathElements.push(sibling);

            let nextLevel = new Map();
            for (const [idx, val] of currentLevel.entries()) {
                const parentIdx = Math.floor(idx / 2);
                if (!nextLevel.has(parentIdx)) {
                    const isR = idx % 2 === 1;
                    const sibIdx = isR ? idx - 1 : idx + 1;
                    const sibVal = currentLevel.has(sibIdx) ? currentLevel.get(sibIdx) : 0n;
                    let hash;
                    if (isR) {
                        hash = poseidon([sibVal, val]);
                    } else {
                        hash = poseidon([val, sibVal]);
                    }
                    nextLevel.set(parentIdx, BigInt(F.toString(hash)));
                }
            }
            currentLevel = nextLevel;
            currentIndex = Math.floor(currentIndex / 2);
        }
        let root = currentLevel.has(0) ? currentLevel.get(0) : 0n;
        return { root, pathElements, pathIndices };
    }

    const cmAProof = getSparseProof(leaves, leafIndexA, 32, poseidon);
    const mt = { root: cmAProof.root };

    console.log('\n--- 2. A→B transfer hides amount + parties ---');
    const input0 = {
        amount: noteA.amount,
        asset_id: noteA.asset_id,
        blinding: noteA.blinding,
        owner_sk: aliceSk,
        leaf_index: BigInt(leafIndexA),
        path: cmAProof.pathElements,
        idx: cmAProof.pathIndices
    };
    const input1 = {
        amount: 0n,
        asset_id: noteA.asset_id,
        blinding: 0n,
        owner_sk: aliceSk,
        leaf_index: 0n,
        path: new Array(32).fill(0n),
        idx: new Array(32).fill(0)
    };

    const noteB = {
        amount: 400n,
        asset_id: noteA.asset_id,
        blinding: 22222n,
        owner_pk: bobPk
    };
    const changeA = {
        amount: 600n,
        asset_id: noteA.asset_id,
        blinding: 33333n,
        owner_pk: alicePk
    };

    const { proof: trProof, cm_out_0, cm_out_1, nf_in_0, nf_in_1 } = await proveTransfer(input0, input1, noteB, changeA, mt.root, 0n);
    const serializedTrProof = serializeProof(trProof);

    const outCt0 = await encryptNoteForAuditor(noteB, auditorPk, 111n);
    const outCt1 = await encryptNoteForAuditor(changeA, auditorPk, 222n);

    const noteCt0 = await encryptNoteForAuditor(noteB, bobPk, 888n);
    const noteCt1 = await encryptNoteForAuditor(changeA, alicePk, 999n);

    await submitTx(CORE_ID, 'transfer', [
        toStruct({ a: toBytesN64(serializedTrProof.a), b: toBytesN128(serializedTrProof.b), c: toBytesN64(serializedTrProof.c) }),
        toStruct({
            root: toBytesN(mt.root.toString(16)),
            nf_in_0: toBytesN(nf_in_0.toString(16)),
            nf_in_1: toBytesN(nf_in_1.toString(16)),
            cm_out_0: toBytesN(cm_out_0.toString(16)),
            cm_out_1: toBytesN(cm_out_1.toString(16)),
            public_amount: toBytesN("00")
        }),
        toVec([toBytes(outCt0), toBytes(outCt1)]),
        toVec([toBytes(noteCt0), toBytes(noteCt1)])
    ], kp);

    assert(true, 'Transfer transaction successful');

    console.log('\n--- 3. Recipient recovers the output note ---');
    const decryptedB = await decryptNoteAsAuditor(noteCt0, bobSk); // Actually encryptNoteForAuditor was used, so it's a symmetric decrypter
    assert(decryptedB.amount === 400n, 'Bob recovers amount');
    assert(decryptedB.owner_pk === bobPk, 'Bob recovers ownership');
    const cmB_computed = F.toObject(poseidon([decryptedB.amount, decryptedB.asset_id, decryptedB.blinding, decryptedB.owner_pk]));
    assert(cmB_computed.toString() === cm_out_0.toString(), 'Recomputed cm matches on-chain cm');

    console.log('\n--- 4. Double-spend rejected ---');
    try {
        await submitTx(CORE_ID, 'transfer', [
            toStruct({ a: toBytesN64(serializedTrProof.a), b: toBytesN128(serializedTrProof.b), c: toBytesN64(serializedTrProof.c) }),
            toStruct({
                root: toBytesN(mt.root.toString(16)),
                nf_in_0: toBytesN(nf_in_0.toString(16)),
                nf_in_1: toBytesN(nf_in_1.toString(16)),
                cm_out_0: toBytesN(cm_out_0.toString(16)),
                cm_out_1: toBytesN(cm_out_1.toString(16)),
                public_amount: toBytesN("00")
            }),
            toVec([toBytes(outCt0), toBytes(outCt1)]),
            toVec([toBytes(noteCt0), toBytes(noteCt1)])
        ], kp);
        assert(false, "Double spend should fail");
    } catch(e) {
        console.log("Expected error caught:", e.message);
        assert(true, "Double-spend rejected");
    }

    console.log('\n=== M1 transfer test complete ===');
}

main().catch(e => { console.error(e); process.exit(1); });
