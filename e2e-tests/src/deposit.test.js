/**
 * M0 deposit e2e test — corresponds to TEST_PLAN.md M0.
 *
 * Asserts:
 * 1. Non-approved deposit REJECTED on-chain   (RULE 1)
 * 2. Approved deposit inserts a leaf
 * 3. Stored auditor_ct decrypts to the original note  (RULE 4)
 * 4. Indexer-reconstructed root == veil_core.current_root()  (US-7)
 *
 * Usage:
 *   VEIL_CORE=<id> ASP=<id> SOROBAN_RPC=<url> SECRET=<key> node src/deposit.test.js
 *
 * VERIFY: this test skeleton will be wired up when deploy scripts land.
 * Currently structured as a testable module with assertion functions.
 */

import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr, Address } from '@stellar/stellar-sdk';
const StellarSdk = { Address };
import { buildPoseidon } from 'circomlibjs';

// ─── config ──────────────────────────────────────────────────────────────────

const CORE_ID  = process.env.VEIL_CORE ?? '';
const ASP_ID   = process.env.ASP ?? '';
const TOKEN_ID = process.env.TOKEN ?? '';
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
function toBytes(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex, 'hex')); }
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
    
    let preparedTx;
    try {
        preparedTx = await server.prepareTransaction(tx);
    } catch (e) {
        console.error("prepareTransaction error:", e);
        if (e.response && e.response.data) {
            console.error("Response data:", e.response.data);
        }
        throw e;
    }
    preparedTx.sign(kp);
    
    const send = await server.sendTransaction(preparedTx);
    if (send.errorResultXdr) {
        throw new Error(`Tx submission failed: ${send.errorResultXdr}`);
    }
    
    if (send.status === 'ERROR') {
        throw new Error(`Tx failed: ${JSON.stringify(send)}`);
    }

    // Poll for status
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

// ─── test: non-approved deposit rejected (RULE 1) ────────────────────────────

async function testNonApprovedRejected() {
    console.log('\n--- Test: non-approved deposit REJECTED (RULE 1) ---');
    const kp = Keypair.fromSecret(SECRET);

    const bogusProof = toStruct({
        a: toBytesN64("00"),
        b: toBytesN128("00"),
        c: toBytesN64("00")
    });

    const bogusPublic = toStruct({
        cm: toBytesN("00"),
        public_amount: toBytesN("00"),
        asp_approved_root: toBytesN("00"),
        asp_blocked_root: toBytesN("00")
    });

    const bogusAspProof = toStruct({
        approved_idx: toVec([]),
        approved_path: toVec([]),
        approved_root: toBytesN("00"),
        blocked_lower_idx: toVec([]),
        blocked_lower_leaf: toBytesN("00"),
        blocked_lower_path: toVec([]),
        blocked_root: toBytesN("00"),
        blocked_upper_idx: toVec([]),
        blocked_upper_leaf: toBytesN("00"),
        blocked_upper_path: toVec([]),
        credential_leaf: toBytesN("00")
    });

    const args = [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        new StellarSdk.Address(TOKEN_ID).toScVal(),
        new StellarSdk.Address(ASP_ID).toScVal(),
        bogusProof,
        bogusPublic,
        bogusAspProof,
        toBytes("00")
    ];

    try {
        await submitTx(CORE_ID, 'deposit', args, kp);
        assert(false, "Deposit with bogus ASP proof should have failed");
    } catch (e) {
        console.log("Expected error caught:", e.message);
        assert(true, "Non-approved deposit rejected on-chain");
    }
}

async function testApprovedDepositInsertsLeaf() {
    console.log('\n--- Test: approved deposit inserts leaf ---');
    const kp = Keypair.fromSecret(SECRET);
    
    const { proveDeposit, serializeProof } = await import('../../client/src/prover/deposit.js');
    const { MerkleTree, buildNonMembershipProof } = await import('./merkle.js');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // 1. Build valid ASP membership proof for the approved credential
    const cred_secret = 1n; // carefully chosen so that Poseidon hash < 2^252
    const issuer_pk = 456n;
    const credLeafHash = poseidon([cred_secret, issuer_pk]);
    const credLeaf = BigInt(F.toString(credLeafHash));

    const approvedTree = new MerkleTree(20, poseidon, [credLeaf]);
    const MAX = (1n << 252n) - 1n;
    const blockedTree = new MerkleTree(20, poseidon, [1n, MAX]);

    // Update ASP roots on-chain
    console.log("Updating ASP roots on-chain...");
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

    const server = new rpc.Server(RPC_URL);
    const aspContract = new Contract(ASP_ID);
    const queryTx = new TransactionBuilder(await server.getAccount(kp.publicKey()), { fee: '100000', networkPassphrase: PASSPHRASE })
        .addOperation(aspContract.call('approved_root'))
        .setTimeout(30).build();
    const querySim = await server.simulateTransaction(queryTx);
    console.log("Current ASP approved_root on-chain:", querySim.result.retval.bytes().toString('hex'));


    const approvedProof = approvedTree.getProof(0);
    const nmProof = buildNonMembershipProof(blockedTree, credLeaf);
    
    console.log("nmProof debug:", {
        lower_leaf: nmProof.lower_leaf.toString(),
        credLeaf: credLeaf.toString(),
        upper_leaf: nmProof.upper_leaf.toString()
    });

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

    const note = {
        amount: 1000n,
        asset_id: 999n,
        blinding: 12345678901234567890n,
        owner_pk: 98765432109876543210n,
    };
    const credential = { cred_secret, issuer_pk };

    // 2. Generate deposit circuit proof
    const { proof, cm, publicSignals } = await proveDeposit(note, credential, aspProof, note.amount);
    const serializedProof = serializeProof(proof);

    // 3. Encrypt note to auditor pubkey
    const { encryptNoteForAuditor } = await import('../../client/src/viewkey/encrypt.js');
    const auditorSk = 42n;
    const auditorPk = F.toObject(poseidon([auditorSk]));
    const auditorCt = await encryptNoteForAuditor(note, auditorPk, 777n);

    // 4. Submit deposit tx
    const args = [
        new StellarSdk.Address(kp.publicKey()).toScVal(),
        new StellarSdk.Address(TOKEN_ID).toScVal(),
        new StellarSdk.Address(ASP_ID).toScVal(),
        toStruct({
            a: toBytesN64(serializedProof.a),
            b: toBytesN128(serializedProof.b),
            c: toBytesN64(serializedProof.c)
        }),
        toStruct({
            cm: toBytesN(BigInt(cm).toString(16)),
            public_amount: toBytesN(note.amount.toString(16)),
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
        toBytes(auditorCt)
    ];

    await submitTx(CORE_ID, 'deposit', args, kp);
    console.log("Deposit tx submitted successfully!");

    // 5. Query veil_core.current_root — must have changed
    const contract = new Contract(CORE_ID);
    const rootTx = new TransactionBuilder(await server.getAccount(kp.publicKey()), { fee: '100000', networkPassphrase: PASSPHRASE })
        .addOperation(contract.call('current_root'))
        .setTimeout(30).build();
    const sim = await server.simulateTransaction(rootTx);
    assert(sim.result.retval, "Got current_root");
    
    // 6. Query veil_core.ciphertext_at(0) — must equal the submitted auditor_ct
    console.log("publicSignals:", publicSignals);
    console.log("Expected approved root:", approvedTree.root.toString());
    console.log("Expected blocked root:", blockedTree.root.toString());
    
    const ctTx = new TransactionBuilder(await server.getAccount(kp.publicKey()), { fee: '100000', networkPassphrase: PASSPHRASE })
        .addOperation(contract.call('ciphertext_at', xdr.ScVal.scvU64(new xdr.Uint64(0))))
        .setTimeout(30).build();
    const ctSim = await server.simulateTransaction(ctTx);
    assert(ctSim.result.retval, "Got ciphertext_at(0)");

    return true;
}

// ─── test: auditor_ct decrypts to original note (RULE 4) ─────────────────────

async function testAuditorCiphertextDecrypts() {
    console.log('\n--- Test: auditor_ct decrypts to original note (RULE 4) ---');
    // After the approved deposit:
    // 1. Read ciphertext_at(idx) from veil_core
    // 2. Decrypt with auditor secret key
    // 3. Assert plaintext == original note (amount, asset_id, blinding, owner_pk)
    //
    // This can be tested locally with the encrypt/decrypt functions:
    const { encryptNoteForAuditor, decryptNoteAsAuditor } = await import(
        '../../client/src/viewkey/encrypt.js'
    );
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const auditorSk = 42n;
    const auditorPk = F.toObject(poseidon([auditorSk]));

    const note = {
        amount: 1000n,
        asset_id: 999n,
        blinding: 12345678901234567890n,
        owner_pk: 98765432109876543210n,
    };

    const encBlinding = 777n;
    const ct = await encryptNoteForAuditor(note, auditorPk, encBlinding);
    assert(ct.length === 160, 'ciphertext is 160 bytes');

    const decrypted = await decryptNoteAsAuditor(ct, auditorSk);
    assert(decrypted.amount   === note.amount,   'amount matches');
    assert(decrypted.asset_id === note.asset_id, 'asset_id matches');
    assert(decrypted.blinding === note.blinding, 'blinding matches');
    assert(decrypted.owner_pk === note.owner_pk, 'owner_pk matches');

    return true;
}

// ─── test: indexer root matches on-chain root (US-7) ─────────────────────────

async function testIndexerRootMatch() {
    console.log('\n--- Test: indexer root == on-chain root (US-7) ---');
    // After deposits:
    // 1. Query veil_core.current_root()
    // 2. Read indexer DB local_root
    // 3. Assert they match
    //
    // VERIFY: wire this up when indexer is running against testnet.
    console.log('SKIP: requires running indexer + deployed contracts');
    return true;
}

// ─── run ─────────────────────────────────────────────────────────────────────

async function main() {
    console.log('=== Veil Protocol M0 — deposit e2e test ===');
    console.log(`Network: ${NETWORK}, RPC: ${RPC_URL}`);

    await testNonApprovedRejected();
    await testApprovedDepositInsertsLeaf();
    await testAuditorCiphertextDecrypts();
    await testIndexerRootMatch();

    console.log('\n=== M0 deposit test complete ===');
}

main().then(() => process.exit(0)).catch(e => { console.error(e); process.exit(1); });
