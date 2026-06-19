import { rpc, Keypair, Contract, TransactionBuilder, Networks, xdr, Address } from '@stellar/stellar-sdk';
import { buildPoseidon } from 'circomlibjs';
import { MerkleTree, buildNonMembershipProof } from './e2e-tests/src/merkle.js';
import 'dotenv/config';

function toBytesN(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0').slice(0, 64), 'hex')); }
function toBytes(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex, 'hex')); }
function toVec(arr) { return xdr.ScVal.scvVec(arr); }
function toU32(n) { return xdr.ScVal.scvU32(n); }
function toStruct(obj) {
    const fields = Object.keys(obj).map(k => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: obj[k] }));
    return xdr.ScVal.scvMap(fields);
}

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const cred_secret = 1n;
    const issuer_pk = 456n;
    const credLeafHash = poseidon([cred_secret, issuer_pk]);
    const credLeaf = BigInt(F.toString(credLeafHash));

    const approvedTree = new MerkleTree(20, poseidon, [credLeaf]);
    const MAX = (1n << 252n) - 1n;
    const blockedTree = new MerkleTree(20, poseidon, [1n, MAX]);

    const approvedProof = approvedTree.getProof(0);
    const nmProof = buildNonMembershipProof(blockedTree, credLeaf);
    
    const kp = Keypair.fromSecret(process.env.SECRET);
    const server = new rpc.Server('https://soroban-testnet.stellar.org');
    const contract = new Contract(process.env.ASP);

    console.log("Approved root:", approvedTree.root.toString(16));
    console.log("Blocked root:", blockedTree.root.toString(16));

    const p = toStruct({
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
    });

    const tx = new TransactionBuilder(await server.getAccount(kp.publicKey()), { fee: '100000', networkPassphrase: Networks.TESTNET })
        .addOperation(contract.call('check_entry', new Address(process.env.VEIL_CORE).toScVal(), p))
        .setTimeout(30).build();
    
    try {
        const sim = await server.simulateTransaction(tx);
        console.log("check_entry sim result:", sim.result ? sim.result.retval : sim.error);
        if (sim.events) console.log("Events:", JSON.stringify(sim.events, null, 2));
    } catch(e) {
        console.error("Simulation failed:", e);
    }
}
main();
