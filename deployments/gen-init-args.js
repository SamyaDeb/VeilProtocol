import { buildPoseidon } from 'circomlibjs';
import { MerkleTree } from '../e2e-tests/src/merkle.js';
import fs from 'fs';

async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // 1. Auditor PK
    const auditorSk = 42n;
    const auditorPkHash = poseidon([auditorSk]);
    let auditorPkHex = BigInt(F.toString(auditorPkHash)).toString(16).padStart(64, '0');

    // 2. Approved Root (needs at least one test credential)
    // cred_secret = 123n, issuer_pk = 456n
    const credLeafHash = poseidon([123n, 456n]);
    const credLeaf = BigInt(F.toString(credLeafHash));

    const approvedTree = new MerkleTree(20, poseidon, [credLeaf]);
    let approvedRootHex = approvedTree.root.toString(16).padStart(64, '0');

    // 3. Blocked Root (empty tree)
    const blockedTree = new MerkleTree(20, poseidon, []);
    let blockedRootHex = blockedTree.root.toString(16).padStart(64, '0');

    console.log(`AUDITOR_PK=${auditorPkHex}`);
    console.log(`APPROVED_ROOT=${approvedRootHex}`);
    console.log(`BLOCKED_ROOT=${blockedRootHex}`);
}

main().catch(console.error);
