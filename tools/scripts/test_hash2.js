import { buildPoseidon } from 'circomlibjs';
import { MerkleTree } from './e2e-tests/src/merkle.js';
async function main() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const credLeafHash = poseidon([1n, 456n]);
    const credLeaf = BigInt(F.toString(credLeafHash));
    const tree = new MerkleTree(20, poseidon, [credLeaf]);
    let current = credLeaf;
    console.log("credLeaf:", credLeaf.toString(16).padStart(64, '0'));
    const proof = tree.getProof(0);
    for (let i = 0; i < 20; i++) {
        console.log(`Level ${i}: sibling = ${proof.pathElements[i].toString(16).padStart(64, '0')}`);
        const hash = poseidon([current, proof.pathElements[i]]);
        current = BigInt(F.toString(hash));
        console.log(`Level ${i} out: ${current.toString(16).padStart(64, '0')}`);
    }
    console.log("Expected root:", current.toString(16).padStart(64, '0'));
}
main();
