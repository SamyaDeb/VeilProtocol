import { buildPoseidon } from 'circomlibjs';
import { MerkleTree, buildNonMembershipProof } from './merkle.js';

async function main() {
    console.time('buildPoseidon');
    const poseidon = await buildPoseidon();
    console.timeEnd('buildPoseidon');

    console.time('buildTree');
    const tree = new MerkleTree(20, poseidon, [123n, 456n, 789n]);
    console.timeEnd('buildTree');

    console.log('root:', tree.root.toString());
    const proof = tree.getProof(0);
    //console.log('proof:', proof);

    console.time('buildNonMembershipProof');
    const nmProof = buildNonMembershipProof(tree, 500n);
    console.timeEnd('buildNonMembershipProof');
    console.log('nm lower:', nmProof.lower_leaf.toString());
    console.log('nm upper:', nmProof.upper_leaf.toString());
}
main().catch(console.error);
