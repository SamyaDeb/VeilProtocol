import { buildPoseidon } from 'circomlibjs';

export class MerkleTree {
    constructor(depth, poseidon, leaves = []) {
        this.depth = depth;
        this.poseidon = poseidon;
        this.F = poseidon.F;
        this.leaves = leaves.map(l => (typeof l === 'bigint' ? l : BigInt(l)));
        
        // Precompute zero hashes for each level
        this.zeroHashes = [0n];
        for (let i = 0; i < depth; i++) {
            this.zeroHashes.push(this.hash(this.zeroHashes[i], this.zeroHashes[i]));
        }

        this.buildTree();
    }

    buildTree() {
        this.tree = [];
        this.tree.push([...this.leaves]);
        
        // Pad the leaves level with the zero hash for level 0
        const numLeaves = 2 ** this.depth;
        while (this.tree[0].length < numLeaves) {
            this.tree[0].push(this.zeroHashes[0]);
        }

        for (let i = 0; i < this.depth; i++) {
            const currentLevel = this.tree[i];
            const nextLevel = [];
            // Optimization: we only need to compute hashes for pairs where at least one element is not a zero hash.
            // Since elements after leaves.length are all zero hashes, we can stop early.
            // Actually, we need the whole tree for getProof, so we compute all for now.
            // But we can optimize by only computing up to the last non-zero hash of the current level.
            let lastNonZeroPairIndex = Math.ceil(this.leaves.length / (2 ** i)) * 2;
            
            for (let j = 0; j < currentLevel.length; j += 2) {
                if (j >= lastNonZeroPairIndex) {
                    nextLevel.push(this.zeroHashes[i + 1]);
                } else {
                    const left = currentLevel[j];
                    const right = currentLevel[j + 1];
                    nextLevel.push(this.hash(left, right));
                }
            }
            this.tree.push(nextLevel);
        }
    }

    hash(left, right) {
        if (typeof left !== 'bigint') left = BigInt(left);
        if (typeof right !== 'bigint') right = BigInt(right);
        const hash = this.poseidon([left, right]);
        return BigInt(this.F.toString(hash));
    }

    get root() {
        return this.tree[this.depth][0];
    }

    getProof(index) {
        let pathElements = [];
        let pathIndices = [];
        let currentIndex = index;

        for (let i = 0; i < this.depth; i++) {
            const isRightChild = currentIndex % 2 === 1;
            pathIndices.push(isRightChild ? 1 : 0);

            const siblingIndex = isRightChild ? currentIndex - 1 : currentIndex + 1;
            pathElements.push(this.tree[i][siblingIndex]);

            currentIndex = Math.floor(currentIndex / 2);
        }

        return { pathElements, pathIndices };
    }
}

export function buildNonMembershipProof(tree, value) {
    // Find adjacent leaves
    let sortedLeaves = [...tree.leaves];
    sortedLeaves.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    
    let lowerLeaf = 0n;
    let upperLeaf = 0n;

    for (let i = 0; i < sortedLeaves.length; i++) {
        if (sortedLeaves[i] > value) {
            upperLeaf = sortedLeaves[i];
            break;
        }
        lowerLeaf = sortedLeaves[i];
    }

    if (upperLeaf === 0n) { // If value is greater than all elements, the upper leaf is the default padding value which is 0. 
        // Wait, the leaves are padded with 0n. 
        // So a non-membership proof might be hard if the tree is mostly 0n.
        // But the 0s are padded at the end of the array. The actual tree is ordered.
        // But wait, the blocked tree leaves must be sorted before putting into the tree!
    }

    const lowerIdx = tree.tree[0].indexOf(lowerLeaf);
    const upperIdx = tree.tree[0].indexOf(upperLeaf);

    const lowerProof = tree.getProof(lowerIdx);
    const upperProof = tree.getProof(upperIdx);

    return {
        lower_leaf: lowerLeaf,
        upper_leaf: upperLeaf,
        lower_path: lowerProof.pathElements,
        lower_idx: lowerProof.pathIndices,
        upper_path: upperProof.pathElements,
        upper_idx: upperProof.pathIndices
    };
}
