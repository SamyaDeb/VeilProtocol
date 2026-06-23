/**
 * Shared Merkle tree for the Veil Protocol browser client.
 *
 * Canonical copy lives here; e2e-tests/src/merkle.js mirrors it.
 * DO NOT alter the hash function, depth, or zero-hash initialisation —
 * these parameters must match the on-chain Poseidon CAP-0075 constants
 * (CIRCUITS.md §0, REFERENCES.md CAP-0075).
 */

import { buildPoseidon } from 'circomlibjs';

export class MerkleTree {
    constructor(depth, poseidon, leaves = []) {
        this.depth = depth;
        this.poseidon = poseidon;
        this.F = poseidon.F;
        this.leaves = leaves.map(l => (typeof l === 'bigint' ? l : BigInt(l)));

        // Precompute zero hashes for each level.
        this.zeroHashes = [0n];
        for (let i = 0; i < depth; i++) {
            this.zeroHashes.push(this.hash(this.zeroHashes[i], this.zeroHashes[i]));
        }

        this.buildTree();
    }

    buildTree() {
        this.tree = [];
        this.tree.push([...this.leaves]);

        const numLeaves = 2 ** this.depth;
        while (this.tree[0].length < numLeaves) {
            this.tree[0].push(this.zeroHashes[0]);
        }

        for (let i = 0; i < this.depth; i++) {
            const currentLevel = this.tree[i];
            const nextLevel = [];
            const lastNonZeroPairIndex = Math.ceil(this.leaves.length / (2 ** i)) * 2;

            for (let j = 0; j < currentLevel.length; j += 2) {
                if (j >= lastNonZeroPairIndex) {
                    nextLevel.push(this.zeroHashes[i + 1]);
                } else {
                    nextLevel.push(this.hash(currentLevel[j], currentLevel[j + 1]));
                }
            }
            this.tree.push(nextLevel);
        }
    }

    hash(left, right) {
        if (typeof left !== 'bigint') left = BigInt(left);
        if (typeof right !== 'bigint') right = BigInt(right);
        const h = this.poseidon([left, right]);
        return BigInt(this.F.toString(h));
    }

    get root() {
        return this.tree[this.depth][0];
    }

    getProof(index) {
        const pathElements = [];
        const pathIndices = [];
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

    /** Insert a new leaf and rebuild affected nodes. */
    insert(leaf) {
        this.leaves.push(typeof leaf === 'bigint' ? leaf : BigInt(leaf));
        this.buildTree();
        return this.leaves.length - 1;
    }
}

/**
 * Build a sorted non-membership proof for `value` in `tree`.
 * Returns the lower/upper bounding leaves and their Merkle paths.
 * The blocked-set tree MUST have its leaves sorted in ascending order.
 */
export function buildNonMembershipProof(tree, value) {
    const sortedLeaves = [...tree.leaves].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

    let lowerLeaf = 0n;
    let upperLeaf = 0n;

    for (let i = 0; i < sortedLeaves.length; i++) {
        if (sortedLeaves[i] > value) {
            upperLeaf = sortedLeaves[i];
            break;
        }
        lowerLeaf = sortedLeaves[i];
    }

    const lowerIdx = tree.tree[0].indexOf(lowerLeaf);
    const upperIdx = tree.tree[0].indexOf(upperLeaf);

    const lowerProof = tree.getProof(lowerIdx === -1 ? 0 : lowerIdx);
    const upperProof = tree.getProof(upperIdx === -1 ? 0 : upperIdx);

    return {
        lower_leaf: lowerLeaf,
        upper_leaf: upperLeaf,
        lower_path: lowerProof.pathElements,
        lower_idx: lowerProof.pathIndices,
        upper_path: upperProof.pathElements,
        upper_idx: upperProof.pathIndices,
    };
}

/** Convenience: build a MerkleTree from a flat array of commitment field elements. */
export async function buildMerkleTree(leaves, depth = 32) {
    const poseidon = await buildPoseidon();
    return new MerkleTree(depth, poseidon, leaves);
}
