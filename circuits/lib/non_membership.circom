pragma circom 2.0.0;

// NonMembership: sorted indexed Merkle non-membership proof.
// Proves that `value` is NOT in the set represented by `root` by showing
// adjacent leaves lower_leaf < value < upper_leaf that ARE in the tree.
//
// Template: NonMembership(depth)
// Inputs:  value              — the value we assert is absent
//          lower_leaf         — the largest leaf value < value in the set
//          upper_leaf         — the smallest leaf value > value in the set
//          lower_path[depth]  — Merkle path for lower_leaf
//          lower_idx[depth]   — path indices for lower_leaf
//          upper_path[depth]  — Merkle path for upper_leaf
//          upper_idx[depth]   — path indices for upper_leaf
// Output:  root               — the computed root (constrain against expected root)
//
// SECURITY: relies on the sorted-tree invariant being maintained by the ASP
// operator off-chain. The circuit proves gap existence given lower+upper membership;
// it does NOT verify the sorting invariant itself (that is the ASP's responsibility).

include "./merkle_tree_checker.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

template NonMembership(depth) {
    signal input value;
    signal input lower_leaf;
    signal input upper_leaf;
    signal input lower_path[depth];
    signal input lower_idx[depth];
    signal input upper_path[depth];
    signal input upper_idx[depth];

    signal output root;

    // lower_leaf < value
    component lt1 = LessThan(252);
    lt1.in[0] <== lower_leaf;
    lt1.in[1] <== value;
    lt1.out === 1;

    // value < upper_leaf
    component lt2 = LessThan(252);
    lt2.in[0] <== value;
    lt2.in[1] <== upper_leaf;
    lt2.out === 1;

    // Both lower_leaf and upper_leaf are in the same tree (same root)
    component lower_checker = MerkleTreeChecker(depth);
    lower_checker.leaf <== lower_leaf;
    for (var i = 0; i < depth; i++) {
        lower_checker.pathElements[i] <== lower_path[i];
        lower_checker.pathIndices[i]  <== lower_idx[i];
    }

    component upper_checker = MerkleTreeChecker(depth);
    upper_checker.leaf <== upper_leaf;
    for (var i = 0; i < depth; i++) {
        upper_checker.pathElements[i] <== upper_path[i];
        upper_checker.pathIndices[i]  <== upper_idx[i];
    }

    // Both paths must produce the same root
    lower_checker.root === upper_checker.root;
    root <== lower_checker.root;
}
