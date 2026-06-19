pragma circom 2.0.0;

// transfer.circom — 2-in / 2-out shielded transfer
//
// Public inputs (in order):
//   1. root
//   2. nf_in_0
//   3. nf_in_1
//   4. cm_out_0
//   5. cm_out_1
//   6. public_amount   (== 0 for internal transfer; reserved for M2 withdraw reuse)

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Transfer(tree_depth) {
    // --- Public inputs ---
    signal input root;
    signal input nf_in_0;
    signal input nf_in_1;
    signal input cm_out_0;
    signal input cm_out_1;
    signal input public_amount;

    // --- Private inputs: Inputs ---
    signal input amount_in_0;
    signal input asset_in_0;
    signal input blinding_in_0;
    signal input owner_sk_0;
    signal input leaf_index_0;
    signal input path_0[tree_depth];
    signal input idx_0[tree_depth];

    signal input amount_in_1;
    signal input asset_in_1;
    signal input blinding_in_1;
    signal input owner_sk_1;
    signal input leaf_index_1;
    signal input path_1[tree_depth];
    signal input idx_1[tree_depth];

    // --- Private inputs: Outputs ---
    signal input amount_out_0;
    signal input asset_out_0;
    signal input blinding_out_0;
    signal input owner_pk_out_0;

    signal input amount_out_1;
    signal input asset_out_1;
    signal input blinding_out_1;
    signal input owner_pk_out_1;

    // --- Range Checks ---
    component rc_in_0 = RangeCheck64(); rc_in_0.x <== amount_in_0;
    component rc_in_1 = RangeCheck64(); rc_in_1.x <== amount_in_1;
    component rc_out_0 = RangeCheck64(); rc_out_0.x <== amount_out_0;
    component rc_out_1 = RangeCheck64(); rc_out_1.x <== amount_out_1;

    // --- Value Conservation ---
    amount_in_0 + amount_in_1 === amount_out_0 + amount_out_1 + public_amount;

    // --- Dummy Note Handling ---
    component isz_in_0 = IsZero(); isz_in_0.in <== amount_in_0;
    signal isReal_in_0 <== 1 - isz_in_0.out;

    component isz_in_1 = IsZero(); isz_in_1.in <== amount_in_1;
    signal isReal_in_1 <== 1 - isz_in_1.out;

    component isz_out_0 = IsZero(); isz_out_0.in <== amount_out_0;
    signal isReal_out_0 <== 1 - isz_out_0.out;

    component isz_out_1 = IsZero(); isz_out_1.in <== amount_out_1;
    signal isReal_out_1 <== 1 - isz_out_1.out;

    // --- Asset Consistency ---
    // All real inputs and outputs must share the same asset_id.
    signal diff_0_1 <== (asset_in_0 - asset_in_1) * isReal_in_0;
    diff_0_1 * isReal_in_1 === 0;

    signal diff_0_out0 <== (asset_in_0 - asset_out_0) * isReal_in_0;
    diff_0_out0 * isReal_out_0 === 0;

    signal diff_0_out1 <== (asset_in_0 - asset_out_1) * isReal_in_0;
    diff_0_out1 * isReal_out_1 === 0;

    signal diff_1_out0 <== (asset_in_1 - asset_out_0) * isReal_in_1;
    diff_1_out0 * isReal_out_0 === 0;

    signal diff_1_out1 <== (asset_in_1 - asset_out_1) * isReal_in_1;
    diff_1_out1 * isReal_out_1 === 0;

    // --- Input 0 ---
    component cm_in_0 = CommitmentHasher();
    cm_in_0.amount <== amount_in_0;
    cm_in_0.asset_id <== asset_in_0;
    cm_in_0.blinding <== blinding_in_0;
    component pk_in_0 = Poseidon(1);
    pk_in_0.inputs[0] <== owner_sk_0;
    cm_in_0.owner_pk <== pk_in_0.out;

    component mt_0 = MerkleTreeChecker(tree_depth);
    mt_0.leaf <== cm_in_0.cm;
    for(var i=0; i<tree_depth; i++) {
        mt_0.pathElements[i] <== path_0[i];
        mt_0.pathIndices[i] <== idx_0[i];
    }
    (mt_0.root - root) * isReal_in_0 === 0;

    component nf_0 = NullifierHasher();
    nf_0.owner_sk <== owner_sk_0;
    nf_0.leaf_index <== leaf_index_0;
    nf_0.cm <== cm_in_0.cm;
    
    nf_in_0 === isReal_in_0 * nf_0.nf;

    // --- Input 1 ---
    component cm_in_1 = CommitmentHasher();
    cm_in_1.amount <== amount_in_1;
    cm_in_1.asset_id <== asset_in_1;
    cm_in_1.blinding <== blinding_in_1;
    component pk_in_1 = Poseidon(1);
    pk_in_1.inputs[0] <== owner_sk_1;
    cm_in_1.owner_pk <== pk_in_1.out;

    component mt_1 = MerkleTreeChecker(tree_depth);
    mt_1.leaf <== cm_in_1.cm;
    for(var i=0; i<tree_depth; i++) {
        mt_1.pathElements[i] <== path_1[i];
        mt_1.pathIndices[i] <== idx_1[i];
    }
    (mt_1.root - root) * isReal_in_1 === 0;

    component nf_1 = NullifierHasher();
    nf_1.owner_sk <== owner_sk_1;
    nf_1.leaf_index <== leaf_index_1;
    nf_1.cm <== cm_in_1.cm;
    
    nf_in_1 === isReal_in_1 * nf_1.nf;

    // --- Output 0 ---
    component cm_hasher_out_0 = CommitmentHasher();
    cm_hasher_out_0.amount <== amount_out_0;
    cm_hasher_out_0.asset_id <== asset_out_0;
    cm_hasher_out_0.blinding <== blinding_out_0;
    cm_hasher_out_0.owner_pk <== owner_pk_out_0;
    
    cm_out_0 === isReal_out_0 * cm_hasher_out_0.cm;

    // --- Output 1 ---
    component cm_hasher_out_1 = CommitmentHasher();
    cm_hasher_out_1.amount <== amount_out_1;
    cm_hasher_out_1.asset_id <== asset_out_1;
    cm_hasher_out_1.blinding <== blinding_out_1;
    cm_hasher_out_1.owner_pk <== owner_pk_out_1;
    
    cm_out_1 === isReal_out_1 * cm_hasher_out_1.cm;
}

// tree_depth = 32 as per CIRCUITS.md Shared Definitions
component main {public [root, nf_in_0, nf_in_1, cm_out_0, cm_out_1, public_amount]} = Transfer(32);
