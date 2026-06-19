pragma circom 2.0.0;

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// remove_liquidity.circom
// Public inputs (in order):
// 1. root
// 2. lp_nf
// 3. cm_out_0
// 4. cm_out_1
// 5. reserve_pre_commit
// 6. reserve_post_commit

template RemoveLiquidity(tree_depth) {
    // Public inputs
    signal input root;
    signal input lp_nf;
    signal input cm_out_0;
    signal input cm_out_1;
    signal input reserve_pre_commit;
    signal input reserve_post_commit;

    // Private inputs - LP Note
    signal input shares;
    signal input lp_asset;
    signal input lp_blinding;
    signal input lp_owner_sk;
    signal input lp_leaf_index;
    signal input lp_path[tree_depth];
    signal input lp_idx[tree_depth];

    // Private inputs - Output Notes
    signal input amount_out_0;
    signal input asset_out_0;
    signal input blinding_out_0;
    signal input owner_pk_0;

    signal input amount_out_1;
    signal input asset_out_1;
    signal input blinding_out_1;
    signal input owner_pk_1;

    // Private inputs - Reserves
    signal input pre_reserve_0;
    signal input pre_reserve_1;
    signal input pre_total_shares;
    signal input pre_reserve_blinding;

    signal input post_reserve_0;
    signal input post_reserve_1;
    signal input post_total_shares;
    signal input post_reserve_blinding;

    // 1. Validate LP Note
    component rc_shares = RangeCheck64(); rc_shares.x <== shares;
    component lp_pk_hasher = Poseidon(1); lp_pk_hasher.inputs[0] <== lp_owner_sk;
    
    component lp_cm_hasher = CommitmentHasher();
    lp_cm_hasher.amount <== shares;
    lp_cm_hasher.asset_id <== lp_asset;
    lp_cm_hasher.blinding <== lp_blinding;
    lp_cm_hasher.owner_pk <== lp_pk_hasher.out;

    component mt_lp = MerkleTreeChecker(tree_depth);
    mt_lp.leaf <== lp_cm_hasher.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt_lp.pathElements[i] <== lp_path[i];
        mt_lp.pathIndices[i] <== lp_idx[i];
    }
    mt_lp.root === root;

    component nf_lp = NullifierHasher();
    nf_lp.owner_sk <== lp_owner_sk;
    nf_lp.leaf_index <== lp_leaf_index;
    nf_lp.cm <== lp_cm_hasher.cm;
    lp_nf === nf_lp.nf;

    // 2. Validate Output Notes
    component rc_out_0 = RangeCheck64(); rc_out_0.x <== amount_out_0;
    component cm_hasher_0 = CommitmentHasher();
    cm_hasher_0.amount <== amount_out_0;
    cm_hasher_0.asset_id <== asset_out_0;
    cm_hasher_0.blinding <== blinding_out_0;
    cm_hasher_0.owner_pk <== owner_pk_0;
    cm_out_0 === cm_hasher_0.cm;

    component rc_out_1 = RangeCheck64(); rc_out_1.x <== amount_out_1;
    component cm_hasher_1 = CommitmentHasher();
    cm_hasher_1.amount <== amount_out_1;
    cm_hasher_1.asset_id <== asset_out_1;
    cm_hasher_1.blinding <== blinding_out_1;
    cm_hasher_1.owner_pk <== owner_pk_1;
    cm_out_1 === cm_hasher_1.cm;

    // 3. Reserve checks
    component rc_pre_0 = RangeCheck64(); rc_pre_0.x <== pre_reserve_0;
    component rc_pre_1 = RangeCheck64(); rc_pre_1.x <== pre_reserve_1;
    component rc_pre_ts = RangeCheck64(); rc_pre_ts.x <== pre_total_shares;

    component pre_res_cm = Poseidon(4);
    pre_res_cm.inputs[0] <== pre_reserve_0;
    pre_res_cm.inputs[1] <== pre_reserve_1;
    pre_res_cm.inputs[2] <== pre_total_shares;
    pre_res_cm.inputs[3] <== pre_reserve_blinding;
    reserve_pre_commit === pre_res_cm.out;

    component rc_post_0 = RangeCheck64(); rc_post_0.x <== post_reserve_0;
    component rc_post_1 = RangeCheck64(); rc_post_1.x <== post_reserve_1;
    component rc_post_ts = RangeCheck64(); rc_post_ts.x <== post_total_shares;

    component post_res_cm = Poseidon(4);
    post_res_cm.inputs[0] <== post_reserve_0;
    post_res_cm.inputs[1] <== post_reserve_1;
    post_res_cm.inputs[2] <== post_total_shares;
    post_res_cm.inputs[3] <== post_reserve_blinding;
    reserve_post_commit === post_res_cm.out;

    // 4. State transition
    post_reserve_0 === pre_reserve_0 - amount_out_0;
    post_reserve_1 === pre_reserve_1 - amount_out_1;
    post_total_shares === pre_total_shares - shares;

    // 5. Payout logic
    signal target_0;
    target_0 <== shares * pre_reserve_0;

    signal actual_0;
    actual_0 <== amount_out_0 * pre_total_shares;

    component leq_0 = LessEqThan(130);
    leq_0.in[0] <== actual_0;
    leq_0.in[1] <== target_0;
    leq_0.out === 1;

    component lt_0 = LessThan(130);
    lt_0.in[0] <== target_0 - actual_0;
    lt_0.in[1] <== pre_total_shares;
    lt_0.out === 1;

    signal target_1;
    target_1 <== shares * pre_reserve_1;

    signal actual_1;
    actual_1 <== amount_out_1 * pre_total_shares;

    component leq_1 = LessEqThan(130);
    leq_1.in[0] <== actual_1;
    leq_1.in[1] <== target_1;
    leq_1.out === 1;

    component lt_1 = LessThan(130);
    lt_1.in[0] <== target_1 - actual_1;
    lt_1.in[1] <== pre_total_shares;
    lt_1.out === 1;
}

component main {public [root, lp_nf, cm_out_0, cm_out_1, reserve_pre_commit, reserve_post_commit]} = RemoveLiquidity(32);
