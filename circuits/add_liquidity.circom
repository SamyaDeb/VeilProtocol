pragma circom 2.0.0;

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

// add_liquidity.circom
// Public inputs (in order):
// 1. root
// 2. nf_in_0
// 3. nf_in_1
// 4. lp_commit
// 5. reserve_pre_commit
// 6. reserve_post_commit

template AddLiquidity(tree_depth) {
    // Public inputs
    signal input root;
    signal input nf_in_0;
    signal input nf_in_1;
    signal input lp_commit;
    signal input reserve_pre_commit;
    signal input reserve_post_commit;

    // Private inputs - Note 0
    signal input amount_in_0;
    signal input asset_in_0;
    signal input blinding_in_0;
    signal input owner_sk_0;
    signal input leaf_index_0;
    signal input path_0[tree_depth];
    signal input idx_0[tree_depth];

    // Private inputs - Note 1
    signal input amount_in_1;
    signal input asset_in_1;
    signal input blinding_in_1;
    signal input owner_sk_1;
    signal input leaf_index_1;
    signal input path_1[tree_depth];
    signal input idx_1[tree_depth];

    // Private inputs - LP Note
    signal input shares;
    signal input lp_asset;
    signal input lp_blinding;
    signal input lp_owner_pk;

    // Private inputs - Reserves
    signal input pre_reserve_0;
    signal input pre_reserve_1;
    signal input pre_total_shares;
    signal input pre_reserve_blinding;

    signal input post_reserve_0;
    signal input post_reserve_1;
    signal input post_total_shares;
    signal input post_reserve_blinding;

    // 1. Validate Input Note 0
    component rc_in_0 = RangeCheck64(); rc_in_0.x <== amount_in_0;
    component pk_hasher_0 = Poseidon(1); pk_hasher_0.inputs[0] <== owner_sk_0;
    
    component cm_in_0 = CommitmentHasher();
    cm_in_0.amount <== amount_in_0;
    cm_in_0.asset_id <== asset_in_0;
    cm_in_0.blinding <== blinding_in_0;
    cm_in_0.owner_pk <== pk_hasher_0.out;

    component mt_0 = MerkleTreeChecker(tree_depth);
    mt_0.leaf <== cm_in_0.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt_0.pathElements[i] <== path_0[i];
        mt_0.pathIndices[i] <== idx_0[i];
    }
    mt_0.root === root;

    component nf_0 = NullifierHasher();
    nf_0.owner_sk <== owner_sk_0;
    nf_0.leaf_index <== leaf_index_0;
    nf_0.cm <== cm_in_0.cm;
    nf_in_0 === nf_0.nf;

    // 2. Validate Input Note 1
    component rc_in_1 = RangeCheck64(); rc_in_1.x <== amount_in_1;
    component pk_hasher_1 = Poseidon(1); pk_hasher_1.inputs[0] <== owner_sk_1;
    
    component cm_in_1 = CommitmentHasher();
    cm_in_1.amount <== amount_in_1;
    cm_in_1.asset_id <== asset_in_1;
    cm_in_1.blinding <== blinding_in_1;
    cm_in_1.owner_pk <== pk_hasher_1.out;

    component mt_1 = MerkleTreeChecker(tree_depth);
    mt_1.leaf <== cm_in_1.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt_1.pathElements[i] <== path_1[i];
        mt_1.pathIndices[i] <== idx_1[i];
    }
    mt_1.root === root;

    component nf_1 = NullifierHasher();
    nf_1.owner_sk <== owner_sk_1;
    nf_1.leaf_index <== leaf_index_1;
    nf_1.cm <== cm_in_1.cm;
    nf_in_1 === nf_1.nf;

    // 3. LP Note Formulated Correctly
    component rc_shares = RangeCheck64(); rc_shares.x <== shares;
    component lp_cm_hasher = CommitmentHasher();
    lp_cm_hasher.amount <== shares;
    lp_cm_hasher.asset_id <== lp_asset;
    lp_cm_hasher.blinding <== lp_blinding;
    lp_cm_hasher.owner_pk <== lp_owner_pk;
    lp_commit === lp_cm_hasher.cm;

    // 4. Reserve checks
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

    // 5. State transition & Math
    post_reserve_0 === pre_reserve_0 + amount_in_0;
    post_reserve_1 === pre_reserve_1 + amount_in_1;
    post_total_shares === pre_total_shares + shares;

    component is_pre_ts_zero = IsZero();
    is_pre_ts_zero.in <== pre_total_shares;

    signal prop_0;
    prop_0 <== amount_in_0 * pre_total_shares;
    signal prop_1;
    prop_1 <== amount_in_1 * pre_total_shares;

    signal shares_times_res_0;
    shares_times_res_0 <== shares * pre_reserve_0;
    
    signal shares_times_res_1;
    shares_times_res_1 <== shares * pre_reserve_1;

    component lt_rem_0 = LessThan(130);
    lt_rem_0.in[0] <== prop_0 - shares_times_res_0;
    lt_rem_0.in[1] <== pre_reserve_0;

    component leq_rem_0 = LessEqThan(130);
    leq_rem_0.in[0] <== shares_times_res_0;
    leq_rem_0.in[1] <== prop_0;

    component lt_rem_1 = LessThan(130);
    lt_rem_1.in[0] <== prop_1 - shares_times_res_1;
    lt_rem_1.in[1] <== pre_reserve_1;

    component leq_rem_1 = LessEqThan(130);
    leq_rem_1.in[0] <== shares_times_res_1;
    leq_rem_1.in[1] <== prop_1;

    signal check_0;
    check_0 <== lt_rem_0.out * leq_rem_0.out;
    
    signal check_1;
    check_1 <== lt_rem_1.out * leq_rem_1.out;

    (1 - is_pre_ts_zero.out) * (1 - check_0) === 0;
    (1 - is_pre_ts_zero.out) * (1 - check_1) === 0;

    is_pre_ts_zero.out * (shares - amount_in_0) === 0;
}

component main {public [root, nf_in_0, nf_in_1, lp_commit, reserve_pre_commit, reserve_post_commit]} = AddLiquidity(32);
