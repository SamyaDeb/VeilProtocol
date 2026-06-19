pragma circom 2.0.0;

// batch_settle.circom — K=4 batch settlement proof for M4 AMM
//
// Proves a batch clearing is balance-preserving and well-formed.
// The committee threshold-decrypts all K orders, computes a clearing, then
// produces this proof.
//
// Public inputs (EXACT ORDER — binding to vkey):
//   1..K.     enc_order_hash[K]  — hashes committed on-chain per submit_order
//   K+1..2K.  cm_out[K]          — output commitments to insert into veil_core
//   2K+1.     committee_pk       — committee field scalar
//   2K+2.     batch_id           — prevents proof replay across batches
//   2K+3.     pre_reserve_cm     — Poseidon(pre_reserve_a, pre_reserve_b, pre_reserve_blinding)
//   2K+4.     post_reserve_cm    — Poseidon(post_reserve_a, post_reserve_b, post_reserve_blinding)

include "./lib/commitment_hasher.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template BatchSettle(K) {
    // --- Public inputs ---
    signal input enc_order_hash[K];
    signal input cm_out[K];
    signal input committee_pk;
    signal input batch_id;
    signal input pre_reserve_cm;
    signal input post_reserve_cm;

    // --- Private inputs per order ---
    signal input amount_in[K];
    signal input asset_out[K];
    signal input min_out[K];
    signal input out_blinding[K];
    signal input out_owner_pk[K];
    signal input r_enc[K];
    signal input amount_out[K];
    signal input is_excluded[K];

    // --- Private inputs (reserves and clearing) ---
    signal input pre_reserve_a;
    signal input pre_reserve_b;
    signal input pre_total_shares;
    signal input pre_reserve_blinding;
    signal input post_reserve_a;
    signal input post_reserve_b;
    signal input post_total_shares;
    signal input post_reserve_blinding;
    signal input clearing_price_num; // price of asset_a in terms of asset_b ratio
    signal input clearing_price_den;
    signal input fee_a;
    signal input fee_b;
    signal input asset_a;
    signal input asset_b;

    // Range checks
    component rc_pre_a = RangeCheck64(); rc_pre_a.x <== pre_reserve_a;
    component rc_pre_b = RangeCheck64(); rc_pre_b.x <== pre_reserve_b;
    component rc_post_a = RangeCheck64(); rc_post_a.x <== post_reserve_a;
    component rc_post_b = RangeCheck64(); rc_post_b.x <== post_reserve_b;
    component rc_fee_a = RangeCheck64(); rc_fee_a.x <== fee_a;
    component rc_fee_b = RangeCheck64(); rc_fee_b.x <== fee_b;
    component rc_price_num = RangeCheck64(); rc_price_num.x <== clearing_price_num;
    component rc_price_den = RangeCheck64(); rc_price_den.x <== clearing_price_den;

    // Ensure prices are non-zero
    component isz_num = IsZero(); isz_num.in <== clearing_price_num; isz_num.out === 0;
    component isz_den = IsZero(); isz_den.in <== clearing_price_den; isz_den.out === 0;

    // Constant-function invariant: post_reserve_a * post_reserve_b >= pre_reserve_a * pre_reserve_b
    component leq_k = LessEqThan(130);
    leq_k.in[0] <== pre_reserve_a * pre_reserve_b;
    leq_k.in[1] <== post_reserve_a * post_reserve_b;
    leq_k.out === 1;

    // Reserve commitments
    component pre_cm_hash = Poseidon(4);
    pre_cm_hash.inputs[0] <== pre_reserve_a;
    pre_cm_hash.inputs[1] <== pre_reserve_b;
    pre_cm_hash.inputs[2] <== pre_total_shares;
    pre_cm_hash.inputs[3] <== pre_reserve_blinding;
    pre_reserve_cm === pre_cm_hash.out;

    component post_cm_hash = Poseidon(4);
    post_cm_hash.inputs[0] <== post_reserve_a;
    post_cm_hash.inputs[1] <== post_reserve_b;
    post_cm_hash.inputs[2] <== post_total_shares;
    post_cm_hash.inputs[3] <== post_reserve_blinding;
    post_reserve_cm === post_cm_hash.out;
    
    post_total_shares === pre_total_shares;

    // --- Per-order constraints ---
    component eoh[K];
    component cm_hash[K];
    component rc_in[K];
    component rc_out[K];
    component rc_min[K];
    
    component eq_a[K];
    component eq_b[K];

    component leq_fill1[K];
    component lt_fill2[K];
    component leq_min[K];
    component lt_excl[K];

    signal is_buy_a[K];
    signal is_buy_b[K];
    signal price_in[K];
    signal price_out[K];
    signal filled[K];

    signal sell_a[K];
    signal sell_b[K];
    signal buy_a[K];
    signal buy_b[K];

    signal p_in_t1[K];
    signal p_in_t2[K];
    signal p_out_t1[K];
    signal p_out_t2[K];

    for (var j = 0; j < K; j++) {
        rc_in[j]  = RangeCheck64(); rc_in[j].x  <== amount_in[j];
        rc_out[j] = RangeCheck64(); rc_out[j].x <== amount_out[j];
        rc_min[j] = RangeCheck64(); rc_min[j].x <== min_out[j];

        // Ensure asset_out matches exactly one of the two pool assets
        eq_a[j] = IsEqual(); eq_a[j].in[0] <== asset_out[j]; eq_a[j].in[1] <== asset_a;
        eq_b[j] = IsEqual(); eq_b[j].in[0] <== asset_out[j]; eq_b[j].in[1] <== asset_b;
        eq_a[j].out + eq_b[j].out === 1;

        is_buy_a[j] <== eq_a[j].out;
        is_buy_b[j] <== eq_b[j].out;

        // Price mapping based on what is being bought
        p_in_t1[j] <== is_buy_b[j] * clearing_price_num;
        p_in_t2[j] <== is_buy_a[j] * clearing_price_den;
        price_in[j] <== p_in_t1[j] + p_in_t2[j];

        p_out_t1[j] <== is_buy_b[j] * clearing_price_den;
        p_out_t2[j] <== is_buy_a[j] * clearing_price_num;
        price_out[j] <== p_out_t1[j] + p_out_t2[j];

        is_excluded[j] * (1 - is_excluded[j]) === 0;
        filled[j] <== 1 - is_excluded[j];

        // If filled: amount_out * P_out <= amount_in * P_in < (amount_out + 1) * P_out
        leq_fill1[j] = LessEqThan(130);
        leq_fill1[j].in[0] <== amount_out[j] * price_out[j];
        leq_fill1[j].in[1] <== amount_in[j] * price_in[j];
        filled[j] * (1 - leq_fill1[j].out) === 0;

        lt_fill2[j] = LessThan(130);
        lt_fill2[j].in[0] <== amount_in[j] * price_in[j];
        lt_fill2[j].in[1] <== (amount_out[j] + 1) * price_out[j];
        filled[j] * (1 - lt_fill2[j].out) === 0;

        // If filled: min_out <= amount_out
        leq_min[j] = LessEqThan(64);
        leq_min[j].in[0] <== min_out[j];
        leq_min[j].in[1] <== amount_out[j];
        filled[j] * (1 - leq_min[j].out) === 0;

        // If excluded: amount_out == 0
        is_excluded[j] * amount_out[j] === 0;

        // If excluded: amount_in * P_in < min_out * P_out
        lt_excl[j] = LessThan(130);
        lt_excl[j].in[0] <== amount_in[j] * price_in[j];
        lt_excl[j].in[1] <== min_out[j] * price_out[j];
        is_excluded[j] * (1 - lt_excl[j].out) === 0;

        // Decryption correctness
        eoh[j] = Poseidon(7);
        eoh[j].inputs[0] <== amount_in[j];
        eoh[j].inputs[1] <== asset_out[j];
        eoh[j].inputs[2] <== min_out[j];
        eoh[j].inputs[3] <== out_blinding[j];
        eoh[j].inputs[4] <== out_owner_pk[j];
        eoh[j].inputs[5] <== committee_pk;
        eoh[j].inputs[6] <== r_enc[j];
        enc_order_hash[j] === eoh[j].out;

        // Output commitment
        cm_hash[j] = CommitmentHasher();
        cm_hash[j].amount   <== amount_out[j];
        cm_hash[j].asset_id <== asset_out[j];
        cm_hash[j].blinding <== out_blinding[j];
        cm_hash[j].owner_pk <== out_owner_pk[j];
        cm_out[j] === cm_hash[j].cm;

        // Conservation values
        sell_a[j] <== is_buy_b[j] * amount_in[j];
        sell_b[j] <== is_buy_a[j] * amount_in[j];
        buy_a[j]  <== is_buy_a[j] * amount_out[j];
        buy_b[j]  <== is_buy_b[j] * amount_out[j];
    }

    // Accumulate sums
    signal sum_sell_a[K + 1];
    signal sum_sell_b[K + 1];
    signal sum_buy_a[K + 1];
    signal sum_buy_b[K + 1];

    sum_sell_a[0] <== 0;
    sum_sell_b[0] <== 0;
    sum_buy_a[0]  <== 0;
    sum_buy_b[0]  <== 0;

    for (var j = 0; j < K; j++) {
        sum_sell_a[j+1] <== sum_sell_a[j] + sell_a[j];
        sum_sell_b[j+1] <== sum_sell_b[j] + sell_b[j];
        sum_buy_a[j+1]  <== sum_buy_a[j]  + buy_a[j];
        sum_buy_b[j+1]  <== sum_buy_b[j]  + buy_b[j];
    }

    // Value conservation
    sum_sell_a[K] + pre_reserve_a === sum_buy_a[K] + post_reserve_a + fee_a;
    sum_sell_b[K] + pre_reserve_b === sum_buy_b[K] + post_reserve_b + fee_b;
}

// K=4 fixed for M4.
component main {public [enc_order_hash, cm_out, committee_pk, batch_id, pre_reserve_cm, post_reserve_cm]} = BatchSettle(4);
