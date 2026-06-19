pragma circom 2.0.0;

// withdraw.circom — 2-in / 1-change-out shielded withdraw
//
// Spends up to 2 shielded input notes and pays `public_amount` to a
// public recipient address, with an optional change note back to self.
//
// Public inputs (in order — this order is the contract's public_inputs vector
// and the vkey binding; changing it changes the vkey):
//   1. root             — Merkle root of the commitment tree
//   2. nf_in_0          — nullifier of input note 0 (0 if dummy)
//   3. nf_in_1          — nullifier of input note 1 (0 if dummy)
//   4. cm_change        — change commitment back to self (0 if no change)
//   5. public_amount    — amount leaving the pool to the public recipient (> 0)
//   6. asset_id         — field element identifying the asset being withdrawn
//   7. recipient_hash   — Poseidon(recipient_address_as_field); binds payout
//
// NOTE: the two-set check (not in SPENT, not in LOCKED) is enforced on-chain
// by veil_core, NOT in circuit. Sets are large and mutable; the contract is
// the authority. The circuit produces a valid, owner-bound nf. See CIRCUITS.md §2.
//
// NOTE: Poseidon(recipient) == recipient_hash is checked on-chain in
// veil_core.withdraw — the actual recipient address is not a circuit input.

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Withdraw(tree_depth) {
    // --- Public inputs ---
    signal input root;
    signal input nf_in_0;
    signal input nf_in_1;
    signal input cm_change;
    signal input public_amount;
    signal input asset_id;
    signal input recipient_hash;

    // --- Private inputs: Input 0 ---
    signal input amount_in_0;
    signal input asset_in_0;
    signal input blinding_in_0;
    signal input owner_sk_0;
    signal input leaf_index_0;
    signal input path_0[tree_depth];
    signal input idx_0[tree_depth];

    // --- Private inputs: Input 1 (may be dummy: amount_in_1 == 0) ---
    signal input amount_in_1;
    signal input asset_in_1;
    signal input blinding_in_1;
    signal input owner_sk_1;
    signal input leaf_index_1;
    signal input path_1[tree_depth];
    signal input idx_1[tree_depth];

    // --- Private inputs: Change output (may be dummy: amount_change == 0) ---
    signal input amount_change;
    signal input asset_change;
    signal input blinding_change;
    signal input owner_pk_change;

    // --- Range Checks ---
    component rc_in_0  = RangeCheck64(); rc_in_0.x  <== amount_in_0;
    component rc_in_1  = RangeCheck64(); rc_in_1.x  <== amount_in_1;
    component rc_pa    = RangeCheck64(); rc_pa.x    <== public_amount;
    component rc_chg   = RangeCheck64(); rc_chg.x   <== amount_change;

    // --- Value Conservation ---
    // Σ amount_in == public_amount (exits to recipient) + amount_change (stays shielded)
    amount_in_0 + amount_in_1 === public_amount + amount_change;

    // --- Real/dummy flags ---
    component isz_in_0 = IsZero(); isz_in_0.in <== amount_in_0;
    signal isReal_in_0 <== 1 - isz_in_0.out;

    component isz_in_1 = IsZero(); isz_in_1.in <== amount_in_1;
    signal isReal_in_1 <== 1 - isz_in_1.out;

    component isz_chg  = IsZero(); isz_chg.in  <== amount_change;
    signal isReal_change <== 1 - isz_chg.out;

    // --- Asset Consistency ---
    // Every real note (inputs + change) must match the public asset_id.
    (asset_in_0 - asset_id) * isReal_in_0   === 0;
    (asset_in_1 - asset_id) * isReal_in_1   === 0;
    (asset_change - asset_id) * isReal_change === 0;

    // --- Input 0: commitment, Merkle membership, nullifier ---
    component cm_in_0 = CommitmentHasher();
    cm_in_0.amount   <== amount_in_0;
    cm_in_0.asset_id <== asset_in_0;
    cm_in_0.blinding <== blinding_in_0;
    component pk_in_0 = Poseidon(1);
    pk_in_0.inputs[0] <== owner_sk_0;
    cm_in_0.owner_pk <== pk_in_0.out;

    component mt_0 = MerkleTreeChecker(tree_depth);
    mt_0.leaf <== cm_in_0.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt_0.pathElements[i] <== path_0[i];
        mt_0.pathIndices[i]  <== idx_0[i];
    }
    (mt_0.root - root) * isReal_in_0 === 0;

    component nf_0 = NullifierHasher();
    nf_0.owner_sk   <== owner_sk_0;
    nf_0.leaf_index <== leaf_index_0;
    nf_0.cm         <== cm_in_0.cm;
    nf_in_0 === isReal_in_0 * nf_0.nf;

    // --- Input 1: commitment, Merkle membership, nullifier ---
    component cm_in_1 = CommitmentHasher();
    cm_in_1.amount   <== amount_in_1;
    cm_in_1.asset_id <== asset_in_1;
    cm_in_1.blinding <== blinding_in_1;
    component pk_in_1 = Poseidon(1);
    pk_in_1.inputs[0] <== owner_sk_1;
    cm_in_1.owner_pk <== pk_in_1.out;

    component mt_1 = MerkleTreeChecker(tree_depth);
    mt_1.leaf <== cm_in_1.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt_1.pathElements[i] <== path_1[i];
        mt_1.pathIndices[i]  <== idx_1[i];
    }
    (mt_1.root - root) * isReal_in_1 === 0;

    component nf_1 = NullifierHasher();
    nf_1.owner_sk   <== owner_sk_1;
    nf_1.leaf_index <== leaf_index_1;
    nf_1.cm         <== cm_in_1.cm;
    nf_in_1 === isReal_in_1 * nf_1.nf;

    // --- Change output commitment ---
    component cm_hasher_chg = CommitmentHasher();
    cm_hasher_chg.amount   <== amount_change;
    cm_hasher_chg.asset_id <== asset_change;
    cm_hasher_chg.blinding <== blinding_change;
    cm_hasher_chg.owner_pk <== owner_pk_change;
    cm_change === isReal_change * cm_hasher_chg.cm;
}

// tree_depth = 32 as per CIRCUITS.md Shared Definitions
component main {public [root, nf_in_0, nf_in_1, cm_change, public_amount, asset_id, recipient_hash]} = Withdraw(32);
