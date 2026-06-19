pragma circom 2.0.0;

// deposit.circom — ZK proof for ASP-gated shielded deposit (CIRCUITS.md §1).
//
// Proves that:
//  - the output commitment cm is correctly formed from (amount, asset_id, blinding, owner_pk)
//  - amount is in [0, 2^64)
//  - amount == public_amount (deposit fully funds the note)
//  - the depositor's KYC credential is in the approved ASP set
//  - the depositor's KYC credential is NOT in the blocked ASP set
//
// Public inputs (in order — this order IS the vkey binding):
//   1. cm                — output commitment
//   2. public_amount     — deposited amount (visible on-chain)
//   3. asp_approved_root — current approved-set root
//   4. asp_blocked_root  — current blocked-set root
//
// NOTE: two-set nullifier check (RULE 3) is NOT needed here — deposit creates,
// it does not spend. The on-chain contract enforces RULE 1 (ASP gate) by
// additionally calling asp.check_entry; this circuit provides the ZK proof of
// credential membership.

include "./lib/commitment_hasher.circom";
include "./lib/range_check.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/non_membership.circom";

template Deposit(asp_depth) {
    // --- private inputs ---
    signal input amount;
    signal input asset_id;
    signal input blinding;
    signal input owner_pk;

    // KYC credential secret (the credential leaf = Poseidon([cred_secret, issuer_pk]))
    signal input cred_secret;
    signal input issuer_pk;

    // approved Merkle path for credential_leaf
    signal input asp_path[asp_depth];
    signal input asp_idx[asp_depth];

    // blocked non-membership adjacent leaves
    signal input blocked_lower_leaf;
    signal input blocked_upper_leaf;
    signal input blocked_lower_path[asp_depth];
    signal input blocked_lower_idx[asp_depth];
    signal input blocked_upper_path[asp_depth];
    signal input blocked_upper_idx[asp_depth];

    // --- public inputs (order matches circuit header above) ---
    signal input cm;
    signal input public_amount;
    signal input asp_approved_root;
    signal input asp_blocked_root;

    // --- constraint 1: commitment is correctly formed ---
    component cm_hasher = CommitmentHasher();
    cm_hasher.amount   <== amount;
    cm_hasher.asset_id <== asset_id;
    cm_hasher.blinding <== blinding;
    cm_hasher.owner_pk <== owner_pk;
    cm_hasher.cm       === cm;

    // --- constraint 2: amount range check ---
    component range = RangeCheck64();
    range.x <== amount;

    // --- constraint 3: public_amount == amount ---
    amount === public_amount;

    // --- constraint 4+5: derive credential leaf and check membership/non-membership ---
    component cred_hasher = Poseidon(2);
    cred_hasher.inputs[0] <== cred_secret;
    cred_hasher.inputs[1] <== issuer_pk;
    signal credential_leaf;
    credential_leaf <== cred_hasher.out;

    component approved_check = MerkleTreeChecker(asp_depth);
    approved_check.leaf <== credential_leaf;
    for (var i = 0; i < asp_depth; i++) {
        approved_check.pathElements[i] <== asp_path[i];
        approved_check.pathIndices[i]  <== asp_idx[i];
    }
    approved_check.root === asp_approved_root;

    component blocked_check = NonMembership(asp_depth);
    blocked_check.value      <== credential_leaf;
    blocked_check.lower_leaf <== blocked_lower_leaf;
    blocked_check.upper_leaf <== blocked_upper_leaf;
    for (var i = 0; i < asp_depth; i++) {
        blocked_check.lower_path[i] <== blocked_lower_path[i];
        blocked_check.lower_idx[i]  <== blocked_lower_idx[i];
        blocked_check.upper_path[i] <== blocked_upper_path[i];
        blocked_check.upper_idx[i]  <== blocked_upper_idx[i];
    }
    blocked_check.root === asp_blocked_root;
}

// asp_depth = 20 (sufficient for production ASP sets)
component main {public [cm, public_amount, asp_approved_root, asp_blocked_root]} =
    Deposit(20);
