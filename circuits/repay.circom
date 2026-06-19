pragma circom 2.0.0;

// repay.circom — Lending repay proof with exact borrow-note enforcement (Milestone M7)
//
// Proves the repayer owns the exact note whose commitment was stored in LoanRec
// at open_loan time. Closes the M6 soundness gap: with the Transfer/Withdraw circuit,
// the repay amount was not circuit-enforced. This circuit binds repay to the exact
// borrow_cm stored on-chain (CONTRACTS.md §4, THREAT_MODEL §6 repay soundness).
//
// Public inputs (in order — this order IS the vkey binding; changing it changes the vkey):
//   1. root      — current Merkle root (recent-root window, root_is_known check on-chain)
//   2. repay_nf  — nullifier of the repay note (→ spent set via core.spend)
//   3. borrow_cm — commitment stored in LoanRec.borrow_cm (on-chain, not caller-supplied)
//
// The contract constructs [root, repay_nf, borrow_cm] for proof verification where
// borrow_cm comes from the stored LoanRec, NOT from the caller. This ensures the
// proof is bound to the exact borrow note from the original loan.
//
// NOTE: The two-set check (repay_nf not in SPENT or LOCKED) is enforced on-chain
// by veil_core.spend. See CIRCUITS.md §2.

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";

template Repay(tree_depth) {
    // ── Public inputs ──────────────────────────────────────────────────────────
    signal input root;       // Merkle root the borrow note is provable at
    signal input repay_nf;   // nullifier of the borrow note (spent to close the loan)
    signal input borrow_cm;  // commitment from LoanRec (on-chain, not caller-supplied)

    // ── Private inputs: the borrow note ───────────────────────────────────────
    signal input amount;
    signal input asset_id;
    signal input blinding;
    signal input owner_sk;
    signal input leaf_index;
    signal input path[tree_depth];
    signal input idx[tree_depth];

    // ── Range check: borrow amount in [0, 2^64) ───────────────────────────────
    component rc = RangeCheck64();
    rc.x <== amount;

    // ── Owner public key ───────────────────────────────────────────────────────
    component pk_hasher = Poseidon(1);
    pk_hasher.inputs[0] <== owner_sk;
    signal owner_pk;
    owner_pk <== pk_hasher.out;

    // ── Borrow note commitment must match the stored LoanRec.borrow_cm ─────────
    component cm_hasher = CommitmentHasher();
    cm_hasher.amount   <== amount;
    cm_hasher.asset_id <== asset_id;
    cm_hasher.blinding <== blinding;
    cm_hasher.owner_pk <== owner_pk;
    borrow_cm === cm_hasher.cm;

    // ── Merkle membership: borrow note is in the tree at root ─────────────────
    component mt = MerkleTreeChecker(tree_depth);
    mt.leaf <== cm_hasher.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt.pathElements[i] <== path[i];
        mt.pathIndices[i]  <== idx[i];
    }
    mt.root === root;

    // ── Nullifier: binds repay_nf to ownership + position ─────────────────────
    component nf_hasher = NullifierHasher();
    nf_hasher.owner_sk   <== owner_sk;
    nf_hasher.leaf_index <== leaf_index;
    nf_hasher.cm         <== cm_hasher.cm;
    repay_nf === nf_hasher.nf;
}

// tree_depth = 32 as per CIRCUITS.md §0
component main {public [root, repay_nf, borrow_cm]} = Repay(32);
