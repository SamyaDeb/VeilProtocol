pragma circom 2.0.0;

// settle_or_refund.circom — ZK refund proof for batch-auction AMM (Milestone M7)
//
// Proves the refunder owns the original input note that was spent at order
// submission, binding the refund to a specific batch without revealing identity.
// Replaces the M3 address-auth refund path (THREAT_MODEL §6 — soundness-critical).
//
// Public inputs (in order — this order IS the vkey binding; changing it changes the vkey):
//   1. batch_id       — identifies the batch being refunded (ties proof to on-chain state)
//   2. nf_in          — nullifier of the original input note (must match stored OrderRecord.nf_in)
//   3. cm_refund      — commitment of the re-minted output note (caller-chosen)
//   4. root           — Merkle root at which the original note is provable
//   5. batch_deadline — ledger sequence past which refund is allowed (bound to proof, checked on-chain)
//
// NOTE: batch_id and batch_deadline are public inputs committed to by the proof but
// not further constrained by circuit arithmetic. Their correctness is enforced
// on-chain by the contract constructing public_inputs from stored state (not caller
// input). This is safe: the Groth16 proof binds any valid proof to exactly these
// public signal values; the contract verifies they match stored batch state.
//
// NOTE: The two-set check (nf_in not in SPENT or LOCKED) is enforced on-chain
// by veil_core state. The circuit's job is only to produce a valid owner-bound
// nf_in. See CIRCUITS.md §2 and THREAT_MODEL §6 for this split.

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";

template SettleOrRefund(tree_depth) {
    // ── Public inputs ──────────────────────────────────────────────────────────
    signal input batch_id;        // ties refund to a specific batch (on-chain checked)
    signal input nf_in;           // nullifier of original input note (→ SPENT; re-proven here)
    signal input cm_refund;       // commitment of the re-minted note (caller chooses blinding/pk)
    signal input root;            // Merkle root the original note is provable at
    signal input batch_deadline;  // ledger sequence threshold (on-chain checked, not circuit-constrained)

    // ── Private inputs: original input note ───────────────────────────────────
    signal input amount;
    signal input asset_id;
    signal input blinding;
    signal input owner_sk;
    signal input leaf_index;
    signal input path[tree_depth];
    signal input idx[tree_depth];

    // ── Private inputs: refund output note ────────────────────────────────────
    signal input out_blinding;
    signal input out_owner_pk;   // may differ from original (refunder can re-key)

    // ── Range check: amount in [0, 2^64) ──────────────────────────────────────
    component rc = RangeCheck64();
    rc.x <== amount;

    // ── Owner public key from secret key ──────────────────────────────────────
    component pk_hasher = Poseidon(1);
    pk_hasher.inputs[0] <== owner_sk;
    signal owner_pk;
    owner_pk <== pk_hasher.out;

    // ── Original input commitment (same note that was spent at submit) ─────────
    component cm_in_hasher = CommitmentHasher();
    cm_in_hasher.amount   <== amount;
    cm_in_hasher.asset_id <== asset_id;
    cm_in_hasher.blinding <== blinding;
    cm_in_hasher.owner_pk <== owner_pk;

    // ── Merkle membership: original note is in the tree at root ───────────────
    component mt = MerkleTreeChecker(tree_depth);
    mt.leaf <== cm_in_hasher.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt.pathElements[i] <== path[i];
        mt.pathIndices[i]  <== idx[i];
    }
    mt.root === root;

    // ── Nullifier: proves ownership and matches stored OrderRecord.nf_in ───────
    component nf_hasher = NullifierHasher();
    nf_hasher.owner_sk   <== owner_sk;
    nf_hasher.leaf_index <== leaf_index;
    nf_hasher.cm         <== cm_in_hasher.cm;
    nf_in === nf_hasher.nf;

    // ── Refund output commitment (the re-minted note inserted into the tree) ───
    // Same amount and asset as original, new blinding and optional new owner_pk.
    component cm_refund_hasher = CommitmentHasher();
    cm_refund_hasher.amount   <== amount;
    cm_refund_hasher.asset_id <== asset_id;
    cm_refund_hasher.blinding <== out_blinding;
    cm_refund_hasher.owner_pk <== out_owner_pk;
    cm_refund === cm_refund_hasher.cm;
}

// tree_depth = 32 as per CIRCUITS.md §0
component main {public [batch_id, nf_in, cm_refund, root, batch_deadline]} = SettleOrRefund(32);
