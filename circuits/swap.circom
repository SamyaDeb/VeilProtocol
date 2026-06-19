pragma circom 2.0.0;

// swap.circom — 1-in shielded swap order, M3 AMM spike
//
// Spends one shielded input note and commits to a flow-encrypted swap intent
// for the batch-auction committee. Output commitments are produced by the
// committee at settle_batch time.
//
// Public inputs (in order — this order is the contract's public_inputs vector
// and the vkey binding; changing it changes the vkey):
//   1. root             — Merkle root of the commitment tree
//   2. nf_in            — nullifier of the input note
//   3. enc_order_hash   — Poseidon(amount_in, asset_out, min_out, out_blinding,
//                                  out_owner_pk, committee_pk, r_enc)
//   4. committee_pk     — committee BN254 field scalar (binds to specific committee)
//
// NOTE: Two-set check (not in SPENT, not in LOCKED) is enforced on-chain by
// veil_core.spend, NOT in circuit. The circuit's job is to produce a valid,
// owner-bound nf_in. See CIRCUITS.md §2.
//
// NOTE: Flow encryption (ElGamal-on-BN254 G1) is performed off-chain.
// enc_order_hash commits to the intent + randomness via Poseidon.
// M3 committee mock uses plaintext intent; real ElGamal is M4.
// // VERIFY: CAP-0074 BN254 G1 scalar-mul host function before implementing
// on-chain flow-encryption verification.

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";

template Swap(tree_depth) {
    // --- Public inputs ---
    signal input root;
    signal input nf_in;
    signal input enc_order_hash;
    signal input committee_pk;

    // --- Private inputs: input note ---
    signal input amount_in;
    signal input asset_in;
    signal input blinding_in;
    signal input owner_sk;
    signal input leaf_index;
    signal input path[tree_depth];
    signal input idx[tree_depth];

    // --- Private inputs: swap intent (encrypted off-chain to committee_pk) ---
    signal input asset_out;
    signal input min_out;
    signal input out_blinding;
    signal input out_owner_pk;
    signal input r_enc;

    // --- Range checks ---
    component rc_in  = RangeCheck64(); rc_in.x  <== amount_in;
    component rc_min = RangeCheck64(); rc_min.x <== min_out;

    // --- Owner public key ---
    component pk_hasher = Poseidon(1);
    pk_hasher.inputs[0] <== owner_sk;

    // --- Input commitment ---
    component cm_in = CommitmentHasher();
    cm_in.amount   <== amount_in;
    cm_in.asset_id <== asset_in;
    cm_in.blinding <== blinding_in;
    cm_in.owner_pk <== pk_hasher.out;

    // --- Merkle membership ---
    component mt = MerkleTreeChecker(tree_depth);
    mt.leaf <== cm_in.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt.pathElements[i] <== path[i];
        mt.pathIndices[i]  <== idx[i];
    }
    mt.root === root;

    // --- Nullifier binding (owner-bound, deterministic) ---
    component nf = NullifierHasher();
    nf.owner_sk   <== owner_sk;
    nf.leaf_index <== leaf_index;
    nf.cm         <== cm_in.cm;
    nf_in === nf.nf;

    // --- Encrypted order hash ---
    // Commits the prover to their intent + randomness so the committee cannot
    // substitute a different order after seeing the on-chain submission.
    // enc_order_hash = Poseidon(amount_in, asset_out, min_out, out_blinding,
    //                           out_owner_pk, committee_pk, r_enc)
    component eoh = Poseidon(7);
    eoh.inputs[0] <== amount_in;
    eoh.inputs[1] <== asset_out;
    eoh.inputs[2] <== min_out;
    eoh.inputs[3] <== out_blinding;
    eoh.inputs[4] <== out_owner_pk;
    eoh.inputs[5] <== committee_pk;
    eoh.inputs[6] <== r_enc;
    enc_order_hash === eoh.out;
}

// tree_depth = 32 as per CIRCUITS.md §0
component main {public [root, nf_in, enc_order_hash, committee_pk]} = Swap(32);
