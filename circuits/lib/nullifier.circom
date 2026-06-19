pragma circom 2.0.0;

// NullifierHasher: nf = Poseidon([owner_sk, leaf_index, cm])
// Deterministic per note; unlinkable to cm without owner_sk.
//
// Template: NullifierHasher()
// Inputs:  owner_sk   — note owner secret key (private)
//          leaf_index — index of the note in the Merkle tree
//          cm         — note commitment
// Output:  nf         — nullifier (public, reveals which note is spent)
//
// NOTE: the two-set check (not in SPENT, not in LOCKED) is enforced on-chain
// by veil_core, NOT in circuit. The circuit's job is only to produce a valid
// owner-bound nf. See CIRCUITS.md §2 and THREAT_MODEL §2.

include "./poseidon.circom";

template NullifierHasher() {
    signal input owner_sk;
    signal input leaf_index;
    signal input cm;

    signal output nf;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== owner_sk;
    hasher.inputs[1] <== leaf_index;
    hasher.inputs[2] <== cm;

    nf <== hasher.out;
}
