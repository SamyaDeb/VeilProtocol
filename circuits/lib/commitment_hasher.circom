pragma circom 2.0.0;

// CommitmentHasher: cm = Poseidon([amount, asset_id, blinding, owner_pk])
// Uses t=5 (4-input) Poseidon.
//
// Template: CommitmentHasher()
// Inputs: amount, asset_id, blinding, owner_pk
// Output: cm

include "./poseidon.circom";

template CommitmentHasher() {
    signal input amount;
    signal input asset_id;
    signal input blinding;
    signal input owner_pk;

    signal output cm;

    component hasher = Poseidon(4);
    hasher.inputs[0] <== amount;
    hasher.inputs[1] <== asset_id;
    hasher.inputs[2] <== blinding;
    hasher.inputs[3] <== owner_pk;

    cm <== hasher.out;
}
