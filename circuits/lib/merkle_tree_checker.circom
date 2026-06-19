pragma circom 2.0.0;

// MerkleTreeChecker: verify a Merkle membership proof.
// Two-to-one compression: Poseidon([left, right]) at each level (t=3 → 2-input).
//
// Template: MerkleTreeChecker(depth)
// Inputs:  leaf              — the leaf value
//          pathElements[depth] — sibling hashes along the path
//          pathIndices[depth]  — 0 = current node is left child, 1 = right child
// Output:  root              — the computed root (constrain against expected root)

include "./poseidon.circom";

template MerkleTreeChecker(depth) {
    signal input leaf;
    signal input pathElements[depth];
    signal input pathIndices[depth];

    signal output root;

    component hashers[depth];
    component selectors[depth];
    signal levelHashes[depth + 1];
    levelHashes[0] <== leaf;

    for (var i = 0; i < depth; i++) {
        // pathIndices[i] must be 0 or 1
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        // selector: if pathIndices[i]==0 → left=current, right=sibling
        //           if pathIndices[i]==1 → left=sibling, right=current
        hashers[i] = Poseidon(2);
        selectors[i] = Selector();
        selectors[i].in[0] <== levelHashes[i];
        selectors[i].in[1] <== pathElements[i];
        selectors[i].sel    <== pathIndices[i];

        hashers[i].inputs[0] <== selectors[i].out[0];
        hashers[i].inputs[1] <== selectors[i].out[1];
        levelHashes[i + 1]   <== hashers[i].out;
    }

    root <== levelHashes[depth];
}

// Selector: swap or pass through based on sel
// sel=0: out[0]=in[0], out[1]=in[1]
// sel=1: out[0]=in[1], out[1]=in[0]
template Selector() {
    signal input in[2];
    signal input sel;
    signal output out[2];

    out[0] <== (in[1] - in[0]) * sel + in[0];
    out[1] <== (in[0] - in[1]) * sel + in[1];
}
