pragma circom 2.0.0;

// kyc_credential.circom — KYC credential proof for ASP-gated deposit.
//
// Proves holder has a valid credential in the approved ASP set and is NOT
// in the blocked set, without revealing which credential.
//
// Public inputs (in order — this order IS the vkey binding):
//   1. asp_approved_root  — current approved-set Merkle root
//   2. asp_blocked_root   — current blocked-set Merkle root
//   3. nullifier_kyc      — prevents one credential from gating unlimited Sybil deposits
//   4. issuer_pk          — public key of the issuing authority

include "./lib/merkle_tree_checker.circom";
include "./lib/non_membership.circom";
include "./lib/poseidon.circom";

// ASP tree depth (can differ from note tree depth; 20 is sufficient for typical sets)
template KycCredential(asp_depth) {
    // --- private inputs ---
    signal input cred_secret;                        // credential secret known only to holder
    signal input issuer_pk;                          // issuer public key (also public)

    // approved Merkle path for credential_leaf
    signal input approved_path[asp_depth];
    signal input approved_idx[asp_depth];

    // blocked non-membership: adjacent leaves bounding credential_leaf
    signal input blocked_lower_leaf;
    signal input blocked_upper_leaf;
    signal input blocked_lower_path[asp_depth];
    signal input blocked_lower_idx[asp_depth];
    signal input blocked_upper_path[asp_depth];
    signal input blocked_upper_idx[asp_depth];

    // --- public inputs (order matches circuit header above) ---
    signal input asp_approved_root;
    signal input asp_blocked_root;
    signal input nullifier_kyc;
    // issuer_pk is both private input and public input; declare the public signal
    signal input issuer_pk_pub;

    // --- constraints ---

    // 1. Derive credential leaf: credential_leaf = Poseidon([cred_secret, issuer_pk])
    //    Simplified attestation check for M0: the credential IS the hash of secret+issuer_pk.
    component cred_hasher = Poseidon(2);
    cred_hasher.inputs[0] <== cred_secret;
    cred_hasher.inputs[1] <== issuer_pk;
    signal credential_leaf;
    credential_leaf <== cred_hasher.out;

    // 2. issuer_pk matches the public input
    issuer_pk === issuer_pk_pub;

    // 3. credential_leaf is in approved tree
    component approved_check = MerkleTreeChecker(asp_depth);
    approved_check.leaf <== credential_leaf;
    for (var i = 0; i < asp_depth; i++) {
        approved_check.pathElements[i] <== approved_path[i];
        approved_check.pathIndices[i]  <== approved_idx[i];
    }
    approved_check.root === asp_approved_root;

    // 4. credential_leaf is NOT in blocked tree
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

    // 5. nullifier_kyc = Poseidon([cred_secret, domain_kyc])
    //    domain_kyc = 1 (domain separation constant)
    component nf_hasher = Poseidon(2);
    nf_hasher.inputs[0] <== cred_secret;
    nf_hasher.inputs[1] <== 1;   // domain constant for KYC nullifier
    nf_hasher.out === nullifier_kyc;
}

component main {public [asp_approved_root, asp_blocked_root, nullifier_kyc, issuer_pk_pub]} =
    KycCredential(20);
