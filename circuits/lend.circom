pragma circom 2.0.0;

// lend.circom — Private RWA lending: LTV range proof (Milestone M6)
//
// Proves a borrow is within LTV against a public oracle price, locking the
// collateral note. Both collateral amount and borrow amount remain entirely
// hidden (private inputs). See CIRCUITS.md §4 and THREAT_MODEL §1.3, §5.
//
// Public inputs (in order — this order is the contract's public_inputs vector
// and the vkey binding; changing it changes the vkey):
//   1. root            — Merkle root of the commitment tree
//   2. collat_nf       — nullifier of the collateral note (→ locked set, RULE 3)
//   3. borrow_cm       — borrow note commitment (output, RULE 4)
//   4. oracle_price    — collateral asset price from Reflector (raw, same units as borrow_price)
//   5. oracle_decimals — collateral price scale / decimals (public, oracle-supplied)
//   6. ltv_max_bps     — maximum LTV in basis points (e.g. 7500 = 75%), public
//   7. borrow_price    — borrow asset price from Reflector (same oracle scale as oracle_price)
//
// NOTE: The two-set check (not in SPENT, not in LOCKED) is enforced on-chain
// by veil_core.lock, NOT in circuit. The circuit produces a valid owner-bound
// collat_nf; the contract is the authority on set membership. See CIRCUITS.md §2.
//
// NOTE: oracle_price and oracle_decimals are verified on-chain by the lending
// contract against the freshly-read Reflector price. See CONTRACTS.md §4.
// borrow_price is also verified on-chain via a second oracle read.
//
// LTV constraint (CIRCUITS.md §4, SECURITY.md §3 overflow-safe):
//   borrow_amount × borrow_price × 10_000 ≤ collat_amount × oracle_price × ltv_max_bps
//   Both amounts are 64-bit; oracle prices bounded; products < 2^142 < 2^160.

include "./lib/commitment_hasher.circom";
include "./lib/merkle_tree_checker.circom";
include "./lib/nullifier.circom";
include "./lib/range_check.circom";
include "./lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Lend(tree_depth) {
    // ── Public inputs ──────────────────────────────────────────────────────────
    signal input root;
    signal input collat_nf;
    signal input borrow_cm;
    signal input oracle_price;
    signal input oracle_decimals;
    signal input ltv_max_bps;
    signal input borrow_price;

    // ── Private inputs: collateral note ───────────────────────────────────────
    signal input collat_amount;
    signal input collat_asset;
    signal input collat_blinding;
    signal input owner_sk;
    signal input leaf_index;
    signal input path[tree_depth];
    signal input idx[tree_depth];

    // ── Private inputs: borrow note ───────────────────────────────────────────
    signal input borrow_amount;
    signal input borrow_asset;
    signal input borrow_blinding;

    // ── Range checks (prevents field-wraparound value creation, SECURITY §4) ──
    component rc_collat = RangeCheck64();
    rc_collat.x <== collat_amount;

    component rc_borrow = RangeCheck64();
    rc_borrow.x <== borrow_amount;

    // ── Owner public key (derived from shared owner_sk) ────────────────────────
    component pk_hasher = Poseidon(1);
    pk_hasher.inputs[0] <== owner_sk;
    signal owner_pk;
    owner_pk <== pk_hasher.out;

    // ── Collateral commitment ──────────────────────────────────────────────────
    component cm_collat = CommitmentHasher();
    cm_collat.amount   <== collat_amount;
    cm_collat.asset_id <== collat_asset;
    cm_collat.blinding <== collat_blinding;
    cm_collat.owner_pk <== owner_pk;

    // ── Merkle membership (collateral is in the tree at root) ─────────────────
    component mt = MerkleTreeChecker(tree_depth);
    mt.leaf <== cm_collat.cm;
    for (var i = 0; i < tree_depth; i++) {
        mt.pathElements[i] <== path[i];
        mt.pathIndices[i]  <== idx[i];
    }
    mt.root === root;

    // ── Collateral nullifier (binds to owner, deterministic, → lock RULE 3) ───
    component nf_hasher = NullifierHasher();
    nf_hasher.owner_sk   <== owner_sk;
    nf_hasher.leaf_index <== leaf_index;
    nf_hasher.cm         <== cm_collat.cm;
    collat_nf === nf_hasher.nf;

    // ── Borrow note commitment (RULE 4: stored with auditor_ct on-chain) ───────
    component cm_borrow = CommitmentHasher();
    cm_borrow.amount   <== borrow_amount;
    cm_borrow.asset_id <== borrow_asset;
    cm_borrow.blinding <== borrow_blinding;
    cm_borrow.owner_pk <== owner_pk;
    borrow_cm === cm_borrow.cm;

    // ── LTV range proof (CIRCUITS.md §4, overflow-safe, SECURITY §3) ──────────
    // Prove: borrow_amount × borrow_price × 10_000 ≤ collat_amount × oracle_price × ltv_max_bps
    //
    // Both amounts are 64-bit (range-checked above). Prices are oracle-bounded.
    // Worst case product: 2^64 × 2^64 × 2^14 = 2^142 < 2^160 → LessEqThan(160) is safe.
    //
    // Two-step multiplication uses intermediate signals to stay within R1CS degree-2.

    signal borrow_prod;
    borrow_prod <== borrow_amount * borrow_price;

    // 10000 is a compile-time constant — degree-1 linear constraint
    signal lhs;
    lhs <== borrow_prod * 10000;

    signal collat_prod;
    collat_prod <== collat_amount * oracle_price;

    // ltv_max_bps is a public signal — degree-2 constraint
    signal rhs;
    rhs <== collat_prod * ltv_max_bps;

    component ltv_check = LessEqThan(160);
    ltv_check.in[0] <== lhs;
    ltv_check.in[1] <== rhs;
    ltv_check.out === 1;
}

// tree_depth = 32 as per CIRCUITS.md §0
component main {public [root, collat_nf, borrow_cm, oracle_price, oracle_decimals, ltv_max_bps, borrow_price]} = Lend(32);
