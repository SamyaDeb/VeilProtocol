# Audit Findings

This document tracks audit findings across all security reviews.

| ID | Circuit/Contract | Severity | Description | Status | Fix commit |
|---|---|---|---|---|---|
| ZK-01 | All Circuits | Critical | Under-constrained signals (ensure every output/intermediate fully constrained) | pending audit | |
| ZK-02 | All Circuits | High | Range checks present on all amounts (0 ≤ x < 2^64) | pending audit | |
| ZK-03 | transfer, swap, batch_settle | Critical | Value conservation (Σin = Σout + public_amount) | pending audit | |
| ZK-04 | deposit, transfer, withdraw | Critical | Nullifier binding (nf deterministically uniquely derived) | pending audit | |
| ZK-05 | All Circuits | High | Public-input ordering matches contract's `public_inputs` exactly | pending audit | |
| ZK-06 | All Circuits / `veil_core` | Critical | Poseidon params identical in-circuit and on-chain | pending audit | |
| ZK-07 | `tools/vk-convert` | High | vkey conversion reproducible, hash-pinned, validated | pending audit | |
| ZK-08 | `veil_core::verifier` | Critical | BN254 pairing convention matches CAP-0074 exactly | pending audit | |
| ZK-09 | `kyc_credential`, `deposit` | Critical | Non-membership soundness (ASP blocked set) | pending audit | |
| ZK-10 | `settle_or_refund` | Critical | Refund/settle-or-refund cannot both refund and settle the same order | pending audit | |
| ZK-11 | `lend.circom` | Critical | Oracle public input bound to on-chain freshly-read price | pending audit | |
