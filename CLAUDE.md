# Veil Protocol — Agent Working Guide

Veil Protocol is privacy-preserving DeFi on Stellar/Soroban: one shielded-state
core exposing a fully-shielded AMM, private RWA lending, and ZK compliance.
This file is the contract you (the coding agent) work under. Read the linked
docs lazily — only pull the one relevant to the slice you are building.

## What this is
- **Hub + modules** on Soroban. `veil_core` owns the shared Merkle tree, the
  spent + locked nullifier sets, the Groth16 verifier wrapper, and the
  auditor-encrypted note store. `amm_pool`, `lending`, and `asp` are separate
  contracts that cross-call into core.
- **Proving:** Circom + Groth16 over BN254, verified on-chain via Protocol 25
  native host functions (CAP-0074 BN254, CAP-0075 Poseidon). Browser WASM proving.
- **Notes:** variable-value UTXOs `(amount, asset, blinding, owner_pk)`; circuits
  enforce `sum_in = sum_out + public_amount` plus range proofs.
- **Reference:** Nethermind Stellar Private Payments (SPP). We mirror its layout
  and reuse its base note/merkle/nullifier circuits and ceremony-cli. We extend
  it with: a fully-shielded batch-auction AMM, lending, multi-set nullifiers,
  and view keys.

## The four integration rules — HARD CONSTRAINTS (never violate)
1. **ASP-gated entry.** Every deposit into `veil_core` MUST first pass an
   `asp` membership/non-membership check via cross-contract call. No deposit path
   may bypass it.
2. **Universal notes.** A note minted by any module is spendable by any other
   module with NO conversion step. One commitment format, one tree.
3. **Two nullifier sets.** Collateral locking writes the `locked` set; spending
   writes the `spent` set. The swap/transfer circuits MUST prove the input note
   is in NEITHER set. A note may never be in both.
4. **View keys are universal.** Every commitment insertion MUST also store a note
   ciphertext encrypted to the auditor pubkey. No module may insert a commitment
   without the paired auditor ciphertext.

## Conventions
- **Use the simplest approach that satisfies the spec.** No speculative
  abstraction, no generics until a second caller exists.
- **Never invent Stellar/Soroban APIs.** If you are not certain a host function,
  SDK symbol, or storage semantic exists, STOP and verify against
  https://developers.stellar.org (or the SPP / reflector-contract source). Flag
  uncertainty in a `// VERIFY:` comment rather than guessing.
- **Test after every change.** A change is not done until its test runs green.
  Circuit change → witness + constraint test. Contract change → `cargo test`.
  Integration change → the milestone verification command in TEST_PLAN.md.
- **Match surrounding style.** Rust: `snake_case`, explicit errors via a
  `#[contracterror]` enum, no `unwrap()` in contract code. Circom: one template
  per file, signals documented, public signals listed in a header comment.
- **Money is real.** Compliance-first, audit-bound. No `// TODO: security`
  shortcuts on consensus-critical or proof-verifying paths.
- **Determinism.** Field-element encodings, hash domain separation, and tree
  parameters are defined ONCE in a shared spec and never duplicated divergently.

## Repo layout (mirrors SPP)
```
circuits/        Circom: note/merkle/nullifier base, swap, lend, kyc_credential, batch_settle
contracts/       Soroban Rust: veil_core, amm_pool, lending, asp, viewkey(lib)
app/             TS/React: WASM prover, Freighter, note store, swap/lend/auditor UIs
poseidon2/       Poseidon2 params + reference impl (shared circuit/contract)
circuit-keys/    pinned proving/verification keys + sha256 manifest
tools/ceremony-cli/  Phase-2 trusted-setup tooling
e2e-tests/       browser-proof -> testnet-verify suites
deployments/     network configs, contract IDs, deploy scripts
indexer/         Node.js Soroban-RPC event indexer (persists Merkle tree)
docs/            see imports below
```

## Docs (load only what the current slice needs)
- @docs/PRD.md — what we're building and for whom; scope IN/OUT; user stories.
- @docs/ARCHITECTURE.md — contracts, call graph, shared state, ZK primitive map.
- @docs/CIRCUITS.md — every circuit's inputs/constraints/flow + circom→soroban.
- @docs/CONTRACTS.md — storage layout, functions, errors, TTL strategy, auth.
- @docs/THREAT_MODEL.md — privacy/double-spend/setup/ASP risks + mitigations.
- @docs/SECURITY.md — SCF Audit Bank readiness checklist + ZK audit concerns.
- @docs/ROADMAP.md — vertical slices mapped to SCF v7.0 tranches.
- @docs/TEST_PLAN.md — unit/integration/e2e + per-milestone verify command.
- @docs/SCF_PROPOSAL.md — grant submission text.
- @docs/REFERENCES.md — every external source and what to pull from it.

## Build/test quick reference (fill in as tooling lands — do not assume)
- Contracts: `cargo test` per crate; `stellar contract build` to wasm. // VERIFY CLI name
- Circuits: `circom <c>.circom --r1cs --wasm`; witness + `snarkjs groth16` checks.
- E2E: see TEST_PLAN.md per-milestone command — that command is the source of truth.
