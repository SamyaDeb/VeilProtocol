# REFERENCES

Every external source the protocol depends on, with a one-line note on what to
pull from each. **Rule:** if an API/claim below is load-bearing for code, verify
it against the linked source before writing — do not work from memory.

## Primary reference — Nethermind Stellar Private Payments (SPP)
- https://github.com/NethermindEth/stellar-private-payments — our structural
  template. Pull: directory layout, base note/merkle/nullifier Circom templates,
  `inputs = outputs + public_amount` conservation pattern, browser WASM proving
  flow, ceremony-cli, ASP membership/non-membership tree design. Note it ships
  ONE transact circuit (2-in/2-out), is unaudited PoC — we extend, not trust.

## Stellar / Soroban — ZK primitives (Protocol 25 "X-Ray")
- https://stellar.org/blog/developers/announcing-stellar-x-ray-protocol-25 —
  X-Ray launch; confirms native BN254 + Poseidon/Poseidon2 host functions live.
- https://developers.stellar.org/docs/build/apps/zk — official ZK-on-Stellar
  build guide. Pull: how Soroban contracts receive + verify Groth16 proofs;
  exact host-fn names/signatures (VERIFY here before coding the verifier wrapper).
- https://github.com/stellar/stellar-protocol/blob/master/core/cap-0074.md —
  BN254 elliptic-curve host functions (pairing, G1/G2 ops). Source of truth for
  the verifier's pairing call.
- https://github.com/stellar/stellar-protocol/blob/master/core/cap-0075.md —
  Poseidon/Poseidon2 hash host functions. Source of truth for hashing domain,
  arity, and field params — MUST match circuit Poseidon params exactly.

## Soroban — storage, archival, contracts
- https://developers.stellar.org/docs/build/guides/dapps/state-archival —
  TTL model. Pull: `extend_ttl` / `get_ttl`, persistent vs temporary vs instance,
  rent top-up, archive/restore. Merkle root + nullifier sets = persistent.
- https://developers.stellar.org/docs/build/guides/storage/choosing-the-right-storage
  — storage-tier selection rationale for each Veil data structure.
- https://developers.stellar.org/docs/learn/fundamentals/contract-development/storage/state-archival
  — archival semantics detail.
- https://developers.stellar.org/docs/build/guides/archival/test-ttl-extension —
  testing TTL logic (used in CONTRACTS/TEST_PLAN).
- Soroban examples — cross_contract: cross-contract call + auth pattern for
  module→core calls. // VERIFY current path under stellar/soroban-examples
- Soroban examples — privacy-pools / ZK example referenced from the ZK build
  guide above; pull verifier-wrapper shape.

## Oracles
- https://github.com/reflector-network/reflector-contract — Reflector oracle
  contract. Pull: SEP-40 `lastprice(Asset) -> Option<PriceData{price:i128,
  timestamp:u64}>`, price scaled by `10^decimals`, `Asset` enum shape. Primary
  oracle for lending LTV.
- https://code4rena.com/audits/2025-10-reflector-v3 — Reflector V3 audit; pull
  known oracle failure modes for the THREAT_MODEL oracle-correlation section.
- https://developers.stellar.org/docs/data/oracles/oracle-providers — Reflector
  + RedStone availability and feed addresses on Stellar.
- https://crates.io/crates/sep-40-oracle — SEP-40 Rust client trait to import
  rather than hand-roll the oracle client.

## ZK / privacy-pool theory
- Privacy Pools paper (Buterin, Illum, Nadler, Schär, Soleimani, 2023),
  "Blockchain Privacy and Regulatory Compliance: Towards a Practical Equilibrium"
  — the association-set / proof-of-innocence model behind Module 3 ASP.
- Tornado Cash Nova — variable-amount shielded UTXO pool; reference for the
  `sum_in = sum_out` value-conservation + range-proof note model.
- Penumbra — batch-auction DEX with flow encryption + threshold decryption;
  PRIMARY design reference for the fully-shielded AMM (encrypted reserves).
- Renegade — MPC/collaborative-SNARK dark pool; ALTERNATIVE design for the
  shielded AMM matching engine (documented as a fallback in ARCHITECTURE).

## Tooling
- https://docs.circom.io — Circom language + compilation (`--r1cs --wasm`).
- snarkjs — Groth16 setup/prove/verify, Phase-2 contributions, vkey export.
- https://github.com/iden3 (circomlib, snarkjs, rapidsnark) — Poseidon/Merkle
  gadgets; ensure Poseidon params match CAP-0075, NOT circomlib defaults blindly.

## SCF / grant
- Stellar Community Fund (SCF) program + v7.0 tranche structure (10/20/30/40%).
- SCF Soroban Audit Bank — audit funding + critical/high/medium remediation
  expectations (drives SECURITY.md).
- https://dorahacks.io/hackathon/stellar-hacks-zk/detail — Stellar ZK hackathon;
  ecosystem signal + potential ASP/auditor partners.

> Convention: when any of the above is wrong or moved, fix the link here and add
> a one-line dated note — this file is the single index of external truth.
