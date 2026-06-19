# ARCHITECTURE — Veil Protocol

> Naming: brand is **Veil Protocol**. The shared-state core contract is
> `veil_core` (SPP calls its equivalent the "pool"). Module contracts keep the
> brief's descriptive filenames: `amm_pool`, `lending`, `asp`, plus a `viewkey`
> library. We mirror SPP's directory layout (REFERENCES.md) and note below
> where we **reuse** vs **extend** it.

## 1. System overview

```
                         ┌───────────────────────────────────────────┐
                         │                BROWSER (app/)               │
                         │  Freighter ── WASM Groth16 prover (snarkjs) │
                         │  localStorage note store (UTXOs)            │
                         │  swap UI │ lend UI │ auditor UI │ LP UI      │
                         └───────────────┬─────────────────────────────┘
                                         │ signed tx + proof + public inputs
                                         ▼
   ┌───────────────────────────── STELLAR / SOROBAN ──────────────────────────────┐
   │                                                                               │
   │   ┌──────────┐  cross-contract   ┌───────────────────────────────────────┐   │
   │   │   asp    │◄──────────────────│              veil_core                 │   │
   │   │ approved │   verify entry    │  • Merkle tree (commitments)           │   │
   │   │ blocked  │                   │  • nullifier sets: spent + locked      │   │
   │   └──────────┘                   │  • Groth16 verifier wrapper (BN254)    │   │
   │                                  │  • auditor ciphertext store (viewkey)  │   │
   │   ┌──────────┐  insert/nullify   │  • Poseidon hashing (CAP-0075)         │   │
   │   │ amm_pool │◄─────────────────►│                                        │   │
   │   │ batches  │                   └───────────────────────────────────────┘   │
   │   │ encrypted│                          ▲                  ▲                  │
   │   │ reserves │                          │                  │                  │
   │   └────┬─────┘                     ┌────┴─────┐      ┌──────┴──────┐          │
   │        │ threshold-decrypt         │ lending  │      │  Reflector  │          │
   │        ▼                           │  (LTV)   │─────►│   oracle    │          │
   │   ┌──────────────┐                 └──────────┘ read └─────────────┘          │
   │   │  committee   │ (off-chain DKG, posts batch clearing + proof)              │
   │   └──────────────┘                                                            │
   └───────────────────────────────────────────────────────────────────────────────┘
                                         ▲
                                         │ Soroban RPC events (~7d retention)
                         ┌───────────────┴─────────────────┐
                         │   indexer/ (Node.js)             │
                         │   persists full Merkle tree,     │
                         │   commitments, encrypted notes   │
                         └──────────────────────────────────┘
```

## 2. Contracts and function signatures

> Signatures are Rust-ish pseudocode; exact Soroban SDK types resolved in
> CONTRACTS.md. `Env`, `Address`, `BytesN<32>` per soroban-sdk. **Field elements
> are `BytesN<32>` big-endian, reduced mod the BN254 scalar field.**

### 2.1 `veil_core` — shared shielded state (EXTENDS SPP pool)
```rust
// --- commitments / tree ---
fn deposit(env, proof: Proof, public: DepositPublic, asp_proof: AspProof,
           auditor_ct: Bytes) -> CommitmentIndex;     // RULE 1 + RULE 4 enforced here
fn insert_commitment(env, caller: Address, leaf: BytesN<32>, auditor_ct: Bytes)
                    -> CommitmentIndex;                // module-only; RULE 4 enforced
fn current_root(env) -> BytesN<32>;
fn root_is_known(env, root: BytesN<32>) -> bool;       // recent-root window

// --- nullifiers (RULE 3: two distinct sets) ---
fn spend(env, caller: Address, nullifier: BytesN<32>) -> ();   // -> spent set
fn lock(env, caller: Address, nullifier: BytesN<32>) -> ();    // -> locked set
fn unlock(env, caller: Address, nullifier: BytesN<32>) -> ();  // locked -> released
fn is_spent(env, n: BytesN<32>) -> bool;
fn is_locked(env, n: BytesN<32>) -> bool;

// --- verification ---
fn verify_groth16(env, vk_id: VkId, proof: Proof, public_inputs: Vec<BytesN<32>>)
                 -> bool;                              // wraps BN254 pairing (CAP-0074)

// --- access control ---
fn register_module(env, admin: Address, module: Address, perms: Perms) -> ();
fn set_admin(env, admin: Address, new_admin: Address) -> ();
```

### 2.2 `asp` — Association Set Provider (REUSES SPP ASP design)
```rust
fn approved_root(env) -> BytesN<32>;
fn blocked_root(env) -> BytesN<32>;
fn update_approved(env, op: Address, new_root: BytesN<32>, attest: Bytes) -> ();
fn update_blocked(env, op: Address, new_root: BytesN<32>, attest: Bytes) -> ();
// Called by veil_core during deposit. Returns Ok only if the membership +
// non-membership proof verifies against the CURRENT approved/blocked roots.
fn check_entry(env, caller: Address, p: AspMembershipProof) -> Result<(), AspError>;
```

### 2.3 `amm_pool` — fully-shielded batch-auction AMM (NEW; not in SPP)
```rust
fn submit_order(env, proof: Proof, enc_order: Bytes, nullifier: BytesN<32>,
                root: BytesN<32>) -> OrderId;   // enc_order = flow-encrypted intent
fn current_batch(env) -> BatchId;
// committee posts the cleared batch + a settlement proof binding inputs->outputs
fn settle_batch(env, committee: Address, batch: BatchId, clearing: Clearing,
                settle_proof: Proof, output_commitments: Vec<(BytesN<32>, Bytes)>)
               -> ();                            // inserts outputs into veil_core
fn add_liquidity(env, proof: Proof, nullifier: BytesN<32>, lp_commit: BytesN<32>,
                 auditor_ct: Bytes) -> ();        // shielded LP
fn remove_liquidity(env, proof: Proof, nullifier: BytesN<32>) -> ();
fn encrypted_reserves(env) -> EncReserves;        // committee-decryptable only
```

### 2.4 `lending` — private RWA lending (NEW; not in SPP)
```rust
fn open_loan(env, proof: Proof, collateral_nullifier: BytesN<32>,
             borrow_commit: BytesN<32>, auditor_ct: Bytes,
             oracle_asset: Asset, root: BytesN<32>) -> LoanId;   // RULE 3: lock
fn repay(env, proof: Proof, repay_nullifier: BytesN<32>,
         collateral_unlock: BytesN<32>) -> ();                   // unlock collateral
fn liquidate(env, proof: Proof, loan: LoanId, oracle_asset: Asset) -> ();
fn read_oracle_price(env, asset: Asset) -> PriceData;            // Reflector SEP-40
```

### 2.5 `viewkey` — auditor disclosure (NEW; library + core-stored state)
```rust
fn set_auditor_pubkey(env, admin: Address, pk: BytesN<32>) -> ();
fn auditor_pubkey(env) -> BytesN<32>;
fn ciphertext_at(env, idx: CommitmentIndex) -> Bytes;  // for off-chain decrypt
// Decryption is OFF-CHAIN: auditor holds the secret key; contract only stores
// the per-commitment ciphertext (RULE 4) and serves it by index.
```

## 3. Cross-contract call graph

```
deposit:        app ─► veil_core.deposit
                           ├─► asp.check_entry            (RULE 1, must pass)
                           ├─► veil_core.verify_groth16   (deposit circuit)
                           ├─► tree.insert + store auditor_ct  (RULE 4)
                           └─► (no nullifier; deposit creates, not spends)

swap (submit):  app ─► amm_pool.submit_order
                           ├─► veil_core.root_is_known
                           ├─► veil_core.verify_groth16   (swap circuit)
                           └─► veil_core.spend(nullifier) (RULE 3: spent set)

swap (settle):  committee ─► amm_pool.settle_batch
                           ├─► veil_core.verify_groth16   (batch_settle circuit)
                           └─► veil_core.insert_commitment × outputs (+auditor_ct)

borrow:         app ─► lending.open_loan
                           ├─► veil_core.root_is_known
                           ├─► lending.read_oracle_price  (Reflector)
                           ├─► veil_core.verify_groth16   (lend circuit, LTV range)
                           ├─► veil_core.lock(nullifier)  (RULE 3: locked set)
                           └─► veil_core.insert_commitment (borrow note +auditor_ct)

repay:          app ─► lending.repay
                           ├─► veil_core.verify_groth16
                           ├─► veil_core.spend(repay_nullifier)
                           └─► veil_core.unlock(collateral_nullifier)
```

**Auth:** modules call `veil_core` mutating fns; `veil_core` checks the caller is
a `register_module`-ed address with the right `Perms` AND `require_auth`s the
module contract. The committee address for `settle_batch` is registered the same
way. Admin actions (`register_module`, `set_admin`, ASP root updates,
`set_auditor_pubkey`) require the respective admin/operator `require_auth`.

## 4. Shared-state model

- **One Merkle tree** of commitments in `veil_core` persistent storage. Every
  module inserts leaves here; there is no per-module tree. (RULE 2 — universal
  notes.) Tree depth fixed (e.g. 32) → fixed anonymity-set ceiling per design.
- **Two nullifier sets**, both in `veil_core`: `spent` (consumed forever) and
  `locked` (collateral held; can transition to released). Spend/transfer/swap
  circuits prove the input nullifier is in **neither** set (RULE 3). Lending
  moves to `locked`; repay moves `locked → released` and spends the repay note.
- **Recent-root window:** `veil_core` retains the last N roots so a proof built
  against a slightly-stale root still verifies (avoids races as the tree grows).
- **Auditor ciphertext store:** parallel to every leaf, indexed identically
  (RULE 4). `insert_commitment` is the *only* leaf-insertion path and it
  *requires* the ciphertext argument — there is no way to insert without it.

## 5. Trust boundaries

```
┌─ TRUSTED (protocol correctness) ────────────────────────────────┐
│ veil_core verifier + tree + nullifier logic; Groth16 soundness;  │
│ trusted-setup ceremony (Phase-2); Poseidon/BN254 host fns.       │
├─ SEMI-TRUSTED (liveness / disclosure, NOT soundness) ────────────┤
│ threshold-decryption committee (Module 1): can halt batches and  │
│   sees aggregate flow; CANNOT forge balances (settle_proof gates).│
│ ASP operator: governs who may enter; CANNOT steal funds or       │
│   de-anonymize existing notes.                                   │
│ auditor (view key): can decrypt notes it is given indices for;   │
│   CANNOT spend; key compromise = disclosure risk, not theft.     │
├─ UNTRUSTED ──────────────────────────────────────────────────────┤
│ indexer/relayer: convenience + availability only; all claims are │
│   re-verifiable against on-chain root. Cannot forge or de-anon.  │
│ the network / observers: see commitments, nullifiers, batch      │
│   aggregates, oracle reads — never amounts, parties, or balances.│
└──────────────────────────────────────────────────────────────────┘
```

The committee is the central new trust assumption versus SPP and the reason for
the longer timeline (PRD §5, ROADMAP). Its decryption power is bounded to
aggregate batch flow; soundness of every balance change is enforced by the
`batch_settle` proof, so a malicious committee can stall but cannot steal.

## 6. ZK primitive map (where BN254 / Poseidon are used)

| Primitive | Location | Use |
|-----------|----------|-----|
| **Poseidon (CAP-0075)** | circuits + `veil_core` | commitment hash, nullifier hash, Merkle node hash. Same params on-chain and in-circuit (MUST match). |
| **BN254 pairing (CAP-0074)** | `veil_core.verify_groth16` | on-chain Groth16 proof verification for every circuit. |
| **BN254 G1/G2 ops (CAP-0074)** | `veil_core` verifier wrapper | vk preprocessing / proof element decoding as required by Groth16. |
| **Flow encryption (ElGamal-on-BN254 / committee key)** | `amm_pool`, committee | encrypts order intent + reserves; threshold-decrypted per batch. // VERIFY curve choice vs host-fn support |

## 7. Data flow — deposit (ASCII)

```
holder ──RWA token──► app
  app: build note (amount,asset,blinding,owner_pk); ASP membership witness;
       deposit proof (WASM); encrypt note to auditor_pk
  app ──tx{proof, public, asp_proof, auditor_ct}──► veil_core.deposit
       veil_core ─► asp.check_entry  ── ok? ──┐ (RULE 1)
       veil_core ─► verify_groth16(deposit)   │
       veil_core: leaf = Poseidon(note); tree.insert(leaf)
       veil_core: store auditor_ct at leaf idx (RULE 4)
       veil_core: emit {leaf, idx, ct}  ─► indexer persists ─► tree rebuildable
  app: save note to localStorage as spendable UTXO
```

## 8. Data flow — private swap via batch auction (ASCII)

```
trader: input note ──► swap proof (nullifier valid, in neither set, intent bound)
        intent ──flow-encrypt to committee key──► enc_order
   app ──► amm_pool.submit_order(proof, enc_order, nullifier, root)
        veil_core.spend(nullifier)            (RULE 3)
   ...batch window closes...
   committee: threshold-decrypt all enc_orders in batch ► compute clearing price
              build settle_proof: Σ inputs = Σ outputs at clearing, reserves
              update consistent, each output well-formed
   committee ──► amm_pool.settle_batch(batch, clearing, settle_proof, outputs[])
        veil_core.verify_groth16(batch_settle)
        veil_core.insert_commitment(output_i, auditor_ct_i)  ∀ outputs (RULE 4)
   traders: scan new leaves, recover their output notes (trial-decrypt)
```

## 9. Extends vs reuses SPP

| Component | Reuse / Extend |
|-----------|----------------|
| Directory layout | **Reuse** wholesale. |
| Note/Merkle/nullifier base circuits | **Reuse** templates; extend with two-set nullifier check. |
| Deposit/transfer/withdraw circuits | **Reuse** as the transfer baseline. |
| ASP membership/non-membership trees | **Reuse** design; wire as mandatory deposit gate. |
| ceremony-cli | **Reuse** for Phase-2. |
| Browser WASM proving | **Reuse** pipeline; add per-circuit keys. |
| Single transact circuit | **Extend** → swap, lend, kyc_credential, batch_settle. |
| Fully-shielded AMM + committee | **New.** No SPP equivalent (primary design: Penumbra-style batch auction; fallback: Renegade-style collaborative SNARK — REFERENCES.md). |
| Lending + oracle LTV | **New.** |
| View keys | **New.** (SPP has ASP but not auditor view keys.) |
