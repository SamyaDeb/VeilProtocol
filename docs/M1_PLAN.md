# M1 Build Plan — Shielded Transfer

Milestone M1 exit gate: `veil e2e transfer --network testnet` green.
Read alongside CLAUDE.md, M0_PLAN.md (foundation this builds on), CIRCUITS.md (§0, §2 for the
transact pattern), CONTRACTS.md (§1 `spend`), ARCHITECTURE.md (§4 shared-state, §8),
THREAT_MODEL.md (§2 double-spend), TEST_PLAN.md (M1).

> Builds directly on M0. Everything from M0 (Poseidon params, BN254 verifier wrapper, tree,
> auditor-ciphertext store, ASP gate, deposit) is assumed live and green before starting M1.

---

## What M1 adds over M0

| Area | M0 had | M1 adds |
|------|--------|---------|
| Circuits | `deposit`, `kyc_credential` | `transfer` (2-in / 2-out transact: spend + create) |
| `veil_core` | `spend`/`lock`/`unlock` **stubs** | real `spend()` — writes `SPENT`, rejects if in `SPENT ∨ LOCKED` (RULE 3) |
| Wallet | single-note save | note **selection / split / merge**, multi-note store |
| Recovery | depositor saves own note | **recipient** recovers an incoming note by scanning the tree (trial-decrypt) |

---

## Resolved design decisions (new in M1)

| Decision | Choice | Reason |
|----------|--------|--------|
| Transact shape | **2-in / 2-out** (reuse SPP's single transact circuit) | SPP ships exactly this; covers split (1→2) and merge (2→1) by zero-padding unused notes. |
| Zero/dummy notes | unused input/output slots use a **dummy note** (amount=0, fixed blinding) excluded from nullifier set checks | Standard SPP pattern; lets one circuit handle 1-in and 2-in cases. |
| Value conservation | `sum_in === sum_out` (no public amount; `public_amount = 0` for an internal transfer) | Pure shielded transfer moves no value in/out of the pool. |
| Recipient note delivery | sender encrypts each output note to the **recipient's viewing pubkey** (X25519 ECIES, same scheme as auditor) and posts it as an **event payload** the indexer persists; recipient trial-decrypts | Mirrors Zcash/SPP note-ciphertext flow. No new contract storage tier needed — rides the insert event. // VERIFY event size limits on testnet |
| Recipient address | recipient's **viewing pubkey + spend pubkey**, shared out-of-band (a "Veil payment address"), NOT a Stellar address | Transfers are internal to the shielded pool; no on-chain identity is revealed. |
| Nullifier definition | `nf = Poseidon([owner_sk, leaf_index, cm])` (already defined in M0 `lib/nullifier.circom`) | Deterministic, owner-bound, unlinkable to `cm` without `owner_sk` (CIRCUITS §0). |

---

## Hard rules in force

- **RULE 3 (first real use):** `spend(nf)` MUST reject if `nf ∈ SPENT` OR `nf ∈ LOCKED`. The
  circuit produces a valid owner-bound `nf`; the **contract** is the authority on set membership
  (CIRCUITS §2 note, THREAT_MODEL §2). A note may never be spent twice.
- **RULE 4:** every output commitment inserted via `insert_commitment` carries a non-empty
  `auditor_ct`. Two outputs → two auditor ciphertexts.
- **RULE 2 (do not block):** the output note format is identical to a deposit note — a transfer
  output must later be spendable by any module with no conversion.

---

## Phase 1 — Transfer circuit

Blocks on: M0 Phase 1 base libraries (`commitment_hasher`, `merkle_tree_checker`, `nullifier`,
`range_check`) already exist.

- [ ] **T1.0** `circuits/transfer.circom` — 2-in / 2-out transact (reuse SPP `transaction.circom`).
  - Header public-input order (this IS the vkey binding):
    ```
    // Public inputs (in order):
    //   1. root
    //   2. nf_in_0
    //   3. nf_in_1
    //   4. cm_out_0
    //   5. cm_out_1
    //   6. public_amount   (== 0 for internal transfer; reserved for M2 withdraw reuse)
    ```
  - Private: for each input `i`: `amount_in_i, asset_in_i, blinding_in_i, owner_sk_i, leaf_index_i,
    path_i[32], idx_i[32]`; for each output `j`: `amount_out_j, asset_out_j, blinding_out_j, owner_pk_out_j`.
  - Constraints:
    - `∀i (real): MerkleTreeChecker(cm_in_i, path_i, idx_i) === root`
    - `∀i (real): Poseidon(owner_sk_i) === owner_pk_in_i` (ownership)
    - `∀i (real): NullifierHasher(owner_sk_i, leaf_index_i, cm_in_i) === nf_in_i`
    - `∀j: CommitmentHasher(amount_out_j, asset_out_j, blinding_out_j, owner_pk_out_j) === cm_out_j`
    - `∀i,j: RangeCheck64`
    - **Value conservation:** `Σ amount_in === Σ amount_out + public_amount` (per asset; single-asset for M1)
    - Asset consistency: all real inputs/outputs share one `asset_id` (M1 single-asset transfer)
    - Dummy-note handling: a slot with `amount = 0` is excluded from the Merkle/nullifier checks via a `isReal` selector signal.
- [ ] **T1.1** Compile + tests:
  ```
  circom circuits/transfer.circom --r1cs --wasm --sym -o circuits/build/
  ```
  Negative tests (must FAIL to satisfy):
  - `Σ in ≠ Σ out` (value not conserved)
  - wrong nullifier (`owner_sk` mismatch)
  - tampered Merkle path
  - output amount out of 64-bit range
  - mixed asset ids across notes
  - swapped public-input order
- [ ] **T1.2** Dev ceremony for `transfer` (testnet only, same flow as M0 T2.3): setup → contribute →
  export `vk_transfer.json`. Run `tools/vk-convert` → `VkId::Transfer` blob. Pin in `circuit-keys/dev/`
  + update `manifest.sha256`.

---

## Phase 2 — `veil_core` spend + transfer path

Blocks on: Phase 1 vk; M0 `veil_core` live.

- [ ] **T2.0** Implement real `spend(caller, nf)` (replaces M0 stub):
  - Check `caller` registered with `SPEND` perm + `require_auth`.
  - Reject `AlreadySpent` if `nf ∈ SPENT`; reject `IsLocked` if `nf ∈ LOCKED` (RULE 3).
  - Insert `nf` into `SPENT`; `extend_ttl`; emit `NullifierSpent{nf}` event.
- [ ] **T2.1** `is_spent(nf)`, `is_locked(nf)` — real reads of `SPENT` / `LOCKED`.
- [ ] **T2.2** `transfer(proof, public: TransferPublic, output_cts: Vec<Bytes>, note_cts: Vec<Bytes>)`:
  - `TransferPublic { root, nf_in_0, nf_in_1, cm_out_0, cm_out_1, public_amount }`.
  - `root_is_known(root)` else `UnknownRoot`.
  - `verify_groth16(VkId::Transfer, proof, [root, nf_in_0, nf_in_1, cm_out_0, cm_out_1, public_amount])`.
  - For each **real** input nullifier: `spend(nf)` (RULE 3). (`nf == 0`/dummy skipped.)
  - For each **real** output: `insert_commitment(self, cm_out_j, output_cts[j])` (RULE 4) and emit the
    recipient `note_cts[j]` in the insert event for trial-decrypt.
  - `public_amount` MUST equal 0 for M1 (`InvalidPublicAmount` otherwise — withdraw is M2).
  - Returns the inserted commitment indices.
- [ ] **T2.3** `cargo test` (veil_core):
  - double-spend: second `spend(nf)` → `AlreadySpent`
  - spend a locked nf → `IsLocked`
  - transfer inserts 2 leaves + 2 auditor cts; root advances
  - unauthorized caller to `spend` → `Unauthorized`
  - `public_amount != 0` → `InvalidPublicAmount`

---

## Phase 3 — Wallet (note management + recovery)

Blocks on: Phase 1 (`transfer.wasm` + zkey).

- [ ] **T3.0** `app/src/store/notes.ts` (extend M0): track a **set** of UTXO notes per owner; mark notes
  spent locally when their `nf` appears on-chain; expose `selectInputs(amount, asset) -> Note[]` (coin
  selection: pick 1–2 notes covering `amount`).
- [ ] **T3.1** `app/src/wallet/address.ts` — Veil payment address: `(viewing_pk, spend_pk)` encoded as a
  shareable string (bech32-ish). `spend_pk = owner_pk = Poseidon(owner_sk)`; `viewing_pk` = X25519 pubkey.
- [ ] **T3.2** `app/src/prover/transfer.ts` — build witness for 1-in/1-out, 1-in/2-out (split),
  2-in/1-out (merge); generate proof; serialize to the 256-byte proof format.
- [ ] **T3.3** `app/src/viewkey/encrypt.ts` (reuse M0 ECIES) — encrypt each output note **twice**: once to
  the recipient `viewing_pk` (`note_ct`), once to the auditor pubkey (`auditor_ct`).
- [ ] **T3.4** `app/src/ui/TransferForm.tsx` — recipient address + amount → select inputs → compute change
  output (back to self) + recipient output → prove → submit `veil_core.transfer` via Freighter → mark
  inputs spent, save change note.
- [ ] **T3.5** `app/src/wallet/scan.ts` — recipient recovery: pull insert events from the indexer,
  trial-decrypt each `note_ct` with own `viewing_sk`; on success, reconstruct the note, verify
  `cm == CommitmentHasher(note)`, and add it to the store as spendable.

---

## Phase 4 — Indexer extension

Blocks on: T2.2 event schema.

- [ ] **T4.0** Index `NullifierSpent` events into a `nullifiers` table (for the wallet to mark notes spent).
- [ ] **T4.1** Persist `note_ct` alongside each commitment so the recipient scan (T3.5) can fetch
  candidates by ledger range. Tree-rebuild logic unchanged (still hashes `cm` leaves only).

---

## Phase 5 — Deploy + E2E

Blocks on: all prior phases; M0 contracts already deployed (upgrade `veil_core` wasm).

- [ ] **T5.0** Upgrade `veil_core` on testnet with the transfer path + real `spend`; load `VkId::Transfer`.
- [ ] **T5.1** `e2e-tests/src/transfer.test.ts` — assertions per TEST_PLAN M1:
  1. **A→B transfer** hides amount + parties (on-chain shows only nullifiers + commitments).
  2. **Recipient recovers** the output note via tree scan + trial-decrypt; `cm` matches.
  3. **Double-spend rejected**: replaying A's nullifier → tx fails with `AlreadySpent`.
  4. Change note returns to A and is spendable in a follow-up transfer.
  ```
  veil e2e transfer --network testnet
  ```

---

## Dependency graph

```
M0 (all green) ─► T1.0 ─► T1.1 ─► T1.2
                                     │
                                     ▼
                          T2.0 ─► T2.1 ─► T2.2 ─► T2.3
                                                   │
T1.2 ─► T3.0 ─► T3.1 ─► T3.2 ─► T3.3 ─► T3.4 ─► T3.5
T2.2 ─► T4.0 ─► T4.1
[all] ─► T5.0 ─► T5.1   (exit: veil e2e transfer green)
```

## Not in M1 (do not build)

- Withdraw / public exit — M2 (the `public_amount` slot is reserved but must be 0 here)
- `lock`/`unlock` real logic — M6
- Auditor disclosure UI — M2
- Multi-asset transfer in one tx — out of scope (single asset per transfer for M1)

## Done check

`veil e2e transfer --network testnet` exits 0 with all four T5.1 assertions passing.
