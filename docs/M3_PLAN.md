# M3 Build Plan — Fully-Shielded AMM De-Risking Spike  ⚠ HIGHEST RISK

Milestone M3 exit gate: `veil e2e amm-spike --network testnet --batch-size 4` green.
Read alongside CLAUDE.md, M0–M2 plans, ARCHITECTURE.md (§2.3, §5 trust, §8 swap data flow),
CIRCUITS.md (§2 swap, §3 batch_settle), CONTRACTS.md (§3 amm_pool), THREAT_MODEL.md (§1.4 committee
disclosure, §6 committee liveness/refund), ROADMAP.md (Fallback decisions), REFERENCES.md (Penumbra,
Renegade), TEST_PLAN.md (M3).

> **This is a spike: thin but full-stack.** Fixed `K=4` batch, 2-of-3 **mock** committee, minimal UI.
> The goal is to prove the hard parts *exist and compose* — encrypted order submission, threshold
> decryption, a value-preserving settlement proof, and the settle-or-refund timeout path — BEFORE the
> bulk of AMM work (M4/M5). **If this spike shows the design is infeasible in budget, it triggers the
> pre-committed fallback (see end of file) BEFORE starting M4.**

---

## What M3 proves (the four hard parts)

1. **Encrypted order submission** — a trader flow-encrypts a swap intent to the committee key and
   submits it; the input note is nullified on submit.
2. **Threshold decryption** — a 2-of-3 committee jointly decrypts the batch's orders (no single member
   can).
3. **Value-preserving settlement** — the committee posts a `batch_settle` proof that conserves value
   across the batch and is verified on-chain; traders recover their output notes.
4. **Settle-or-refund liveness** — if the committee withholds settlement past a timeout, each submitter
   reclaims their value via a refund proof. An order can be **settled XOR refunded, never both**
   (THREAT_MODEL §6 — top audit item).

---

## Resolved design decisions (new in M3) — several are spike-validated, expect change

| Decision | Choice (spike) | Reason / risk |
|----------|----------------|---------------|
| Flow-encryption scheme | **threshold ElGamal over BN254 G1** (CAP-0074 G1 ops) | Curve already supported on-chain; pairings not needed for ElGamal. // VERIFY G1 ops suffice for the encrypt/decrypt we need vs needing a different curve — this is a primary spike question (ARCHITECTURE §6 VERIFY) |
| Committee key | 2-of-3 **Shamir** secret-shared ElGamal secret; mock DKG (trusted dealer for spike) | Permissionless DKG is explicitly out of scope (PRD §5); spike uses a known dealer. |
| Batch size | **fixed K=4** | One fixed-K settle circuit first (CIRCUITS §3); variable/recursive batches are an M4+ optimization. |
| Clearing (spike) | **simplified single clearing price**, mock/oracle-anchored (NOT yet a real CFMM) | Real constant-function clearing + encrypted reserves is M4. The spike only needs value conservation to hold. |
| Reserves (spike) | **plaintext or trivial** placeholder; `ENC_RESERVES` wired but not enforced | Encrypted-reserve transition proof is M4. |
| Refund design | settle-or-refund: after `BATCH_TIMEOUT`, submitter proves their order is in an unsettled batch and **mints a fresh note of equal value**; the order is marked `refunded` so `settle_batch` can't also include it | Avoids literal "un-spend"; the nullifier stays spent. Mutual exclusion (settle XOR refund) is the soundness-critical property. |
| Output recovery | settle inserts each output commitment with a recipient `note_ct` (reuse M1 trial-decrypt) | Traders scan + decrypt to recover swap outputs (ARCHITECTURE §8). |
| Committee tooling | `tools/committee-cli/` (off-chain): collect batch, threshold-decrypt, compute clearing, build `batch_settle` witness + proof, call `settle_batch` | Mock committee for the spike; reputational/staked real committee is later. |

---

## Hard rules in force

- **RULE 3:** `submit_order` calls `veil_core.spend(nf)` — the input note is consumed on submit; reject
  if in `SPENT ∨ LOCKED`.
- **RULE 4:** every output commitment from `settle_batch` carries a non-empty `auditor_ct`.
- **Soundness:** a malicious committee can **stall** (liveness) but can **never steal or forge** — every
  balance change is gated by the `batch_settle` proof (ARCHITECTURE §5). The refund path must not allow
  double-claim (settle XOR refund).

---

## Phase 1 — Flow-encryption primitive  (spike question #1)

Blocks on: nothing (can start in parallel with M2 wrap-up).

- [ ] **T1.0** `app/src/crypto/threshold_elgamal.ts` — ElGamal over BN254 G1: keygen (dealer),
  `encrypt(intent, committee_pk) -> (c1, c2)`, partial-decrypt per share, combine 2-of-3.
- [ ] **T1.1** `tools/committee-cli/` scaffold — holds the 3 key shares (spike: local files), exposes
  `decrypt-batch`.
- [ ] **T1.2** Round-trip test: encrypt 4 intents → 2-of-3 partial decrypts combine → recover plaintext;
  1-of-3 fails. **Decision gate:** confirm the chosen curve/scheme works with available host-fn support;
  if not, record the finding and consult the fallback before proceeding.

---

## Phase 2 — Swap + batch_settle circuits

Blocks on: T1.2 (encryption scheme fixed); M0 base libs.

- [ ] **T2.0** `circuits/swap.circom` (CIRCUITS §2):
  - Public (in order): `root, nf_in, enc_order_hash, committee_pk`.
  - Constraints: input membership; ownership; `nf_in` correct; `RangeCheck64(amount_in)`,
    `RangeCheck64(min_out)`; `EncOrderHasher(asset_out, min_out, out_blinding, out_owner_pk,
    committee_pk, r_enc) === enc_order_hash` (binds the on-chain ciphertext to this proof).
  - Negative tests: wrong nf; intent not matching enc_order_hash; OOB amounts.
- [ ] **T2.1** `circuits/batch_settle.circom` (CIRCUITS §3), **fixed K=4**:
  - Public (in order): `batch_id, enc_order_hash_0..3, clearing, cm_out_0..3, pre_reserve_commit, post_reserve_commit`.
  - Constraints: `∀j Decrypt(enc_order_hash_j) === intent_j`; **value conservation** `Σ in === Σ out + fee`
    per asset at the single `clearing`; `∀j LessEqThan(min_out_j, amount_out_j)`; `∀j
    CommitmentHasher(...) === cm_out_j` + range; `ReserveTransition(pre, in, out) === post`.
  - Negative tests: value not conserved; a `min_out_j > amount_out_j`; reserve transition wrong;
    output commitment malformed.
- [ ] **T2.2** `circuits/settle_or_refund.circom` — refund leg: prove an order (by `enc_order_hash`) was
  submitted, its batch passed `BATCH_TIMEOUT` unsettled, and mint a fresh note `cm_refund` of equal value
  to the original owner. Output public: `enc_order_hash, cm_refund, batch_id`. **Mutual-exclusion is
  enforced on-chain** (the order is marked refunded; a settled order can't refund and vice versa) — the
  circuit proves well-formedness of the refund note. Negative test: refund amount ≠ original.
- [ ] **T2.3** Dev ceremony for `swap`, `batch_settle` (K=4), `settle_or_refund`; vk-convert →
  `VkId::{Swap, BatchSettle4, SettleOrRefund}`; pin + manifest.

---

## Phase 3 — `amm_pool` contract

Blocks on: Phase 2 vks; M0 `veil_core` (insert/spend), M1 `spend`.

- [ ] **T3.0** Scaffold `contracts/amm_pool/` (CONTRACTS §3): storage `CORE, COMMITTEE, COMMITTEE_PK,
  CUR_BATCH, ORDERS, ENC_RESERVES, LP`; error enum. Register `amm_pool` as a `veil_core` module (INSERT +
  SPEND perms).
- [ ] **T3.1** `submit_order(proof, enc_order, nf, root)`:
  - `core.root_is_known(root)` → `core.verify_groth16(VkId::Swap, ...)` → `core.spend(nf)` (RULE 3) →
    store `(order_id → (enc_order, nf))` in `ORDERS` under `CUR_BATCH`.
- [ ] **T3.2** `current_batch()`; batch lifecycle (open → window closes → settling). Track `batch_open_ledger`
  for the timeout.
- [ ] **T3.3** `settle_batch(committee, batch, clearing, settle_proof, outputs: Vec<(BytesN<32>, Bytes)>)`:
  - `require_auth(COMMITTEE)` (committee address registered like a module).
  - `core.verify_groth16(VkId::BatchSettle4, settle_proof, [batch_id, enc_order_hash_0..3, clearing,
    cm_out_0..3, pre, post])`.
  - For each output: `core.insert_commitment(self, cm_out_j, auditor_ct_j)` (RULE 4) + emit recipient `note_ct`.
  - Mark the batch settled (orders can no longer refund); update `ENC_RESERVES` (placeholder for spike);
    open next batch. Reject `BatchClosed` if already settled; `ReserveMismatch` on bad transition.
- [ ] **T3.4** `refund(proof, order_id)`: only if `CUR_BATCH`/order's batch is past `BATCH_TIMEOUT` and
  unsettled. `core.verify_groth16(VkId::SettleOrRefund, ...)` → `core.insert_commitment(cm_refund, ct)` →
  mark order `refunded`. Reject if the batch was settled or the order already refunded (mutual exclusion).
- [ ] **T3.5** `cargo test` (amm_pool): submit spends nf + stores order; non-committee `settle_batch` →
  `Unauthorized`; bad settle proof → `BadProof`; settle inserts 4 outputs + cts; **refund after timeout
  succeeds; refund after settle REJECTED; settle after refund REJECTED** (the XOR property).

---

## Phase 4 — Committee CLI + minimal UI

Blocks on: Phase 1 (decrypt), Phase 2 (proving), Phase 3 (contract).

- [ ] **T4.0** `tools/committee-cli/` — `settle <batch>`: fetch `ORDERS`, threshold-decrypt (2-of-3),
  compute simplified clearing, build `batch_settle` witness + proof, encrypt each output to the trader's
  viewing pubkey + auditor, call `settle_batch`.
- [ ] **T4.1** `app/src/prover/swap.ts` + `app/src/ui/SwapForm.tsx` — minimal: enter intent → flow-encrypt
  to `COMMITTEE_PK` → prove `swap` → `submit_order`. Post-settle: scan + trial-decrypt output note.
- [ ] **T4.2** `app/src/ui/RefundButton.tsx` — after timeout on an unsettled batch, prove + call `refund`.

---

## Phase 5 — Deploy + E2E

- [ ] **T5.0** Deploy `amm_pool` to testnet; register as module + set `COMMITTEE`, `COMMITTEE_PK`; load the
  three vks.
- [ ] **T5.1** `e2e-tests/src/amm-spike.test.ts` — assertions per TEST_PLAN M3:
  1. **4 encrypted orders submitted** (each spends its input note).
  2. **2-of-3 committee threshold-decrypts** and posts a **value-preserving** `settle_batch` that verifies
     on-chain.
  3. **Traders recover outputs** via scan + trial-decrypt.
  4. **Withheld settlement → refund**: a separate batch is left unsettled past timeout; submitters refund
     successfully; that batch can no longer be settled.
  ```
  veil e2e amm-spike --network testnet --batch-size 4
  ```

---

## Dependency graph

```
T1.0 ─► T1.1 ─► T1.2 (curve/scheme decision gate)
                  │
                  ▼
       T2.0 ─► T2.1 ─► T2.2 ─► T2.3
                                 │
                                 ▼
       T3.0 ─► T3.1 ─► T3.2 ─► T3.3 ─► T3.4 ─► T3.5
                                                 │
       T4.0 ─► T4.1 ─► T4.2                      │
       [all] ─► T5.0 ─► T5.1  (exit: veil e2e amm-spike green)
```

## ⚠ Fallback decision gate (pre-committed, ROADMAP)

**Evaluate at the end of M3, BEFORE starting M4.** If the spike shows the fully-shielded
committee/clearing design is infeasible within budget (e.g. threshold ElGamal + on-chain verify too
costly, or the settle/clearing proof won't fit Soroban limits):

1. **Pivot:** ship **shielded-swap-vs-public-pool** for mainnet (M1-style notes in/out of a *public*
   reserve), and reclassify encrypted reserves (M4) as post-grant R&D.
2. Keep M0–M2 + M6 (compliant private payments + private lending) as the funded deliverable.

This pivot is disclosed up-front in SCF_PROPOSAL — it is an honest, pre-planned branch, not a miss.
Record the spike findings and the decision in `docs/` before continuing either way.

## Not in M3 (do not build)

- Real CFMM clearing + encrypted-reserve transition — M4
- Shielded LP — M5
- Permissionless DKG / rotating committee — out of scope (PRD §5)
- Variable / recursive batch sizes — M4+ optimization

## Done check

`veil e2e amm-spike --network testnet --batch-size 4` exits 0 with all four T5.1 assertions passing,
**and** the fallback decision is explicitly recorded.
