# M4 Build Plan — Encrypted Reserves + Real Clearing

Milestone M4 exit gate: `veil e2e amm-settle --network testnet` green.
Read alongside CLAUDE.md, M3_PLAN.md (the spike this promotes to production), ARCHITECTURE.md (§2.3,
§4 shared state, §8), CIRCUITS.md (§3 batch_settle), CONTRACTS.md (§3 amm_pool, §7 resource notes),
THREAT_MODEL.md (§1.4), REFERENCES.md (Penumbra), TEST_PLAN.md (M4).

> **Prerequisite:** the M3 spike passed AND the fallback gate chose to proceed with the fully-shielded
> design. If the gate chose the pivot, build shielded-swap-vs-public-pool instead and skip the
> encrypted-reserve tasks below.

---

## What M4 adds over the M3 spike

| Area | M3 spike had | M4 makes real |
|------|--------------|---------------|
| Reserves | placeholder / plaintext | **`ENC_RESERVES`** — committee-decryptable encrypted pool reserves, hidden on-chain |
| Clearing | simplified single price | **real constant-function (x·y=k) or oracle-anchored** single clearing price for the batch |
| Reserve proof | none enforced | **reserve-transition proof**: `post = pre + Σin − Σout`, verified in `batch_settle` |
| Slippage | basic `min_out ≤ amount_out` | **`min_out` enforced with order exclusion**: orders that can't clear at the price are excluded (and refundable) |
| Batch size | K=4 | production K (e.g. K=8/16/32); pick K to fit Soroban limits (CONTRACTS §7) |

---

## Resolved design decisions (new in M4)

| Decision | Choice | Reason |
|----------|--------|--------|
| Clearing function | **constant-function (x·y=k)** single batch price | Penumbra-style batch auction reference (REFERENCES); deterministic, provable in-circuit. // VERIFY in-circuit division/inversion cost vs oracle-anchored alternative |
| Encrypted reserves | reserves committed as `Poseidon`/Pedersen commitment on-chain; **plaintext value encrypted to committee key** (`ENC_RESERVES`); circuit proves the committed reserves match the encrypted ones | Reserves stay hidden from observers; committee can decrypt to compute clearing; soundness via the commitment binding. |
| Order exclusion | an order whose `min_out` exceeds what it gets at the clearing price is **excluded** from the settle (not value-conserved into outputs) and becomes **refundable** via the M3 settle-or-refund path | Honors slippage bounds without failing the whole batch. |
| Batch size K | choose the largest K whose `settle_batch` proof verifies within Soroban CPU/size limits with margin | One settle proof amortizes pairing cost across K orders (CONTRACTS §7). // VERIFY limits on testnet |
| Reserve-transition encoding | `ReserveTransition(pre_reserves, in_sums, out_sums) === post_reserves` per asset, overflow-safe | CIRCUITS §3 constraint 5. |

---

## Hard rules in force

- **RULE 3 / RULE 4:** unchanged from M3 (submit spends; settle inserts outputs with auditor cts).
- **Soundness:** committee still can only **stall**, never steal — the reserve-transition + value-conservation
  proof gates every reserve change. The committee *sees* batch contents (THREAT_MODEL §1.4 — the accepted
  core tradeoff) but cannot forge balances.

---

## Phase 1 — batch_settle v2 (real clearing + reserves)

Blocks on: M3 `batch_settle.circom` (extend).

- [ ] **T1.0** Extend `circuits/batch_settle.circom` to production K with:
  - **Constant-function clearing:** compute the single clearing price from decrypted orders + pre-reserves;
    prove each filled order trades at that one price (no per-trader discrimination).
  - **Reserve-transition:** `post_reserves === pre_reserves + Σ in − Σ out` per asset; prove `pre`/`post`
    match their on-chain commitments and the committee-encrypted values.
  - **Order exclusion:** a per-order `filled` selector; excluded orders contribute 0 to in/out sums and are
    flagged for refund; `∀ filled j: min_out_j ≤ amount_out_j`.
- [ ] **T1.1** Negative tests: price not single/uniform; reserve transition off by one; an excluded order
  still counted in outputs; `min_out` violated on a filled order; commitment/encryption mismatch on reserves.
- [ ] **T1.2** Dev ceremony for the production-K `batch_settle`; vk-convert → `VkId::BatchSettle{K}`; pin +
  manifest. (Keep K=4 variant for tests if useful.)

---

## Phase 2 — `amm_pool` encrypted reserves

Blocks on: Phase 1 vk; M3 `amm_pool`.

- [ ] **T2.0** Implement `ENC_RESERVES` storage + `encrypted_reserves()` read (committee-decryptable only).
  Store the on-chain reserve **commitment** alongside the ciphertext.
- [ ] **T2.1** Update `settle_batch` to:
  - verify the production-K proof including the reserve-transition + clearing public inputs;
  - update both the reserve commitment and `ENC_RESERVES` from the proof's `post` outputs;
  - mark excluded orders refundable (feed into the M3 refund path);
  - reject `ReserveMismatch` if the posted post-reserves don't match the proof.
- [ ] **T2.2** `cargo test`: multi-order batch settles; reserves update consistently and stay encrypted;
  excluded (min_out-violating) order is not settled and is refundable; tampered reserve update → `ReserveMismatch`.

---

## Phase 3 — Committee CLI clearing + UI

Blocks on: Phase 1, Phase 2.

- [ ] **T3.0** `tools/committee-cli`: implement real clearing — decrypt batch + reserves, compute the
  constant-function clearing price, determine filled vs excluded orders, build the production-K witness,
  prove, and call `settle_batch`.
- [ ] **T3.1** UI: surface `min_out` slippage input in `SwapForm`; show "excluded → refundable" state when an
  order doesn't clear.

---

## Phase 4 — Deploy + E2E

- [ ] **T4.0** Upgrade `amm_pool` on testnet; load `VkId::BatchSettle{K}`.
- [ ] **T4.1** `e2e-tests/src/amm-settle.test.ts` — assertions per TEST_PLAN M4:
  1. **Multi-order batch clears at one price.**
  2. **Reserves update consistently and remain encrypted** on-chain (observer sees only commitments/ciphertext).
  3. **`min_out` honored**: an order that can't meet slippage is excluded (and refundable), the rest settle.
  ```
  veil e2e amm-settle --network testnet
  ```

---

## Dependency graph

```
M3 (proceed gate) ─► T1.0 ─► T1.1 ─► T1.2
                                       │
                                       ▼
                            T2.0 ─► T2.1 ─► T2.2
                            T3.0 ─► T3.1
                            [all] ─► T4.0 ─► T4.1  (exit: veil e2e amm-settle green)
```

## Not in M4 (do not build)

- Shielded LP / fee accrual — M5
- Note portability proof — M5
- Lending — M6
- Permissionless committee / DKG — out of scope

## Done check

`veil e2e amm-settle --network testnet` exits 0 with all three T4.1 assertions passing.
