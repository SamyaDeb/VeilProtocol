# M6 Build Plan — Private RWA Lending

Milestone M6 exit gate: `veil e2e lending --network testnet` green.
Read alongside CLAUDE.md, M0_PLAN.md + M1_PLAN.md (foundation — lending needs the tree, `spend`, and
the locked-set storage keys), CIRCUITS.md (§4 lend), CONTRACTS.md (§4 lending), ARCHITECTURE.md (§2.4,
§3 borrow/repay call graph), THREAT_MODEL.md (§1.3 oracle correlation, §5 oracle manipulation),
REFERENCES.md (Reflector, sep-40-oracle), PRD.md (US-3), TEST_PLAN.md (M6).

> **Dependency note (ROADMAP):** M6 depends on **M0** (locked-set storage), **M1** (`spend`), and the
> oracle — **NOT** on M3/M4/M5. It can be built right after M2 if the AMM is deferred. This is the
> ROADMAP's named fallback deliverable (compliant private payments + private lending).

---

## What M6 adds

| Area | Adds |
|------|------|
| Circuits | `lend` — LTV range proof: `borrow_value ≤ LTV_max × collateral_value` against a public oracle price, **both amounts hidden** |
| `veil_core` | real `lock()` / `unlock()` (replaces M0 stubs) — writes/clears the `LOCKED` set (RULE 3 for collateral) |
| `lending` contract | `open_loan`, `repay`, `liquidate`, `read_oracle_price` with Reflector binding |
| Oracle | Reflector SEP-40 `lastprice` read + staleness check + **proof's `oracle_price` public input bound to the freshly-read on-chain price** |

---

## Resolved design decisions (new in M6)

| Decision | Choice | Reason |
|----------|--------|--------|
| Oracle client | **`sep-40-oracle` crate** (REFERENCES) — import, don't hand-roll | SEP-40 `lastprice(Asset) -> Option<PriceData{price:i128, timestamp:u64}>`, price scaled by `10^decimals`. // VERIFY Asset enum shape + Reflector testnet contract id |
| Oracle binding | `open_loan` reads Reflector, rejects if older than `STALENESS`, and **asserts the proof's `oracle_price`/`oracle_decimals` public inputs equal the freshly-read values** | Prevents proving LTV against a stale/favorable price (CIRCUITS §4, THREAT_MODEL §5). The single most important lending check. |
| LTV math | `borrow_amount × borrow_price × 10_000 ≤ collat_amount × oracle_price × ltv_max_bps`, scaled + overflow-safe (`checked_*` / widened) | CIRCUITS §4 constraint 4; SECURITY §3 overflow item. |
| Collateral lock | `open_loan` → `core.lock(collat_nf)` (LOCKED set, RULE 3); a locked note can be **neither swapped nor re-borrowed** | US-3; `lock` rejects if `nf ∈ SPENT ∨ LOCKED`. |
| Repay | `repay` → `core.spend(repay_nf)` + `core.unlock(collat_nf)` → collateral becomes spendable again | ARCHITECTURE §3 repay flow. |
| Liquidation | `liquidate` allowed only when the loan is **unhealthy** at the fresh oracle price; otherwise `Healthy` error | THREAT_MODEL §5; conservative `LTV_MAX_BPS` with margin. |
| Asset-leakage acceptance | the oracle feed read reveals *which asset* (low-entropy, fixed asset set), but **not amounts** | THREAT_MODEL §1.3 — accepted, documented for v1. |

---

## Hard rules in force

- **RULE 3 (locked set — first real use):** `lock(nf)` rejects if `nf ∈ SPENT ∨ LOCKED`; `unlock`
  requires `LOCKED`. Locked collateral cannot be swapped (a `swap`/`transfer` `spend(nf)` on a locked nf
  fails with `IsLocked`). A note is never in both sets.
- **RULE 4:** the minted borrow note carries a non-empty `auditor_ct`.
- **RULE 2:** collateral may be any universal note (incl. a swap-output note) — no conversion.

---

## Phase 1 — `lend` circuit

Blocks on: M0 base libs (`commitment_hasher`, `merkle_tree_checker`, `nullifier`, `range_check`).

- [ ] **T1.0** `circuits/lend.circom` (CIRCUITS §4):
  - Public (in order): `root, collat_nf, borrow_cm, oracle_price, oracle_decimals, ltv_max_bps, borrow_price`.
  - Private: collateral note `(collat_amount, collat_asset, collat_blinding, owner_sk)`, `leaf_index`,
    Merkle witness; borrow note `(borrow_amount, borrow_asset, borrow_blinding, owner_pk)`.
  - Constraints: collateral membership + ownership (`Poseidon(owner_sk)===owner_pk`); `collat_nf` correct
    (→ lock); `borrow_cm = CommitmentHasher(...)`; `RangeCheck64` on both amounts; **LTV:**
    `LessEqThan(borrow_amount·borrow_price·10_000, collat_amount·oracle_price·ltv_max_bps)` (scaled,
    overflow-safe).
- [ ] **T1.1** Negative tests (must FAIL): over-LTV borrow; wrong `collat_nf`; tampered Merkle path; amount
  out of range; `borrow_cm` mismatch; public-input reorder.
- [ ] **T1.2** Dev ceremony → `vk_lend.json` → `VkId::Lend`; pin + manifest.

---

## Phase 2 — `veil_core` lock / unlock (real)

Blocks on: M0 `LOCKED`/`SPENT` storage keys.

- [ ] **T2.0** Implement real `lock(caller, nf)` (replaces M0 stub): registered caller + `require_auth`;
  reject `AlreadySpent` if `nf ∈ SPENT`, `AlreadyLocked` if `nf ∈ LOCKED`; insert into `LOCKED`; `extend_ttl`;
  emit `NullifierLocked{nf}`.
- [ ] **T2.1** Implement real `unlock(caller, nf)`: requires `nf ∈ LOCKED` else `NotLocked`; remove from
  `LOCKED`; emit `NullifierUnlocked{nf}`.
- [ ] **T2.2** Confirm `spend(nf)` already rejects `IsLocked` (from M1) — add a regression test that a locked
  collateral nf cannot be spent by a transfer/swap.
- [ ] **T2.3** `cargo test`: lock then swap-spend → `IsLocked`; lock twice → `AlreadyLocked`; lock a spent nf
  → `AlreadySpent`; unlock non-locked → `NotLocked`; unlock then spend succeeds.

---

## Phase 3 — `lending` contract

Blocks on: Phase 1 vk, Phase 2 lock/unlock; M0 `veil_core` insert/verify.

- [ ] **T3.0** Scaffold `contracts/lending/` (CONTRACTS §4): storage `CORE, ORACLE, LTV_MAX_BPS, STALENESS,
  LOANS: Map<LoanId, LoanRec{collat_nf, borrow_cm, price, asset}>`; error enum. Register `lending` as a
  `veil_core` module (LOCK + UNLOCK + SPEND + INSERT perms).
- [ ] **T3.1** `read_oracle_price(asset) -> PriceData` — call Reflector `lastprice`; `NoPrice` if none;
  `StaleOracle` if `now − timestamp > STALENESS`.
- [ ] **T3.2** `open_loan(proof, collat_nf, borrow_commit, auditor_ct, oracle_asset, root)`:
  - `core.root_is_known(root)`; `read_oracle_price(oracle_asset)` (staleness);
  - **assert the proof's `oracle_price` + `oracle_decimals` public inputs equal the freshly-read price**
    (the critical binding);
  - `core.verify_groth16(VkId::Lend, proof, [root, collat_nf, borrow_cm, oracle_price, oracle_decimals,
    ltv_max_bps, borrow_price])`;
  - `core.lock(collat_nf)` (RULE 3) → `core.insert_commitment(borrow_cm, auditor_ct)` (RULE 4) →
    record `LoanRec`; return `LoanId`.
- [ ] **T3.3** `repay(proof, repay_nf, collat_unlock)`: verify → `core.spend(repay_nf)` →
  `core.unlock(collat_unlock)` → close `LoanRec`.
- [ ] **T3.4** `liquidate(proof, loan, oracle_asset)`: read fresh price; verify the loan is **unhealthy**
  (`Healthy` error otherwise); verify proof; seize/settle per design (collateral nullifier resolution).
- [ ] **T3.5** `cargo test` (lending): borrow within LTV succeeds + locks; over-LTV rejected (bad proof);
  stale oracle rejected; `oracle_price` public input ≠ fresh price rejected; repay unlocks + spends;
  liquidate only when unhealthy; LTV math overflow-safe (fuzz large amounts).

---

## Phase 4 — Lend UI

Blocks on: Phase 1 (`lend.wasm`/zkey), Phase 3.

- [ ] **T4.0** `app/src/prover/lend.ts` — build witness (collateral note + borrow note + oracle inputs),
  prove, serialize.
- [ ] **T4.1** `app/src/ui/LendForm.tsx` — pick collateral note, choose borrow amount, fetch live Reflector
  price, prove LTV, submit `open_loan`; show locked-collateral state; repay flow.

---

## Phase 5 — Deploy + E2E

- [ ] **T5.0** Deploy `lending` to testnet; register as module; set `ORACLE` (Reflector testnet), `LTV_MAX_BPS`,
  `STALENESS`; load `VkId::Lend`.
- [ ] **T5.1** `e2e-tests/src/lending.test.ts` — assertions per TEST_PLAN M6:
  1. **Borrow within LTV** (amounts hidden) succeeds; collateral is locked.
  2. **Over-LTV REJECTED** by the circuit.
  3. **Locked collateral cannot be swapped** (RULE 3 locked) — a transfer/swap on it fails `IsLocked`.
  4. **Repay releases** collateral (unlock); it becomes swappable again.
  5. **Stale oracle REJECTED.**
  6. **Unhealthy loan liquidatable.**
  ```
  veil e2e lending --network testnet
  ```

---

## Dependency graph

```
M0 (locked-set keys) + M1 (spend) ─► T2.0 ─► T2.1 ─► T2.2 ─► T2.3
M0 base libs ─► T1.0 ─► T1.1 ─► T1.2
                                  │
                                  ▼ (+ T2.x)
                       T3.0 ─► T3.1 ─► T3.2 ─► T3.3 ─► T3.4 ─► T3.5
                       T4.0 ─► T4.1
                       [all] ─► T5.0 ─► T5.1  (exit: veil e2e lending green)
```

## Not in M6 (do not build)

- Dual-oracle median / circuit-breaker — roadmap hardening (THREAT_MODEL §5), not v1
- Mainnet ceremony / audit — M7
- BENJI / mainnet Reflector — M8

## Done check

`veil e2e lending --network testnet` exits 0 with all six T5.1 assertions passing.
