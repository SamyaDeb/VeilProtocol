# M5 Build Plan — Shielded Liquidity Provision + Note Portability

Milestone M5 exit gate: `veil e2e amm-lp --network testnet` green.
Read alongside CLAUDE.md, M3_PLAN.md + M4_PLAN.md (the AMM this extends), ARCHITECTURE.md (§2.3
add/remove_liquidity, §4 universal notes), CIRCUITS.md (§0 note model), CONTRACTS.md (§3 amm_pool),
PRD.md (US-4 portability, US-6 LP), ROADMAP.md (M5), TEST_PLAN.md (M5).

> Prerequisite: M4 (encrypted-reserve clearing) green, OR the M3 fallback's public-pool AMM is the base.
> This is the milestone that **proves RULE 2 end-to-end**: a note minted by one module is usable by
> another with no conversion.

---

## What M5 adds

| Area | Adds |
|------|------|
| Circuits | `add_liquidity` (spend asset note(s) → mint LP note, hidden size), `remove_liquidity` (burn LP note → mint asset note(s) + accrued fees) |
| `amm_pool` | `add_liquidity` / `remove_liquidity` fns; pro-rata fee accounting on the encrypted reserves |
| LP privacy | LP **position size is hidden** on-chain; fee accrual is **provable to the LP** |
| RULE 2 | a Module-1 **swap-output note** opens an LP position (or is spent elsewhere) with **no conversion step** |

---

## Resolved design decisions (new in M5)

| Decision | Choice | Reason |
|----------|--------|--------|
| LP position representation | an **LP note** = a universal note (`amount = LP shares`, `asset_id = LP-share asset`, `blinding`, `owner_pk`) stored as a normal commitment in the **same tree** | RULE 2: one note format, one tree (ARCHITECTURE §4). LP shares are just another asset_id. |
| Fee accrual | fees accumulate into the encrypted reserves; an LP's claim = `shares / total_shares × reserve_growth`, proven in `remove_liquidity` against the reserve commitments at add-time and remove-time | Pro-rata, provable to the LP, size stays hidden. |
| Total-shares tracking | `total_lp_shares` kept as part of the (encrypted/committed) reserve state, updated on add/remove | Needed to compute pro-rata without revealing individual sizes. |
| Hidden size | LP `amount` (shares) lives only inside the note + proof; on-chain shows a commitment + nullifier, never the size | US-6. |
| Portability proof | the e2e test takes an actual `cm_out` from an M3/M4 swap settlement and uses it directly as an `add_liquidity` input — no transform | US-4 / RULE 2 acceptance criterion. |

---

## Hard rules in force

- **RULE 2 (headline for M5):** swap-output note → LP input with NO conversion. Proven end-to-end.
- **RULE 3:** `add_liquidity` spends its input note(s); `remove_liquidity` spends the LP note. Reject
  double-spend / locked.
- **RULE 4:** every minted commitment (LP note on add; asset notes on remove) carries an auditor ct.

---

## Phase 1 — LP circuits

Blocks on: M0 base libs; M4 reserve commitments.

- [ ] **T1.0** `circuits/add_liquidity.circom`:
  - Public (in order): `root, nf_in_0, nf_in_1, lp_commit, reserve_pre_commit, reserve_post_commit`.
  - Constraints: input membership + ownership + nullifiers; `lp_commit = CommitmentHasher(shares,
    LP_ASSET, blinding, owner_pk)`; `shares` computed correctly from deposited amounts vs current reserves
    (`shares = amount_in × total_shares / reserve`); reserve commitment updated; range checks.
- [ ] **T1.1** `circuits/remove_liquidity.circom`:
  - Public (in order): `root, lp_nf, cm_out_0, cm_out_1, reserve_pre_commit, reserve_post_commit`.
  - Constraints: LP note membership + ownership + `lp_nf`; payout `amount_out =
    shares / total_shares × reserve` **including accrued fees**; output commitments well-formed; reserve
    + total-shares decremented; range checks.
- [ ] **T1.2** Negative tests: shares miscomputed; payout exceeds pro-rata; reserve/total-shares transition
  wrong; wrong nullifier; public-input reorder.
- [ ] **T1.3** Dev ceremony → `vk_add_liquidity.json`, `vk_remove_liquidity.json` → `VkId::{AddLiquidity,
  RemoveLiquidity}`; pin + manifest.

---

## Phase 2 — `amm_pool` LP functions

Blocks on: Phase 1 vks; M4 `ENC_RESERVES`.

- [ ] **T2.0** `add_liquidity(proof, nf, lp_commit, auditor_ct)` (CONTRACTS §3):
  - `core.verify_groth16(VkId::AddLiquidity, ...)` → `core.spend(nf)` per input (RULE 3) →
    `core.insert_commitment(lp_commit, auditor_ct)` (RULE 4) → update reserve commitment + `total_lp_shares`
    + `ENC_RESERVES` → record `lp_commit` in `LP` map.
- [ ] **T2.1** `remove_liquidity(proof, nf)`:
  - verify → `core.spend(lp_nf)` → `core.insert_commitment` for each asset output (RULE 4) → decrement
    reserves + shares → emit fee-accrual event.
- [ ] **T2.2** `cargo test`: add mints an LP note + updates shares; remove burns it + pays pro-rata incl.
  fees; LP size never appears in any event; double-remove → `AlreadySpent`; `UnknownLp` on a non-LP note.

---

## Phase 3 — UI + portability wiring

Blocks on: Phase 1, Phase 2.

- [x] **T3.0** `app/src/prover/lp.ts` + `app/src/ui/LiquidityForm.tsx` — add/remove LP; show provable
  accrued fees to the LP (computed client-side from reserve commitments at add vs now).
- [x] **T3.1** Portability: ensure the wallet treats a swap-output note and a deposit note identically —
  `selectInputs` can feed either into `add_liquidity`. No conversion code path.

---

## Phase 4 — Deploy + E2E

- [x] **T4.0** Upgrade `amm_pool` on testnet; load the two LP vks.
- [x] **T4.1** `e2e-tests/src/amm-lp.test.ts` — assertions per TEST_PLAN M5:
  1. **LP add/remove with hidden size**: on-chain shows only commitments/nullifiers, never the LP amount.
  2. **Pro-rata fee accrual provable to the LP**: after some swap volume, remove returns principal + fees.
  3. **Note portability (RULE 2)**: a Module-1 swap-output note opens an LP position with **no conversion**.
  ```
  veil e2e amm-lp --network testnet
  ```

---

## Dependency graph

```
M4 (green) ─► T1.0 ─► T1.1 ─► T1.2 ─► T1.3
                                        │
                                        ▼
                             T2.0 ─► T2.1 ─► T2.2
                             T3.0 ─► T3.1
                             [all] ─► T4.0 ─► T4.1  (exit: veil e2e amm-lp green)
```

## T3 exit (end of M5)

> A genuinely **fully-shielded swap** — trader, size, counterparty, balances, AND reserves private — on
> testnet, plus shielded LP and proven note portability. This is the headline result (ROADMAP T3 exit).

## Not in M5 (do not build)

- Lending — M6
- Mainnet ceremony / audit — M7
- Real assets (BENJI) — M8

## Done check

`veil e2e amm-lp --network testnet` exits 0 with all three T4.1 assertions passing.
