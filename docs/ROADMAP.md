# ROADMAP — Veil Protocol

**Principle: vertical slices, not horizontal phases.** Every milestone crosses
circuit + contract + frontend + test, and is independently demoable end-to-end on
**testnet** (browser proof → on-chain verify). No milestone ships "just the
contracts" or "just the circuits."

**Timeline reality (per the chosen scope — fully-shielded AMM + lending +
compliance, single dev):** ~28–40 weeks. The fully-shielded batch-auction AMM
with a threshold-decryption committee is research-grade and is the single largest
risk to the timeline; it is deliberately given the most room and an early
de-risking spike. This timeline and its risk are stated plainly in SCF_PROPOSAL.

> Testnet uses **TEST-RWA** (self-issued) so progress never blocks on issuer
> timelines; **BENJI + Reflector** integration lands as the mainnet slice.

---

## SCF tranche map (v7.0: 10% / 20% / 30% / 40%)

| Tranche | % | Theme | Milestones | Exit demo |
|---------|---|-------|-----------|-----------|
| **T1** | 10% | Foundation + compliant shielded pool | M0, M1 | ASP-gated deposit + shielded transfer, e2e on testnet |
| **T2** | 20% | Private value movement + AMM spike | M2, M3 | Private withdraw + committee/AMM de-risk demo on testnet |
| **T3** | 30% | Fully-shielded AMM | M4, M5 | End-to-end private batch swap on testnet |
| **T4** | 40% | Lending + ceremony + audit + mainnet | M6, M7, M8 | Private lending e2e; audits clean; mainnet w/ BENJI |

Tranche release is gated on the exit demo's **verification command passing**
(TEST_PLAN.md) — the demo *is* the deliverable, not a doc.

---

## T1 — Foundation + compliant shielded pool (10%)

### M0 — ShieldCore + ASP-gated deposit + view-key ciphertext  *(~wk 1–4)*
Vertical slice: `deposit.circom` + `kyc_credential.circom` → `veil_core` (tree,
verifier wrapper, auditor ciphertext store) + `asp` → frontend deposit UI +
WASM prover + Freighter + indexer (tree persistence).
- Reuses SPP base templates + ASP design; first BN254 verify wired on testnet.
- **Independently testable:** a non-approved address is rejected; an approved
  deposit inserts a commitment + decryptable auditor ciphertext; indexer
  reconstructs the on-chain root. (RULE 1 + RULE 4 proven.)
- **Verify:** `e2e-tests` deposit suite; see TEST_PLAN M0.

### M1 — Shielded transfer  *(~wk 5–7)*
Vertical slice: extend transact circuit (spend + create) → `veil_core.spend`
(two-set check, RULE 3) → wallet note store (split/merge), recover output note.
- **Independently testable:** A→B private transfer; double-spend rejected;
  recipient recovers note by scanning tree. (RULE 3 proven for `spent`.)
- **Verify:** TEST_PLAN M1.

> **T1 exit:** compliant deposit + shielded transfer running e2e on testnet. This
> alone is a credible private-payments product and the floor we never regress.

---

## T2 — Private value movement + AMM de-risk (20%)

### M2 — Shielded withdraw + relayer (optional) + auditor UI  *(~wk 8–10)*
Vertical slice: withdraw circuit → `veil_core` exit path → auditor disclosure UI
(decrypt in-scope ciphertext via view key) + optional relayer to break payer-IP
linkage.
- **Independently testable:** withdraw to a public address; auditor decrypts
  exactly the in-scope note and nothing else (US-5). View keys proven universal.
- **Verify:** TEST_PLAN M2.

### M3 — Fully-shielded AMM de-risking spike  *(~wk 11–16)* ⚠ highest risk
Vertical slice (thin but full-stack): flow encryption to a committee key →
`amm_pool.submit_order` + `settle_batch` skeleton → `batch_settle.circom` for a
**fixed small K (e.g. K=4)** with a **2-of-3 mock committee** → minimal UI.
- Proves the hard part early: encrypted order submission, threshold decryption,
  a settlement proof that conserves value, and the settle-or-refund timeout path.
- **Independently testable:** 4 orders submitted (encrypted) → committee settles a
  balance-preserving batch on testnet → traders recover outputs; an unsettled
  batch refunds. (Committee trust + liveness path proven, THREAT_MODEL §6.)
- **Verify:** TEST_PLAN M3. **If this spike reveals the threshold/clearing design
  is infeasible in budget, it triggers the documented fallback decision** (see
  Fallbacks) BEFORE committing T3 — this is why it lives in T2.

---

## T3 — Fully-shielded AMM (30%)

### M4 — Encrypted reserves + real clearing  *(~wk 17–24)*
Vertical slice: `ENC_RESERVES` with committee-decryptable state → real
constant-function (or oracle-anchored) clearing in `batch_settle.circom` →
slippage/`min_out` enforcement → reserve-transition proof.
- **Independently testable:** multi-order batch clears at one price; reserves
  update consistently and stay hidden; `min_out` honored or order excluded.
- **Verify:** TEST_PLAN M4.

### M5 — Shielded liquidity provision + note portability  *(~wk 25–28)*
Vertical slice: `add_liquidity`/`remove_liquidity` (shielded LP) → fee accrual →
prove a Module-1 swap-output note opens a position with no conversion (RULE 2,
US-4).
- **Independently testable:** LP adds/removes with hidden size + earns fees; a
  swap-output note is used directly as input elsewhere. (RULE 2 proven end-to-end.)
- **Verify:** TEST_PLAN M5.

> **T3 exit:** a genuinely fully-shielded swap — trader, size, counterparty,
> balances, AND reserves private — on testnet. This is the headline result.

---

## T4 — Lending + ceremony + audit + mainnet (40%)

### M6 — Private RWA lending  *(~wk 29–33)*
Vertical slice: `lend.circom` (LTV range proof) → `lending.open_loan/repay/
liquidate` with Reflector oracle binding + `locked` nullifier set (RULE 3 for
collateral) → lend UI.
- **Independently testable:** borrow against a shielded note within LTV (amounts
  hidden); over-LTV rejected; locked collateral cannot be swapped/re-borrowed;
  repay releases it; stale-oracle rejected; liquidation on an unhealthy loan.
  (US-3 + RULE 3 `locked` proven.)
- **Verify:** TEST_PLAN M6.

### M7 — Mainnet ceremony + dual audit remediation  *(~wk 33–37)*
Cross-layer hardening: multi-party Phase-2 ceremony (pin keys + transcripts);
contract audit pass + circuit/setup audit pass (SECURITY §1); remediate all
Critical/High; bug bounty opens.
- **Independently testable:** CI verifies pinned keys; a deliberately-tampered
  proof is rejected on-chain; audit findings tracked to closed.
- **Verify:** SECURITY §8 gate checklist.

### M8 — Mainnet launch with BENJI + Reflector  *(~wk 37–40)*
Vertical slice: swap TEST-RWA → live **BENJI**; wire **Reflector** mainnet feeds;
deploy `veil_core`+`asp`+`amm_pool`+`lending` to mainnet behind the SECURITY §8
sign-off gate; monitoring + anonymity-set metric (PRD §6).
- **Independently testable:** a real ASP-gated BENJI deposit → private swap →
  private withdraw round-trip on mainnet.
- **Verify:** TEST_PLAN M8 (mainnet smoke).

---

## Dependency graph
```
M0 ─► M1 ─► M2
        └─► M3(spike) ─► M4 ─► M5 ─► M6 ─► M7 ─► M8
M0 also unblocks M3 (committee needs core insert path)
M6 depends on M0 (locked set) + M1 (spend) + oracle; not on M4/M5 logic
```

## Fallback decisions (pre-committed, triggered by the M3 spike)
If the fully-shielded committee design proves infeasible within budget:
1. **Ship shielded-swap-vs-public-pool for mainnet** (M1-style notes in/out of a
   public reserve), and reclassify fully-shielded reserves as a post-grant R&D
   line. Preserves the whole product; downgrades only the AMM's reserve privacy.
2. Keep M0–M2 + M6 (compliant private payments + private lending) as the funded
   deliverable — already a first-of-its-kind on Stellar.
This branch is disclosed up-front in SCF_PROPOSAL so a pivot is honest, not a miss.
