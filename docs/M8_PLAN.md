# M8 Build Plan — Mainnet Launch with BENJI + Reflector

Milestone M8 exit gate: `veil e2e mainnet-roundtrip --network mainnet --asset BENJI` green.
Read alongside CLAUDE.md, M7_PLAN.md (the sign-off gate this depends on), PRD.md (§5 scope, §6 success
metrics, §8 dependencies), ARCHITECTURE.md (full), CONTRACTS.md (§4 oracle, §1 TTL), REFERENCES.md
(Reflector mainnet, BENJI), SECURITY.md (§8 gate), ROADMAP.md (M8), TEST_PLAN.md (M8).

> **Hard precondition:** M7's SECURITY §8 sign-off gate is fully satisfied. Mainnet deploy is forbidden
> until every box is checked. This milestone wires real assets, deploys behind that gate, and proves a
> real round-trip on mainnet.

---

## What M8 delivers

| Area | Deliverable |
|------|-------------|
| Real asset | Swap the dev **TEST-RWA** target for **Franklin Templeton BENJI** (asset_id + SAC address) |
| Oracle | Wire **Reflector mainnet** feeds into `lending` |
| Deploy | `veil_core` + `asp` + `amm_pool` + `lending` to **mainnet** behind the SECURITY §8 gate |
| Ops | Monitoring + **anonymity-set metric** (PRD §6): commitments-in-pool growth, no de-anon incident |
| Proof | ASP-gated BENJI deposit → private swap → private withdraw round-trip on mainnet |

---

## Resolved design decisions (new in M8)

| Decision | Choice | Reason |
|----------|--------|--------|
| Target asset | **BENJI** (Franklin Templeton) on mainnet; TEST-RWA remains the testnet/dev asset | PRD §5 target; TEST-RWA ensured dev was never blocked on issuer timelines. // VERIFY BENJI SAC contract id + issuer cooperation (PRD §8) |
| asset_id derivation | `asset_id = Poseidon(issuer, code)` for BENJI, computed once and pinned | CIRCUITS §0 asset_id definition; must match across circuit + contract + wallet. |
| Oracle | **Reflector mainnet** SEP-40 feed for the BENJI/collateral asset | REFERENCES; PRD §8 (Reflector live on mainnet). // VERIFY mainnet Reflector contract id + feed availability for the asset |
| Deploy gate | mainnet deploy script **asserts** the SECURITY §8 checklist artifacts (signed audits, pinned ceremony keys, key custody, bug bounty open, runbook) before broadcasting | SECURITY §8 "no exceptions". |
| Key custody | admin (multisig), committee (t-of-n), auditor (HSM) keys in production custody; `set_admin` two-step | SECURITY §3/§6. |
| Anonymity-set metric | indexer exposes commitments-in-pool count + growth trend; alert on de-anon signals | PRD §6 success metric. |

---

## Hard rules in force (unchanged, now on mainnet)

- **RULE 1:** every mainnet BENJI deposit passes `asp.check_entry` first.
- **RULE 2 / 3 / 4:** universal notes, two nullifier sets, paired auditor ciphertext — all as in T1–T3.
- Reflector `oracle_price` binding for any lending op (CONTRACTS §4).

---

## Phase 1 — Real asset + oracle wiring

Blocks on: M7 sign-off.

- [ ] **T1.0** Pin BENJI: resolve the BENJI SAC contract id + `asset_id = Poseidon(issuer, code)`; add a
  mainnet asset config in `deployments/mainnet.json`. Verify issuer cooperation (PRD §8).
- [ ] **T1.1** Wire Reflector **mainnet** oracle: set `lending.ORACLE` to the mainnet Reflector contract;
  confirm the BENJI/collateral feed exists and is SEP-40 compatible; set conservative `LTV_MAX_BPS` +
  `STALENESS`.
- [ ] **T1.2** Frontend + indexer: switch network config to mainnet; load BENJI asset metadata; keep
  TEST-RWA available for testnet.

---

## Phase 2 — Gated mainnet deploy

Blocks on: Phase 1; M7 SECURITY §8 gate satisfied.

- [ ] **T2.0** Mainnet deploy script that **asserts the SECURITY §8 gate** (refuses to broadcast if any
  artifact is missing): signed audits, pinned ceremony keys (`veil verify-keys`), key custody,
  bug-bounty-open flag, approved runbook.
- [ ] **T2.1** Deploy `veil_core`, `asp`, `amm_pool`, `lending` to mainnet; record contract ids in
  `deployments/mainnet.json`.
- [ ] **T2.2** Initialize: admin (multisig), register modules + committee, set auditor pubkey (HSM-held),
  initialize ASP approved/blocked roots from the production compliance set, load ceremony vkeys via
  `vk-convert` + the mainnet key gate.

---

## Phase 3 — Monitoring + anonymity-set metric

Blocks on: Phase 2.

- [ ] **T3.0** Indexer mainnet mode: persist the tree, expose `/root`, `/anonymity-set` (commitment count
  + growth trend), and nullifier/disclosure event streams.
- [ ] **T3.1** Monitoring/alerting: contract health, oracle staleness, committee liveness (→ refund path),
  and a de-anon signal watch (PRD §6). Hook the incident runbook.

---

## Phase 4 — Mainnet smoke E2E

Blocks on: Phases 1–3.

- [ ] **T4.0** `e2e-tests/src/mainnet-roundtrip.test.ts` — assertions per TEST_PLAN M8:
  1. **ASP-gated BENJI deposit** succeeds (and a non-approved address is rejected).
  2. **Private swap** of the deposited BENJI note (trader/size/counterparty hidden).
  3. **Private withdraw** back to a public address — full round-trip completes.
  4. **Reflector feed read + bound** in any lending op (oracle_price public input == fresh price).
  5. **Monitoring + anonymity-set metric** reporting live.
  ```
  veil e2e mainnet-roundtrip --network mainnet --asset BENJI
  ```

---

## Dependency graph

```
M7 sign-off ─► T1.0 ─► T1.1 ─► T1.2
                                 │
                                 ▼
              (SECURITY §8 gate) ─► T2.0 ─► T2.1 ─► T2.2
                                            T3.0 ─► T3.1
                                            [all] ─► T4.0  (exit: mainnet-roundtrip green)
```

## What success looks like (PRD §6 + closing)

> A regulated institution deposits BENJI through a compliance gate, swaps and borrows against it on
> Stellar mainnet with amounts and counterparties private, and a regulator can audit a specific position
> on lawful request — none of which is possible on Stellar today. That is "100% private settlement for
> institutions," shipped.

| Metric (PRD §6) | Target |
|---|---|
| Mainnet deposit→swap→withdraw round-trip | works, ASP-gated, acceptable latency |
| Browser swap proof time | within interactive budget on a commodity laptop |
| On-chain Groth16 verify cost | within Soroban limits with margin |
| Auditor disclosure | regulator decrypts exactly in-scope notes, nothing else |
| RWA integration | ≥1 real issuer asset (BENJI) live |
| Anonymity set @ 6 months | growth trend, no de-anon incident |

## Not in M8 (out of scope — PRD §5)

- Cross-chain / bridge privacy; network-level (IP) anonymity; mobile apps; fiat on/off-ramp;
  governance token; permissionless committee/ASP governance (post-grant R&D).

## Done check

`veil e2e mainnet-roundtrip --network mainnet --asset BENJI` exits 0 with all five T4.0 assertions
passing — the full program is delivered.
