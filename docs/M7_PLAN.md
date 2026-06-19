# M7 Build Plan — Mainnet Ceremony + Dual Audit Remediation

Milestone M7 exit gate: `veil verify-keys && veil e2e tampered-proof-rejected --network testnet` green,
**and** the SECURITY §8 sign-off checklist fully checked.
Read alongside CLAUDE.md, SECURITY.md (§1 scope, §5 ceremony, §7 testing-as-evidence, §8 gate),
THREAT_MODEL.md (§3 trusted setup, and every "soundness-critical" item), CIRCUITS.md (§7–§8 ceremony +
vkey conversion), ROADMAP.md (M7), TEST_PLAN.md (M7).

> This milestone is **mostly process + hardening, not new features.** It replaces all dev/solo proving
> keys with a multi-party ceremony output, runs two independent audits, and remediates every
> Critical/High before mainnet. No new product surface ships here.

---

## What M7 delivers

| Area | Deliverable |
|------|-------------|
| Trusted setup | **Multi-party Phase-2 ceremony** for every production circuit; transcripts + final zkeys + vkeys pinned and hash-verified |
| Key hygiene | **Hard gate**: mainnet config refuses any dev/solo-generated key |
| Audit pass 1 | `veil_core`, `asp`, `viewkey`, `amm_pool` + M1/M3 circuits + setup review (contract audit **and** circuit/setup audit, separate firms) |
| Audit pass 2 | `lending`, `lend.circom`, oracle binding, liquidation, refund path (the riskiest pieces, isolated) |
| Remediation | All Critical/High fixed + re-audited/regression-tested; Medium tracked with owner + date |
| CI | pinned-key sha256 verification; negative-test build (broken variant must fail soundness tests) |
| Bug bounty | Funded pool live before mainnet |

---

## Resolved design decisions (new in M7)

| Decision | Choice | Reason |
|----------|--------|--------|
| Phase-2 ceremony tooling | **`tools/ceremony-cli/`** (reuse SPP ceremony-cli) | REFERENCES; proven Phase-2 contribution flow. |
| Contributors | **≥ N independent contributors** per circuit; transcripts published | Soundness holds if ≥1 contributor is honest (THREAT_MODEL §3). |
| Phase-1 source | documented perpetual Powers-of-Tau with provenance + hash | SECURITY §5; reuse a large well-witnessed PoT. |
| Key pinning | final zkey sha256 + every contribution hash + vkey in `circuit-keys/`; CI verifies on every PR | SECURITY §5; reproducible, auditable. |
| Mainnet key gate | a build-time/config gate that **refuses** any key whose hash is in the dev set | SECURITY §5; dev keys can never reach mainnet. |
| Audit split | (a) Soroban contract audit, (b) ZK circuit + setup audit — **different firms**; no single firm rubber-stamps both | SECURITY §1. |
| vkey reload | re-run `tools/vk-convert` on ceremony vkeys; re-initialize on-chain `VK` storage with the audited, pinned keys | CIRCUITS §8; the on-chain vk must match the ceremony output. |

---

## Soundness-critical focus (must be zero-defect at mainnet — THREAT_MODEL §9)

These drive the audit and the negative-test build: **double-spend (RULE 3), trusted setup, refund
(settle XOR refund), cross-contract auth abuse, and the vkey-conversion path.**

---

## Phase 1 — Multi-party Phase-2 ceremony

Blocks on: all production circuits frozen (no R1CS changes after this point).

- [ ] **T1.0** Freeze circuits: snapshot every `--r1cs` (constraint count must not drift after ceremony).
- [ ] **T1.1** Run `tools/ceremony-cli` Phase-2 per circuit with ≥N independent contributors; collect
  contribution transcripts.
- [ ] **T1.2** Export final `zkey` + `vk.json` per circuit; record contribution chain + final sha256.
- [ ] **T1.3** `tools/vk-convert` → Soroban vk blobs for every circuit; replace the dev keys in
  `circuit-keys/` (move dev keys to `circuit-keys/dev/` clearly marked testnet-only).
- [ ] **T1.4** Update `circuit-keys/manifest.sha256` with the ceremony outputs; **CI job** verifies the
  pinned hashes on every PR (`veil verify-keys`).

---

## Phase 2 — Mainnet key gate + CI hardening

Blocks on: Phase 1.

- [ ] **T2.0** Implement the **mainnet key gate**: deploy/config tooling refuses to load any vk whose hash
  is in the dev set; mainnet may only use ceremony-pinned keys (SECURITY §5).
- [ ] **T2.1** `veil verify-keys` CLI — verifies `circuit-keys/` files match `manifest.sha256` and the
  on-chain `VK` matches the ceremony vkey (reproducible build check).
- [ ] **T2.2** **Negative-test build** CI job (SECURITY §7): build a deliberately broken variant (e.g.
  nullifier check removed, or value-conservation constraint dropped) and assert the soundness negative
  tests **FAIL** there — proving the tests have teeth.
- [ ] **T2.3** `e2e-tests/src/tampered-proof-rejected.test.ts` — a deliberately tampered proof (byte-flipped
  A/B/C, or wrong public inputs) is **REJECTED on-chain** by `verify_groth16` for each circuit.

---

## Phase 3 — Audit pass 1 (Modules 1+3 core) + remediation

Blocks on: Phase 1 (audited code uses ceremony keys).

- [ ] **T3.0** Prepare the audit handoff package (SECURITY §7): coverage report, the §3 contract checklist
  + §4 circuit checklist self-assessment, threat model, ceremony transcripts.
- [ ] **T3.1** Engage **two firms**: Soroban contract audit (`veil_core`, `asp`, `viewkey`, `amm_pool`) +
  ZK circuit/setup audit (M1/M3 circuits + trusted setup).
- [ ] **T3.2** Remediate **all Critical/High** → block until fixed + re-audited/regression-tested.
  Track Medium with owner + date (SECURITY §2). Add a regression test per finding.

---

## Phase 4 — Audit pass 2 (lending) + remediation

Blocks on: M6 complete; Phase 3.

- [ ] **T4.0** Isolated audit of `lending`, `lend.circom`, oracle binding, liquidation, and the
  settle-or-refund path (the riskiest pieces — SECURITY §1).
- [ ] **T4.1** Remediate all Critical/High; regression tests; Medium tracked.

---

## Phase 5 — Bug bounty + operational readiness

Blocks on: Phases 1–4.

- [ ] **T5.0** Launch a funded **bug bounty** (live for ≥ the SECURITY §8 defined window before mainnet).
- [ ] **T5.1** Operational readiness (SECURITY §6): committee t-of-n params + member identities/staking
  documented; auditor key custody (HSM); ASP operator key custody; incident runbook (oracle outage,
  committee halt → refund, key compromise) approved.

---

## Exit gate — SECURITY §8 sign-off checklist (ALL required)

- [ ] Zero open Critical/High (both audit passes signed)
- [ ] Mainnet trusted-setup ceremony complete + pinned (`veil verify-keys` green)
- [ ] Both audit passes (contract + circuit) signed off
- [ ] Bug bounty open ≥ defined window
- [ ] Admin / committee / auditor keys in production custody (multisig / HSM; `set_admin` two-step)
- [ ] Incident runbook approved
- [ ] `veil e2e tampered-proof-rejected --network testnet` green
- [ ] Negative-test build CI proves soundness tests fail on a broken build

> **No exceptions — this is institutional money** (SECURITY §8).

---

## Dependency graph

```
circuits frozen ─► T1.0 ─► T1.1 ─► T1.2 ─► T1.3 ─► T1.4
                                                      │
                                                      ▼
                                  T2.0 ─► T2.1 ─► T2.2 ─► T2.3
                                  T3.0 ─► T3.1 ─► T3.2
                       M6 done ─► T4.0 ─► T4.1
                                  T5.0 ─► T5.1
                                  [all] ─► SECURITY §8 gate  (exit)
```

## Not in M7 (do not build)

- New product features of any kind
- BENJI / mainnet deploy — M8 (gated on this milestone's sign-off)

## Done check

`veil verify-keys && veil e2e tampered-proof-rejected --network testnet` exit 0, and every box in the
SECURITY §8 checklist above is checked.
