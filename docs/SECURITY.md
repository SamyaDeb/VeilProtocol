# SECURITY — Veil Protocol audit-readiness

Maps the protocol to **SCF Soroban Audit Bank** expectations: every Critical/High
finding remediated and verified before mainnet; Medium tracked with owner + date;
ZK-circuit concerns audited separately from contract logic. This doc is the
checklist the team works against and hands to auditors.

## 1. Audit scope & sequencing
- **Audit pass 1 (pre-mainnet, Modules 1+3 core):** `veil_core`, `asp`,
  `viewkey`, `amm_pool`, all circuits in scope for M1/M3 + trusted-setup review.
- **Audit pass 2 (pre-lending-mainnet):** `lending`, `lend.circom`, oracle
  binding, liquidation, refund path. (Lending is the riskiest piece; isolated.)
- Both passes split: (a) Soroban contract audit, (b) ZK circuit + setup audit —
  different specializations; do not let one firm rubber-stamp both.

## 2. Severity → remediation policy (Audit Bank aligned)
| Severity | Definition | Gate |
|----------|-----------|------|
| **Critical** | fund theft, value forgery, double-spend, proof-soundness break | **Block mainnet.** Fix + re-audit the fix. |
| **High** | privacy break, auth bypass, censorship of funds, oracle abuse | **Block mainnet.** Fix + regression test. |
| **Medium** | bounded leak, griefing, liveness degrade | Fix or formally accept with written rationale + owner + date. |
| **Low/Info** | hardening, style, defense-in-depth | Track; fix opportunistically. |

## 3. Soroban contract checklist
- [ ] No `unwrap()`/`panic!`/`expect()` on user-reachable paths; all return typed errors.
- [ ] Every privileged fn `require_auth`s the correct address (admin/operator/committee/module).
- [ ] `MODULES` ACL enforced on **all** mutating `veil_core` fns (no unguarded insert/spend/lock).
- [ ] Integer math overflow-safe (`checked_*` / widened types) — esp. LTV scaling.
- [ ] No reentrancy window: verify-then-mutate ordering; tree/nullifier updates atomic per call.
- [ ] Storage tier correct: tree/nullifiers/ciphertexts **persistent**, never temporary.
- [ ] TTL strategy: critical entries extended on touch; keeper + `bump_ttl`; restore-on-access tested.
- [ ] Per-entry size within Soroban limits (sets as per-key entries, not one giant Map value). // VERIFY
- [ ] Events emitted for every leaf insert + nullifier write (indexer correctness / PRD US-7).
- [ ] Recent-root window bounded; stale-root acceptance window justified + tested.
- [ ] Admin keys: multisig / hardware; `set_admin` two-step; no single hot key on mainnet.
- [ ] Upgrade path: module upgrade cannot silently change `veil_core` state semantics.
- [ ] Deposit path cannot bypass `asp.check_entry` (RULE 1) — proven by negative test.
- [ ] `insert_commitment` cannot run without a valid `auditor_ct` (RULE 4) — negative test.

## 4. ZK-circuit-specific checklist
- [ ] **Under-constrained signals:** every output/intermediate fully constrained
      (no free witness an attacker can choose). Top circuit-audit concern.
- [ ] **Range checks present** on all amounts (`0 ≤ x < 2^64`) — prevents field
      wraparound creating value.
- [ ] **Value conservation** (`Σin = Σout + public_amount` / batch clearing) holds
      for every swap/transfer/settle path.
- [ ] **Nullifier binding:** `nf` deterministically and uniquely derived from
      `owner_sk` + note; no malleability.
- [ ] **Public-input ordering** matches the contract's `public_inputs` vector
      exactly; documented in each circuit header; part of the vkey.
- [ ] **Poseidon params identical** in-circuit and on-chain (CAP-0075) — round
      constants, arity, field. Mismatch = silent break.
- [ ] **vkey conversion** (CIRCUITS §8) reproducible, hash-pinned, and validated
      by a "known good proof verifies / tampered proof rejects" test on-chain.
- [ ] **BN254 pairing convention** matches the CAP-0074 host fn (argument order /
      negation) — verified against developers.stellar.org, not assumed from EIP-197.
- [ ] **Non-membership soundness** (ASP blocked set) — sorted/indexed-tree gadget audited.
- [ ] **Refund/settle-or-refund circuit** cannot both refund and settle the same order.
- [ ] **Oracle public input** is bound to the on-chain freshly-read price (no stale-price proofs).

## 5. Trusted-setup / ceremony checklist
- [ ] Phase-1 source PoT documented, with provenance + hash.
- [ ] Phase-2 multi-party, ≥N independent contributors, transcripts published.
- [ ] Contribution hashes + final zkey sha256 pinned in `circuit-keys/`; CI verifies.
- [ ] Mainnet config refuses any dev/solo-generated key (hard gate).
- [ ] Per-circuit vkey on-chain matches the ceremony output (reproducible build).

## 6. Operational / key-management
- [ ] Committee threshold params (t-of-n) documented; member identities + staking.
- [ ] Auditor key custody (HSM); disclosure requests logged on-chain (event).
- [ ] ASP operator key custody; root-update attestations retained.
- [ ] Incident runbook: oracle outage, committee halt (→ refund), key compromise.
- [ ] Bug-bounty live before mainnet.

## 7. Testing-as-evidence (ties to TEST_PLAN)
- [ ] 100% of soundness-critical paths (THREAT_MODEL: dbl-spend, setup, refund,
      auth, vkey) have explicit negative tests that FAIL on a deliberately broken build.
- [ ] Fuzz/property tests on value conservation + nullifier uniqueness.
- [ ] E2E browser-proof→testnet-verify green for every milestone (TEST_PLAN cmds).
- [ ] Coverage report attached to audit handoff.

## 8. Pre-mainnet sign-off gate
Mainnet deploy requires ALL of: zero open Critical/High; mainnet trusted-setup
ceremony complete + pinned; both audit passes (contract + circuit) signed;
bug-bounty open ≥ defined window; admin/committee/auditor keys in production
custody; incident runbook approved. **No exceptions — this is institutional money.**
