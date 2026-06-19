# M8 Build Plan — Mainnet Launch with BENJI + Reflector

**Goal:** Flip testnet → mainnet. M7 made the codebase production-equivalent; M8
runs the external processes (ceremony, audit, bug bounty) and deploys behind the
SECURITY §8 gate. The only new code is the mainnet deploy script, the mainnet smoke
e2e, and any audit-finding remediations.

Hard precondition: every box in the M7 exit gate is checked.

Exit gate: `veil e2e mainnet-roundtrip --network mainnet --asset BENJI` green.

Read alongside: CLAUDE.md, M7_PLAN.md (all boxes checked first), SECURITY.md §8,
ROADMAP.md M8, TEST_PLAN.md M8, REFERENCES.md (Reflector mainnet, BENJI).

---

## What M8 delivers

| Area | Deliverable |
|------|-------------|
| Ceremony | Multi-party Phase-2 for every production circuit; transcripts + ceremony keys pinned |
| Audit | Two independent audit passes (contract + circuit/setup); all Critical/High remediated |
| Bug bounty | Funded pool live ≥ defined window before mainnet broadcast |
| Deploy | All contracts to mainnet behind the SECURITY §8 gate assertion |
| Smoke | ASP-gated BENJI deposit → private swap → private withdraw on mainnet |

---

## Phase 1 — Multi-party Phase-2 ceremony

Blocks on: all circuits frozen (M7 Phase 1 complete — no R1CS changes after this).

### 1A. Ceremony execution (human contributors, external)

Circuits requiring a ceremony key:
`deposit`, `kyc_credential`, `transfer`, `withdraw`, `swap`, `batch_settle`,
`lend`, `settle_or_refund`, `repay`, (optionally `liquidate` if circuit was built).

For each circuit:
1. Start from Phase-1 Powers-of-Tau (`pot17.ptau` or larger if constraint count requires)
2. Run `tools/ceremony-cli` with ≥N independent contributors; collect each contribution hash
3. Verify the contribution chain: `snarkjs zkey verify <circuit>.r1cs pot.ptau <final>.zkey`
4. Export `vk_<circuit>.json`; run `tools/vk-convert` → `vk_<circuit>.bin`
5. Record: `sha256(final.zkey)`, `sha256(vk.bin)`, all contribution hashes → `circuit-keys/ceremony-transcript.txt`

### 1B. Update `circuit-keys/manifest.sha256` with ceremony outputs

Move ceremony keys into `circuit-keys/prod/` (distinct from `circuit-keys/dev/`).
Update `manifest.sha256` to point to `prod/` entries. The mainnet key gate added in
M7 Phase 3C will refuse any key whose hash matches a `dev/` entry.

Run `vk-verify` (no network): must exit 0.

### 1C. Re-initialize on-chain VK storage with ceremony keys

Re-run `deployments/m8-deploy.sh` (see Phase 2) which calls `veil_core.init_vk` for
each circuit using the ceremony `vk.bin`. This replaces the dev keys that were loaded
during testnet runs.

---

## Phase 2 — Gated mainnet deploy script

### 2A. `deployments/m8-deploy.sh`

The deploy script that executes the mainnet broadcast. It enforces the SECURITY §8
gate before any transaction is sent:

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# ── SECURITY §8 gate (no exceptions) ─────────────────────────────────────────
echo "=== Asserting SECURITY §8 gate ==="

# 1. Ceremony keys in place and verified
vk-verify --manifest circuit-keys/manifest.sha256 || { echo "FATAL: manifest mismatch"; exit 1; }

# 2. No dev keys in prod path
for f in circuit-keys/prod/*.bin; do
    h=$(sha256sum "$f" | awk '{print $1}')
    if grep -q "$h" circuit-keys/dev/*.bin 2>/dev/null; then
        echo "FATAL: $f matches a dev key. Ceremony required."; exit 1
    fi
done

# 3. Signed audit artifacts present
[ -f "audits/pass1-signed.pdf" ]    || { echo "FATAL: audit pass 1 missing"; exit 1; }
[ -f "audits/pass2-signed.pdf" ]    || { echo "FATAL: audit pass 2 missing"; exit 1; }

# 4. Bug bounty confirmation
[ "${BUG_BOUNTY_OPEN:-}" = "yes" ]  || { echo "FATAL: set BUG_BOUNTY_OPEN=yes"; exit 1; }

# 5. Production key custody confirmed
[ "${ADMIN_MULTISIG:-}" = "yes" ]   || { echo "FATAL: set ADMIN_MULTISIG=yes"; exit 1; }
[ "${AUDITOR_HSM:-}" = "yes" ]      || { echo "FATAL: set AUDITOR_HSM=yes"; exit 1; }

# 6. Incident runbook approved
[ -f "docs/RUNBOOK.md" ]            || { echo "FATAL: incident runbook missing"; exit 1; }
grep -q "APPROVED" docs/RUNBOOK.md  || { echo "FATAL: runbook not approved"; exit 1; }

echo "=== Gate passed. Deploying to mainnet ==="

# ── Deploy ────────────────────────────────────────────────────────────────────
NETWORK=mainnet
PASSPHRASE="Public Global Stellar Network ; September 2015"
# ... (same deploy flow as m6-deploy.sh but pointing at mainnet.json config)
```

### 2B. Deploy and initialize all contracts to mainnet

Same sequence as `m6-deploy.sh`:
1. Deploy `veil_core`, `asp`, `amm_pool`, `lending`
2. Initialize with mainnet config from `deployments/mainnet.json`
3. Load ceremony vkeys via `init_vk` for each circuit
4. Register modules + committee; set auditor pubkey (HSM-held)
5. Initialize ASP approved/blocked roots from the production compliance set
6. Record all mainnet contract ids in `deployments/mainnet.json`

---

## Phase 3 — Audit passes + remediation

Blocks on: Phase 1 (audited code uses ceremony keys); M7 Phase 3A/3B (tooling ready).

### 3A. Audit pass 1 — Soroban contracts + M1/M3 circuits (external firm)

Scope: `veil_core`, `asp`, `amm_pool`, `circuits/{deposit,transfer,withdraw,swap,batch_settle,settle_or_refund,kyc_credential}` + trusted setup review.

Hand off: coverage report, SECURITY §3 contract checklist self-assessment, SECURITY §4
circuit checklist self-assessment, ceremony transcripts, all `// VERIFY` closed.

### 3B. Audit pass 2 — Lending + repay + liquidation (separate firm or isolated pass)

Scope: `lending`, `circuits/{lend,repay,liquidate}`, oracle binding, liquidation path.
This is the riskiest isolated module (SECURITY §1).

### 3C. Remediation (code work when findings arrive)

For each Critical/High finding:
- Fix in code
- Add a regression test that would have caught it
- Update the relevant SECURITY checklist item

Track Medium findings with owner + target date. Log all findings in `audits/findings.md`.

---

## Phase 4 — Bug bounty

Blocks on: Phase 3.

Launch a funded bug bounty pool (e.g. Immunefi or similar). Define scope (all contracts
+ circuits + the vkey-conversion path). The pool must be live for at least the defined
window before mainnet broadcast. Set `BUG_BOUNTY_OPEN=yes` in the gate env once live.

---

## Phase 5 — Mainnet smoke E2E

### 5A. `e2e-tests/src/mainnet-roundtrip.test.js`

Full stack on mainnet with BENJI:

```javascript
// T4.0 assertions (TEST_PLAN M8):
// 1. ASP-gated BENJI deposit succeeds; non-approved address rejected
// 2. Private swap of the deposited BENJI note (trader/size hidden on-chain)
// 3. Private withdraw back to a public address (round-trip complete)
// 4. Reflector mainnet feed read and oracle_price bound in any lending op
// 5. /anonymity-set metric increments after the deposit
```

Add to `e2e-tests/package.json`:
```json
"mainnet-roundtrip": "node src/mainnet-roundtrip.test.js"
```

Run as: `source deployments/mainnet.json && npm run mainnet-roundtrip --prefix e2e-tests`

---

## Phase 6 — Incident runbook (`docs/RUNBOOK.md`)

Write and get approved before mainnet broadcast (required by gate assertion). Sections:

1. **Oracle outage** — lending halts staleness checks; no new loans until Reflector recovers;
   existing loans are safe; liquidations use last valid price within window.
2. **Committee halt** — if a batch is not settled within `BATCH_DEADLINE` ledgers,
   submitters call `refund_order` with their `settle_or_refund` proof to reclaim notes.
3. **Key compromise** — admin: run `propose_admin` → `accept_admin` from the backup
   multisig key. Auditor: rotate `set_auditor_pubkey`; old ciphertexts remain decryptable
   with old key; new commitments use the new key. ASP operator: `update_blocked` to
   quarantine any affected credential immediately.
4. **On-call contacts and escalation path.**
5. Sign off with `# APPROVED — <date> — <name>` at the end of the file.

---

## Exit gate (SECURITY §8 — no exceptions)

- [ ] `vk-verify --manifest circuit-keys/manifest.sha256` exits 0 (ceremony keys on disk)
- [ ] Zero open Critical/High (both audit passes signed, in `audits/`)
- [ ] Bug bounty open ≥ defined window (`BUG_BOUNTY_OPEN=yes`)
- [ ] Admin keys in production multisig (`ADMIN_MULTISIG=yes`)
- [ ] Auditor key in HSM (`AUDITOR_HSM=yes`)
- [ ] `docs/RUNBOOK.md` contains `# APPROVED`
- [ ] `veil e2e tampered-proof-rejected --network testnet` green (M7 carried forward)
- [ ] `veil e2e mainnet-roundtrip --network mainnet --asset BENJI` green

---

## Dependency graph

```
M7 complete ──► 1A ceremony ──► 1B manifest update ──► 1C reload VKs on-chain
                                                         │
                                          3A audit pass 1 ──► 3C remediation
                                          3B audit pass 2 ──► 3C remediation
                                          4  bug bounty
                                          2A gate script ──► 2B mainnet deploy
                                          6  runbook
                                          [all] ──► 5A mainnet smoke ──► EXIT
```

## Not in M8 (out of scope — PRD §5)

- Cross-chain / bridge privacy
- Network-level (IP) anonymity
- Mobile apps, fiat on/off-ramp, governance token
- Permissionless committee / ASP governance (post-grant R&D)
- New product modules beyond M0–M6

## Done check

`veil e2e mainnet-roundtrip --network mainnet --asset BENJI` exits 0 with all five
T5A assertions passing. The full program is delivered.
