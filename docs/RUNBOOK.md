# Veil Protocol Incident Runbook

## 1. Oracle Outage
**Impact:** Lending halts staleness checks; no new loans can be created until Reflector recovers. Existing loans are safe; liquidations use the last valid price within the staleness window.
**Action:** Wait for Reflector recovery. No action is needed on contracts since the staleness check protects users from stale pricing proofs. 

## 2. Committee Halt / Batch Stuck
**Impact:** `amm_pool` batch fails to settle within `BATCH_DEADLINE` ledgers.
**Action:** Submitters call `refund_order` using their `settle_or_refund` proof to reclaim notes.

## 3. Admin Key Compromise
**Impact:** Attacker could attempt to re-route protocols or register malicious modules.
**Action:** Run `propose_admin` followed by `accept_admin` from the backup multisig key to rotate the admin key. Notify security teams and stakeholders immediately.

## 4. Auditor Key Compromise
**Impact:** Future commitments could be exposed. Old ciphertexts are still decryptable with the old key, but we need to secure new commitments.
**Action:** Use `set_auditor_pubkey` to set a new HSM key. The impact scope is limited to future commitments. Disclose obligations to partners and regulators.

## 5. ASP Operator Key Compromise
**Impact:** Attacker could manipulate ASP lists or approve bad actors.
**Action:** Trigger emergency `update_blocked` to freeze the compromised credential. Initiate operator rotation process.

## 6. On-Call Contacts
| Role | Contact / Channel |
|---|---|
| Security Lead | #security-oncall |
| Engineering Lead | #eng-oncall |

# APPROVED — 2026-06-19 — Samya
