# M2 Build Plan — Shielded Withdraw + Auditor Disclosure (+ optional Relayer)

Milestone M2 exit gate: `veil e2e withdraw-and-audit --network testnet` green.
Read alongside CLAUDE.md, M0_PLAN.md + M1_PLAN.md (foundation), CIRCUITS.md (§0, §1 for the
public-amount pattern), CONTRACTS.md (§1, §5 viewkey), ARCHITECTURE.md (§2.5, §5 trust),
THREAT_MODEL.md (§1.5 network, §1.6 view-key over-disclosure), PRD.md (US-5), TEST_PLAN.md (M2).

> Builds on M0 + M1. Assumes `transfer`, real `spend`, the tree, and the auditor-ciphertext store
> are live and green.

---

## What M2 adds

| Area | Adds |
|------|------|
| Circuits | `withdraw` (spend shielded note(s) → public payout + optional change), reusing the M1 transact shape with a **non-zero `public_amount`** |
| `veil_core` | exit path: verify → spend → pay out the underlying asset to a public Stellar address (SAC `transfer`) → insert change commitment |
| Token custody | **deposit must actually custody the asset; withdraw pays it back out** (verify M0 deposit did the inbound `transfer`; if deferred, do it here) |
| Frontend | Auditor disclosure UI (decrypt in-scope note via view key); withdraw UI |
| Privacy | optional **relayer** to break payer-IP / gas linkage (THREAT_MODEL §1.5) |
| Compliance | disclosure-request event logged on-chain (CONTRACTS §5) |

---

## Resolved design decisions (new in M2)

| Decision | Choice | Reason |
|----------|--------|--------|
| Withdraw shape | reuse M1 2-in/2-out transact; `public_amount > 0` is the amount leaving the pool to a public address | One transact circuit family; withdraw = transfer with a public exit leg (SPP pattern). |
| Public recipient binding | the recipient Stellar address is **bound into the proof** as a public input (`recipient_hash`) so a relayer/observer can't redirect the payout | Prevents front-running/redirect of the withdrawn funds. |
| Token interface | **Stellar Asset Contract / SEP-41 `transfer`** for inbound (deposit) + outbound (withdraw) | Standard token movement on Soroban. // VERIFY SEP-41 client trait + SAC address for TEST-RWA |
| Deposit custody (carry-over) | confirm `veil_core.deposit` calls `token.transfer(depositor → veil_core, public_amount)`; add it if M0 deferred it | A withdraw can only pay out value the pool actually holds. |
| Auditor decryption | **off-chain**, auditor X25519 secret key; contract only serves `ciphertext_at(idx)` (CONTRACTS §5) | View-key model: contract never holds the secret; decrypt happens in the auditor tool/UI. |
| Disclosure logging | `request_disclosure(auditor, idx)` emits a `DisclosureRequested{idx}` event (no decryption on-chain) | Audit trail (SECURITY §6) without weakening privacy. |
| Relayer | **optional** off-chain service that submits the user's signed withdraw tx and pays gas | Breaks payer-IP/gas linkage only (THREAT_MODEL §1.5); network-level anonymity stays out of scope. |

---

## Hard rules in force

- **RULE 3:** withdraw spends input nullifiers via `spend()` — rejects double-spend / locked notes.
- **RULE 4:** the change commitment (if any) carries a non-empty `auditor_ct`.
- **View-key bound (THREAT_MODEL §1.6):** the auditor can decrypt **only** notes for which it is given
  the specific index/ciphertext. The key **cannot spend** (no soundness/theft power). An out-of-scope
  index must yield nothing.

---

## Phase 1 — Withdraw circuit

Blocks on: M1 `transfer.circom` (extend, don't fork).

- [ ] **T1.0** `circuits/withdraw.circom` — transact with a public exit leg.
  - Header public-input order:
    ```
    // Public inputs (in order):
    //   1. root
    //   2. nf_in_0
    //   3. nf_in_1
    //   4. cm_change          (change note back to self; dummy if none)
    //   5. public_amount      (amount withdrawn to the public recipient, > 0)
    //   6. asset_id           (which asset is leaving the pool)
    //   7. recipient_hash     (Poseidon of the public recipient address; binds payout)
    ```
  - Constraints: input membership + ownership + nullifiers (as M1); `cm_change` well-formed;
    range checks; **`Σ amount_in === public_amount + amount_change`** (value conservation with a public leg);
    single asset.
- [ ] **T1.1** Compile + negative tests: over-withdraw (`public_amount > Σ in`); wrong change; tampered
    recipient_hash; wrong nullifier; public-input reorder.
- [ ] **T1.2** Dev ceremony → `vk_withdraw.json` → `VkId::Withdraw` blob; pin + `manifest.sha256`.

---

## Phase 2 — `veil_core` withdraw exit path + token custody

Blocks on: Phase 1 vk.

- [ ] **T2.0** Confirm/implement deposit custody: `deposit` does `token.transfer(depositor, self, public_amount)`
  before inserting the commitment. (If M0 already did this, just add a regression test.)
- [ ] **T2.1** `withdraw(proof, public: WithdrawPublic, recipient: Address, change_ct: Bytes)`:
  - `WithdrawPublic { root, nf_in_0, nf_in_1, cm_change, public_amount, asset_id, recipient_hash }`.
  - Assert `Poseidon(recipient) == recipient_hash` (bind payout target).
  - `root_is_known` → `verify_groth16(VkId::Withdraw, ...)`.
  - `spend(nf)` for each real input (RULE 3).
  - If `cm_change` is real: `insert_commitment(self, cm_change, change_ct)` (RULE 4).
  - `token.transfer(self, recipient, public_amount)` — pay out.
  - Emit `Withdrawn{ asset_id, public_amount }` (amount visible by necessity; parties hidden).
- [ ] **T2.2** `cargo test`: successful withdraw moves tokens + spends nf + inserts change; over-withdraw
  rejected by proof; replay nf → `AlreadySpent`; recipient mismatch → error; pool balance accounting correct.

---

## Phase 3 — Viewkey disclosure (contract + auditor tool)

Blocks on: M0 `AUDITOR_CT` store + `ciphertext_at`.

- [ ] **T3.0** `veil_core.request_disclosure(auditor, idx)` — `require_auth(auditor)`; emit
  `DisclosureRequested{ idx }`. (No decryption on-chain.)
- [ ] **T3.1** `app/src/viewkey/decrypt.ts` — `decryptNote(ct, auditorSk) -> Note` (inverse of M0 ECIES):
  ECDH with the embedded ephemeral pubkey → HKDF → ChaCha20-Poly1305 open. Returns `null` on auth-tag
  failure (out-of-scope / wrong key → nothing).
- [ ] **T3.2** `app/src/ui/AuditorPanel.tsx` — input: leaf index + auditor secret key. Fetch
  `ciphertext_at(idx)`; decrypt; display `(amount, asset_id, blinding, owner_pk)`. Trying an index whose
  ct was encrypted to a different key yields nothing (tag failure). Calls `request_disclosure` to log.

---

## Phase 4 — Withdraw UI + optional relayer

Blocks on: Phase 1 (`withdraw.wasm`/zkey), Phase 2.

- [ ] **T4.0** `app/src/prover/withdraw.ts` — build witness (select inputs, compute change), prove, serialize.
- [ ] **T4.1** `app/src/ui/WithdrawForm.tsx` — public recipient address + amount → select notes → prove →
  submit `veil_core.withdraw` (directly, or via relayer) → mark inputs spent, save change note.
- [ ] **T4.2** *(optional)* `relayer/` — minimal Node service: accepts a signed withdraw tx, submits it,
  pays the fee. Stateless, untrusted (THREAT_MODEL §1.5/F: convenience only, re-verifiable on-chain).
  Document that it sees the public payout but not the shielded inputs.

---

## Phase 5 — Deploy + E2E

- [ ] **T5.0** Upgrade `veil_core` on testnet with withdraw + disclosure; load `VkId::Withdraw`.
- [ ] **T5.1** `e2e-tests/src/withdraw-and-audit.test.ts` — assertions per TEST_PLAN M2:
  1. **Withdraw** to a public address succeeds; tokens land at the recipient; change note returns to sender.
  2. **Auditor decrypts exactly the in-scope note**: given the deposited note's index, the auditor recovers
     `(amount, asset, …)`.
  3. **Out-of-scope yields nothing**: auditor key on an index encrypted to a different recipient → null.
  4. Disclosure request emits the `DisclosureRequested` event.
  ```
  veil e2e withdraw-and-audit --network testnet
  ```

---

## Dependency graph

```
M0+M1 (green) ─► T1.0 ─► T1.1 ─► T1.2
                                   │
                                   ▼
                        T2.0 ─► T2.1 ─► T2.2
T3.0 ─► T3.1 ─► T3.2   (viewkey path; parallel, depends only on M0 ct store)
T1.2 ─► T4.0 ─► T4.1 ─► T4.2(optional)
[all] ─► T5.0 ─► T5.1   (exit: veil e2e withdraw-and-audit green)
```

## Not in M2 (do not build)

- AMM / swap — M3
- Lending / oracle — M6
- Per-scope derived view keys / threshold auditor — roadmap hardening (THREAT_MODEL §1.6), not v1
- Network-level (Tor/mixnet) anonymity — explicitly out of scope (PRD §5)

## T1 exit (end of M2)

> Compliant deposit + shielded transfer + withdraw + auditor disclosure running e2e on testnet.
> This is a credible private-payments product on its own and the floor that must never regress
> (M0–M1 suites run on every PR — ROADMAP).

## Done check

`veil e2e withdraw-and-audit --network testnet` exits 0 with all four T5.1 assertions passing.
