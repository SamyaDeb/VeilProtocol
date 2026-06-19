# THREAT MODEL — Veil Protocol

Institutional money, compliance-bound. We enumerate attacker goals, the concrete
attack, and the mitigation. Severity is impact-if-unmitigated.

**Attacker classes:** (A) passive chain observer; (B) active user (malicious
depositor/borrower); (C) malicious/colluding committee member; (D) malicious ASP
operator; (E) compromised auditor; (F) infrastructure (indexer/relayer/RPC);
(G) protocol-logic attacker (consensus/circuit bug).

**Security goals:** (G1) no theft / no value creation (soundness); (G2) no
double-spend; (G3) confidentiality of amounts/assets/parties/balances; (G4)
unlinkability of deposits↔spends and trades↔traders; (G5) compliance integrity
(only vetted funds enter; selective lawful disclosure only); (G6) liveness.

---

## 1. Privacy leaks

### 1.1 Deposit↔spend linkage (G4) — HIGH
- **Attack (A):** correlate a deposit commitment with a later withdrawal/spend by
  amount equality, timing, or a thin anonymity set (e.g. only one note of that
  size exists).
- **Mitigations:** variable amounts + value-conservation lets users split/merge
  so spend amounts need not equal deposit amounts; nullifiers are unlinkable to
  commitments without `owner_sk`; recent-root window decouples spend timing from
  insertion; **batch auctions** mix many traders per settlement so individual
  trade timing is hidden. **Residual:** small anonymity sets early in mainnet —
  surfaced as a metric (PRD §6) and a documented user caution (avoid unique
  round-number amounts; wait for set growth). Relayer breaks payer-IP/gas linkage.

### 1.2 Amount correlation (G3/G4) — MEDIUM
- **Attack (A):** even hidden, distinctive amounts (exact, rare values) re-link
  in/out notes.
- **Mitigations:** value-splitting; encourage denomination hygiene in the wallet
  UX; batch clearing reveals only aggregate per-asset flow, not per-order amounts.
  **Residual:** out-of-band-known unique amounts; documented.

### 1.3 Oracle correlation / timing (G3) — MEDIUM (lending)
- **Attack (A):** a borrow tx reads Reflector at ledger T; observer infers the
  collateral asset from which feed was read, and bounds amounts from LTV + price.
- **Mitigations:** the oracle price is a *public* input by necessity, but
  collateral and borrow **amounts** stay hidden (range proof, CIRCUITS §4). Asset
  identity leakage is bounded: support a fixed set of oracle assets so "which feed
  was read" is low-entropy and does not single out a user. **Residual:** asset
  (not amount) of a loan may be inferable; documented as accepted for v1.

### 1.4 Batch-flow disclosure to committee (G3) — MEDIUM
- **Attack (C):** committee threshold-decrypts orders → sees individual intents.
- **Mitigations:** committee sees *intents within a batch* but binding to
  on-chain identities is limited (orders are nullifier-bound, not address-bound);
  threshold scheme requires t-of-n collusion to decrypt; committee is contractually
  bound + reputationally staked (semi-trusted, ARCHITECTURE §5). **Residual & the
  core tradeoff of the fully-shielded design:** a t-of-n colluding committee
  learns batch contents. Roadmap mitigations: larger/rotating committee,
  permissionless DKG, and research into committee-blind clearing (collaborative
  SNARK / MPC matching, Renegade-style) to remove the disclosure entirely.

### 1.5 Network-level deanonymization (G4) — OUT OF SCOPE (documented)
- **Attack (F):** IP/RPC-level correlation of submitter to tx.
- **Mitigations:** optional relayer; users advised to use Tor/VPN. Network privacy
  is explicitly out of protocol scope (PRD §5); we do not claim it.

### 1.6 View-key over-disclosure (G3/G5) — HIGH
- **Attack (E):** compromised/over-broad auditor key decrypts more than the lawful
  scope, or all notes.
- **Mitigations:** disclosure is per-commitment (auditor needs the specific
  index/ciphertext); the key cannot spend (G1 preserved). Roadmap: per-scope
  derived view keys / threshold auditor so a single key compromise ≠ global
  disclosure. **Residual:** a single global auditor key is a fat target in v1 —
  flagged for the security review and slated for key-hierarchy hardening.

---

## 2. Double-spend & nullifier integrity (G2) — CRITICAL

- **Attack (B):** spend the same note twice; or swap a note already locked as
  collateral; or re-use a nullifier across modules.
- **Mitigations (RULE 3):** `veil_core` holds the *single* authoritative `SPENT`
  and `LOCKED` sets shared by all modules. `spend`/`lock` reject if the nullifier
  is in **either** set. Nullifiers are owner-bound and deterministic (CIRCUITS
  §0), so the same note always yields the same `nf`. No module keeps its own
  nullifier set. **Test:** double-spend, lock-then-swap, and swap-then-lock are
  explicit negative e2e cases (TEST_PLAN).
- **Subtlety:** the "not in set" check is on-chain, not in-circuit (sets are large
  + mutable). Safe because the circuit binds `nf` to ownership; the contract is
  the authority on set membership at execution time. A reorg cannot un-spend
  because Stellar has fast finality (no deep reorgs). // VERIFY finality assumption

---

## 3. Trusted-setup risk (G1) — CRITICAL

- **Attack (G/C):** if Phase-2 toxic waste is known to anyone, they can forge
  proofs → mint value from nothing, undetectably.
- **Mitigations:** Phase-1 reuses a large, well-witnessed perpetual Powers-of-Tau;
  **Phase-2 is our own per-circuit ceremony**, multi-party before mainnet, so
  soundness holds if ≥1 contributor was honest. All keys + contribution
  transcripts + sha256 pinned in `circuit-keys/`. Testnet may use solo/dev keys
  **only behind a hard gate** that blocks them from mainnet config (PRD/ROADMAP).
  **Residual:** ceremony social-trust assumption — disclosed in SCF_PROPOSAL and
  SECURITY; mainnet ceremony is a public, auditable event.
- **Related:** vkey-conversion bug (CIRCUITS §8) could make the on-chain verifier
  accept malformed proofs → treated as a Critical audit item; conversion output
  is reproducible + hash-checked + covered by a verify-known-proof test.

---

## 4. ASP centralization / censorship (G5/G6) — HIGH

- **Attack (D):** ASP operator wrongfully blocks a legitimate user (censorship),
  approves a sanctioned entity (compliance failure), or sets a malicious root.
- **Mitigations:** ASP can gate *entry* but **cannot touch existing notes, spend,
  or de-anonymize** (ARCHITECTURE §5). Root updates are operator-`require_auth`ed
  and event-logged with attestations; `ROOT_HISTORY` makes changes auditable.
  Approved/blocked roots are public so wrongful blocks are externally detectable.
  **Residual:** single-operator trust in v1 — documented; roadmap adds
  multi-operator / governance and an appeal path. ASP compromise is a compliance/
  liveness risk, never a fund-safety risk.

---

## 5. Oracle manipulation (G1, lending) — HIGH

- **Attack (A/B):** push a manipulated Reflector price to over-borrow or trigger
  unfair liquidation.
- **Mitigations:** staleness check (`STALENESS`), proof's `oracle_price` public
  input must equal the freshly-read on-chain price (CONTRACTS §4), fixed
  conservative `LTV_MAX_BPS` with margin, and reliance on Reflector's own
  aggregation/consensus (audited, REFERENCES). Roadmap: dual-oracle
  (Reflector+RedStone) median + deviation circuit-breaker. **Residual:** trust in
  the oracle's aggregation; bounded by conservative LTV.

---

## 6. Committee liveness / griefing (G6) — MEDIUM

- **Attack (C/F):** committee refuses to settle → orders stuck, funds locked in
  spent-but-unsettled limbo.
- **Mitigations:** orders nullify the input only on submit, but outputs only exist
  post-settle → need a **timeout/refund path**: if a batch is not settled within
  a window, submitters can reclaim via a refund proof that re-mints the input
  note (un-spend via a settle-or-refund circuit). Committee is reputationally
  staked. **Residual:** liveness depends on ≥ t honest committee members online;
  mitigated by committee size/rotation. **This refund path is itself a soundness-
  sensitive circuit and a top audit item.**

---

## 7. Cross-contract / auth abuse (G1) — HIGH

- **Attack (B/G):** a fake "module" calls `veil_core.insert_commitment`/`spend`
  to mint or burn notes.
- **Mitigations:** `MODULES` ACL + `require_auth` on every privileged core fn
  (CONTRACTS §6); only registered module addresses with explicit `Perms` may
  mutate. `register_module` is admin-gated. Reentrancy: core mutations are
  ordered (verify → state change) and modules cannot recursively re-enter a
  half-updated tree. **Test:** unauthorized-caller negative tests on every
  mutating core fn.

---

## 8. Frontend / key management (G3) — MEDIUM

- **Attack (F):** localStorage note theft, malicious frontend, phishing.
- **Mitigations:** notes encrypted at rest; deterministic note recovery from
  `owner_sk` so loss of localStorage ≠ loss of funds (re-scan tree); reproducible
  frontend build; Freighter for signing (keys never in page). **Residual:** user
  device security; documented.

---

## 9. Summary matrix

| # | Threat | Class | Sev | Soundness? | Status |
|---|--------|-------|-----|-----------|--------|
| 1.1 | deposit↔spend linkage | A | High | No | mitigated + residual |
| 1.3 | oracle correlation | A | Med | No | bounded |
| 1.4 | committee sees batch | C | Med | No | core tradeoff; roadmap |
| 1.6 | view-key over-disclosure | E | High | No | v1 residual; harden |
| 2 | double-spend | B | Crit | **Yes** | mitigated (RULE 3) |
| 3 | trusted setup | G/C | Crit | **Yes** | ceremony + pinning |
| 4 | ASP censorship | D | High | No | governance roadmap |
| 5 | oracle manipulation | A/B | High | partial | staleness+bind+LTV |
| 6 | committee liveness | C/F | Med | refund=Yes | refund path (audit) |
| 7 | auth abuse | B/G | High | **Yes** | ACL + require_auth |
| 8 | frontend/keys | F | Med | No | encrypt + recovery |

**Soundness-critical (must be zero-defect at mainnet):** 2, 3, 6 (refund), 7,
and the vkey-conversion path. These drive the SECURITY checklist.
