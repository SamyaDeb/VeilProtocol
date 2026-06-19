# TEST PLAN — Veil Protocol

Three layers, plus one **binding verification command per milestone** that proves
the slice works end-to-end. A milestone is "done" only when its command is green
on testnet. Commands are illustrative skeletons — exact CLI/script names are
pinned as they land (`// VERIFY` against tooling), but the *assertion each makes*
is fixed.

## 1. Unit tests

### 1a. Circuit unit tests (per circuit)
- **Witness generation:** valid inputs produce a witness; the circuit is
  satisfiable. `circom_tester` / snarkjs witness calc.
- **Constraint count + structure:** snapshot `--r1cs` info; alert on drift.
- **Negative (must FAIL to satisfy):** out-of-range amount; broken value
  conservation; wrong nullifier; tampered Merkle path; non-membership violated;
  LTV exceeded; mismatched public-input order.
- **Cross-check:** snarkjs off-chain `verify` accepts a real proof, rejects a
  byte-flipped proof.
- Circuits: `deposit, transfer/transact, withdraw, swap, batch_settle, lend,
  kyc_credential, settle-or-refund`.

### 1b. Contract unit tests (per crate, `cargo test`)
- `veil_core`: insert increments index + updates root; `spend` rejects if in
  `SPENT`∨`LOCKED`; `lock` rejects same; `unlock` requires `LOCKED`;
  `insert_commitment` rejects empty `auditor_ct` (RULE 4) and unregistered caller;
  recent-root window behavior; TTL extend on touch (`get_ttl` assertions).
- `asp`: `check_entry` accepts approved+non-blocked, rejects otherwise; root
  update auth; `ROOT_HISTORY` tolerance.
- `amm_pool`: `submit_order` spends nullifier + stores order; `settle_batch`
  rejects non-committee, rejects bad proof, inserts outputs w/ ciphertext;
  reserve-mismatch rejected; refund after timeout.
- `lending`: LTV math overflow-safe; stale-oracle rejected; `oracle_price` public
  input must equal freshly-read price; `open_loan` locks, `repay` unlocks+spends;
  `liquidate` only when unhealthy.
- **Property/fuzz:** value conservation and nullifier uniqueness under random
  inputs.

## 2. Integration tests (cross-contract, in Soroban test env)
- Deposit calls `asp.check_entry` and **fails closed** when ASP rejects (RULE 1).
- Module→`veil_core` auth: a fake module address cannot `insert`/`spend`/`lock`.
- `open_loan` → `lock`; attempt to `swap` the locked note → rejected (RULE 3);
  `repay` → `unlock` → note now swappable.
- Swap-output note used as lending collateral with no conversion (RULE 2).
- `settle_batch` inserts every output with a paired `auditor_ct` (RULE 4).

## 3. End-to-end (browser proof → testnet verify)
Full stack: build witness in-browser (WASM) → snarkjs prove → submit via
Freighter → on-chain BN254 verify → indexer observes → wallet recovers notes.
Run against Stellar **testnet**; assert on-chain state + indexer state agree.

---

## 4. Per-milestone verification commands (the binding gate)

> Convention: `veil e2e <suite> --network testnet` runs the browser-driven suite
> headless and exits non-zero on any failed assertion. Each suite encodes the ACs
> below. // VERIFY harness/runner name when e2e/ lands.

### M0 — compliant deposit
```
veil e2e deposit --network testnet
```
Asserts: non-approved deposit REJECTED on-chain; approved deposit inserts a leaf;
stored `auditor_ct` decrypts with the auditor key to the original note;
indexer-reconstructed root == `veil_core.current_root`. (RULE 1, RULE 4, US-1, US-7)

### M1 — shielded transfer
```
veil e2e transfer --network testnet
```
Asserts: A→B transfer hides amount/parties; recipient recovers the output note;
replaying the same nullifier is REJECTED (double-spend). (RULE 3 spent, US-2.)

### M2 — withdraw + auditor disclosure
```
veil e2e withdraw-and-audit --network testnet
```
Asserts: withdraw to a public address succeeds; auditor decrypts exactly the
in-scope note; auditor key on an out-of-scope index yields nothing. (US-5.)

### M3 — AMM de-risk spike (K=4, mock committee)
```
veil e2e amm-spike --network testnet --batch-size 4
```
Asserts: 4 encrypted orders submitted; 2-of-3 committee threshold-decrypts and
posts a value-preserving `settle_batch` that verifies on-chain; traders recover
outputs; a withheld settlement triggers a successful refund. (THREAT_MODEL §6.)

### M4 — encrypted-reserve clearing
```
veil e2e amm-settle --network testnet
```
Asserts: multi-order batch clears at one price; reserves update consistently and
remain encrypted on-chain; `min_out` honored (violating order excluded).

### M5 — shielded LP + portability
```
veil e2e amm-lp --network testnet
```
Asserts: LP add/remove with hidden size; pro-rata fee accrual provable to LP; a
Module-1 swap-output note opens a position with no conversion. (RULE 2, US-4, US-6.)

### M6 — private lending
```
veil e2e lending --network testnet
```
Asserts: borrow within LTV (amounts hidden) succeeds; over-LTV REJECTED by the
circuit; locked collateral cannot be swapped (RULE 3 locked); repay releases it;
stale oracle REJECTED; unhealthy loan liquidatable. (US-3.)

### M7 — ceremony + audit gate
```
veil verify-keys && veil e2e tampered-proof-rejected --network testnet
```
Asserts: pinned `circuit-keys/` sha256 match ceremony output; a deliberately
tampered proof is REJECTED on-chain; SECURITY §8 checklist all checked.

### M8 — mainnet smoke (BENJI + Reflector)
```
veil e2e mainnet-roundtrip --network mainnet --asset BENJI
```
Asserts: ASP-gated BENJI deposit → private swap → private withdraw round-trip on
mainnet; Reflector feed read + bound in any lending op; monitoring + anonymity-set
metric reporting.

---

## 5. Regression & soundness guarantees
- **Negative-test build:** a CI job builds a deliberately broken variant (e.g.
  nullifier check removed) and asserts the soundness negative tests FAIL there —
  proving the tests actually have teeth. (SECURITY §7.)
- T1 suites (M0–M1) run on every PR — the compliant-pool floor never regresses.
- Coverage report generated each milestone; attached to audit handoff.
- Each `// VERIFY` in CONTRACTS/CIRCUITS has a corresponding test or an open issue
  before its milestone closes.
