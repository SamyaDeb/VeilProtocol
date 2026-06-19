# M7 Build Plan — Testnet → Mainnet-Ready Hardening

**Goal:** Run on testnet in production-equivalent configuration so that mainnet launch
(M8) is a config switch, not a code change. Every soundness hole is closed, every
`// VERIFY: before mainnet` comment is resolved, admin safety is hardened, tooling
gates the deploy, and the asset/oracle wiring is real.

Exit gate: `veil verify-keys && veil e2e tampered-proof-rejected --network testnet`
green, BENJI asset_id pinned, Reflector mainnet feed confirmed, anonymity-set metric
live in indexer.

Read alongside: CLAUDE.md, SECURITY.md §3–§8, THREAT_MODEL.md §2/§3/§5/§6/§7,
CIRCUITS.md §7–§8, CONTRACTS.md §1 TTL, ROADMAP.md M7.

---

## Outstanding `// VERIFY` comments resolved by this milestone

| File | Comment | Resolution |
|------|---------|------------|
| `amm_pool/src/lib.rs:120` | replace `refund_order` address-auth with settle-or-refund circuit | Phase 1 |
| `amm_pool/src/lib.rs:109` | CAP-0074 G1 scalar-mul for real Groth16 verify | Phase 3 (tampered-proof e2e confirms the host fn works) |
| `lending/src/lib.rs:292` | repay circuit with exact-value enforcement | Phase 1 |
| `lending/src/lib.rs:379` | ZK liquidation proof | Phase 1 |
| `veil_core/src/lib.rs:275` | token Client transfer fn | Phase 4 (confirmed against SDK when wiring BENJI SAC) |
| `lending/src/lib.rs:165` | Reflector lastprice signature | Phase 4 (confirmed against mainnet contract) |

---

## Phase 1 — Close soundness holes (CRITICAL — block mainnet)

These are the only remaining soundness gaps per THREAT_MODEL §9. Everything else is
hardening. Do these first.

### 1A. `circuits/settle_or_refund.circom`

THREAT_MODEL §6 flags "refund=Yes" as soundness-critical. The current `refund_order`
authorises with a Stellar address — a circuit must do it.

**Circuit:** proves the refunder owns the original input note (same `owner_sk` → `nf`
derivation as the swap circuit) AND that the same order has not already settled
(settled flag is a public input bound to the batch).

Public inputs (in order):
1. `batch_id` — ties the refund to the exact batch
2. `nf_in` — nullifier of the original input note (was spent on submit; re-minted on refund)
3. `cm_refund` — output commitment (the re-minted note)
4. `root` — Merkle root the original note was proven in
5. `batch_deadline` — ledger sequence after which refund is allowed

Private inputs: `(amount, asset_id, blinding, owner_sk, leaf_index, path[32], idx[32])`,
`out_blinding`, `out_owner_pk`.

Constraints:
- `MerkleTreeChecker(cm_in, path, idx) === root`
- `Nullifier(owner_sk, leaf_index, cm_in) === nf_in`
- `CommitmentHasher(amount, asset_id, out_blinding, out_owner_pk) === cm_refund`
- `amount` in range `[0, 2^64)`

**Contract update (`amm_pool.refund_order`):**
- Replace Stellar-address auth with: `core.verify_groth16(VkId::SettleOrRefund, proof, [batch_id, nf_in, cm_refund, root, batch_deadline])`
- Add `VkId::SettleOrRefund` to veil_core's VkId enum (and the mirror in amm_pool)
- Negative test: same order cannot both settle AND refund (settle writes `BSET_PFX`; refund checks it; refund writes `REFD_PFX`; second refund rejected)

**Witness test (`circuits/test_settle_or_refund_witness.mjs`):**
- Valid refund proof for an unsettled batch passes
- Settled batch → `batch_id` mismatch rejected
- Wrong `owner_sk` → wrong `nf_in` rejected
- `cm_refund` mismatch rejected

**Ceremony:** run `snarkjs groth16 setup` → contribute → export vk → `vk-convert` → pin
in `circuit-keys/dev/`; add to `manifest.sha256`.

---

### 1B. Lending repay circuit (`circuits/repay.circom`)

Current `lending.repay` accepts any `repay_nf` without proving the amount matches the
borrow. Before mainnet the repay note must be the exact borrow note (same `borrow_cm`
that was committed at loan open).

**Circuit:** proves the repayer owns a note whose commitment equals the stored `borrow_cm`.

Public inputs (in order):
1. `root` — current Merkle root
2. `repay_nf` — nullifier of the repay note (→ spent set)
3. `borrow_cm` — the commitment stored in the LoanRec (public, on-chain)

Private inputs: `(amount, asset_id, blinding, owner_sk, leaf_index, path[32], idx[32])`.

Constraints:
- `CommitmentHasher(amount, asset_id, blinding, Poseidon(owner_sk)) === borrow_cm`
- `MerkleTreeChecker(borrow_cm, path, idx) === root`
- `Nullifier(owner_sk, leaf_index, borrow_cm) === repay_nf`
- `amount` in range `[0, 2^64)`

**Contract update (`lending.repay`):**
- Replace dummy-proof path with: `core.verify_groth16(VkId::Repay, proof, [root, repay_nf, borrow_cm])`
- Add `VkId::Repay` to veil_core and lending's VkId mirror
- Assert `root_is_known(root)` before verify
- Negative test: wrong `borrow_cm` (different loan) rejected

**Witness test (`circuits/test_repay_witness.mjs`):**
- Valid repay (correct borrow note) passes
- Wrong `owner_sk` rejected
- Wrong `borrow_cm` rejected
- Tampered Merkle path rejected

**Ceremony:** same as 1A.

---

### 1C. Liquidation ZK proof (`circuits/liquidate.circom`)

Current `lending.liquidate` computes undercollateralization from stored prices with no
ZK enforcement — the liquidator could manipulate inputs. For mainnet, the contract
passes the freshly-read oracle price as a public input and verifies a proof that
`current_price × borrow_amount > ltv_max_bps × collat_amount × oracle_price_at_open`.

But this requires knowing private amounts. **Simplified mainnet approach:** prove the
stored `LoanRec.open_oracle_price` and `ltv_max_bps` are consistent with the borrow_cm
on-chain; the health check itself stays in the contract using public `oracle_price`.
The circuit's job is only to verify the liquidator knows the borrow note (they hold
the cm) and the loan is for that cm.

Public inputs: `borrow_cm`, `loan_id` (as field element), `current_price`.

Private inputs: the borrow note fields that hash to `borrow_cm`.

Constraints:
- `CommitmentHasher(borrow_amount, borrow_asset, blinding, owner_pk) === borrow_cm`
- `borrow_amount` in range

The health-check arithmetic (`current_price × 10_000 < open_oracle_price × ltv_max_bps`)
stays on-chain in the contract (reading from `LoanRec`) — this is acceptable because
both prices are public and the range check is done correctly.

**If the liquidation circuit adds more complexity than value** (the health check is
already fully on-chain with public prices), it is acceptable to keep the current
approach with a clear comment documenting why, and close the `// VERIFY` with that
rationale. Decide during implementation and document the choice.

---

## Phase 2 — Contract admin hardening

### 2A. `set_admin` two-step in `veil_core`

Replace the one-call `set_admin` with a propose + accept pattern (SECURITY §3, M8
key-custody requirement).

```rust
// Propose: current admin signs; stores pending_admin in instance storage
fn propose_admin(env, admin: Address, new_admin: Address) -> Result<(), VeilError>

// Accept: new_admin signs; promotes pending → current; clears pending
fn accept_admin(env, new_admin: Address) -> Result<(), VeilError>
```

Storage key: `PENDING_ADMIN` in instance storage.

Negative tests:
- `accept_admin` by anyone other than `PENDING_ADMIN` → `Unauthorized`
- `propose_admin` by non-admin → `Unauthorized`
- Double-propose overwrites (last propose wins — safe since admin must still sign)

### 2B. `bump_ttl` keeper function in `veil_core`

Add an admin-callable function to re-extend TTL on specific persistent entries before
archival (CONTRACTS §1 TTL strategy). Without this, the protocol has no on-call
mechanism to rescue cold-but-critical tree nodes or nullifier entries.

```rust
// Extends TTL on a list of storage keys (any tier) to the high threshold.
// admin must require_auth. Called by the keeper job or on-call.
fn bump_ttl(env, admin: Address, keys: Vec<Val>) -> Result<(), VeilError>
```

The function iterates `keys`, calls `env.storage().persistent().extend_ttl(key, low, high)`
for each, and emits a `(symbol_short!("bump_ttl"), keys.len())` event for monitoring.

Test: insert a leaf, set ledger sequence forward past the medium threshold, call
`bump_ttl`, assert `get_ttl` returns a value near the high threshold.

---

## Phase 3 — CI/tooling gate

### 3A. `tools/vk-verify/` CLI

A small Rust binary (`tools/vk-verify/src/main.rs`) that:
1. Reads `circuit-keys/manifest.sha256`
2. For each entry, computes `sha256(file)` and asserts it matches
3. Optionally connects to a Soroban RPC and reads the on-chain `VK` for each circuit,
   comparing the bytes to the pinned `.bin`

```
Usage: vk-verify [--network testnet|mainnet] [--rpc <url>] [--core <contract-id>]
       vk-verify          # disk-only manifest check (no network)
       vk-verify --network testnet ...  # disk + on-chain check
```

Exit 0 = all match. Exit 1 = mismatch, prints which files differ.

This is the `veil verify-keys` command referenced in the M7 exit gate.

### 3B. `e2e-tests/src/tampered-proof-rejected.test.js`

For each circuit (Deposit, Transfer, Withdraw, Swap, BatchSettle, Lend, SettleOrRefund,
Repay): take a valid proof generated off-chain, byte-flip `proof.pi_a[0][0]` by +1,
submit to `veil_core.verify_groth16(vk_id, tampered_proof, valid_public_inputs)` via
simulation, assert the result is `false` (not an error — the verifier returns bool).

```
npm run tampered-proof-rejected --prefix e2e-tests
```

Add script to `e2e-tests/package.json`:
```json
"tampered-proof-rejected": "node src/tampered-proof-rejected.test.js"
```

### 3C. Mainnet key gate in deploy scripts

In `deployments/m8-deploy.sh` (the mainnet deploy script written in M8), add a
pre-flight assertion block:

```bash
# --- Mainnet key gate ---
# Refuse any vk whose sha256 matches a dev key (dev hashes are in circuit-keys/dev/)
assert_not_dev_key() {
    local bin_file="$1"
    local actual_hash; actual_hash=$(sha256sum "$bin_file" | awk '{print $1}')
    if grep -q "$actual_hash" circuit-keys/dev/*.bin 2>/dev/null; then
        echo "FATAL: $bin_file matches a dev key. Run the multi-party ceremony first."
        exit 1
    fi
}
for f in circuit-keys/prod/*.bin; do assert_not_dev_key "$f"; done
```

This gate runs before any `stellar contract invoke` and calls `vk-verify --network mainnet`.

Also add to `deployments/m7-testnet-prod-sim.sh` a softer version that checks
testnet keys are ceremony-generated (not solo dev keys from this session).

---

## Phase 4 — Asset/oracle wiring

### 4A. BENJI asset_id + `deployments/mainnet.json`

Compute `asset_id = Poseidon(issuer_field, code_field)` for BENJI:
- `issuer_field` = the BENJI issuer Stellar address encoded as a field element
  (use the same encoding as `owner_pk` — big-endian bytes mod BN254 scalar field)
- `code_field` = `"BENJI"` encoded as a field element (ASCII bytes as big-endian u64)

Pin the result in `deployments/mainnet.json`:
```json
{
  "network": "mainnet",
  "passphrase": "Public Global Stellar Network ; September 2015",
  "rpc": "https://soroban-mainnet.stellar.org",
  "assets": {
    "BENJI": {
      "asset_id": "<poseidon-result-hex>",
      "sac": "<BENJI-SAC-contract-id>",
      "issuer": "<G...>",
      "reflector_feed": "BENJI/USD"
    },
    "TEST_RWA": {
      "asset_id": "0x...",
      "sac": "<testnet-TEST-RWA-SAC>",
      "reflector_feed": null
    }
  },
  "reflector": "<mainnet-Reflector-contract-id>",
  "ltv_max_bps": 7500,
  "staleness": 3600
}
```

// VERIFY: BENJI SAC contract id against Franklin Templeton issuer on mainnet; confirm
Reflector mainnet contract id from REFERENCES.md (reflector-network docs).

### 4B. Reflector oracle mainnet verification

Before `deployments/mainnet.json` is pinned, confirm:
1. The mainnet Reflector contract id (from REFERENCES.md / reflector-network repo)
2. A BENJI price feed exists and returns a valid `PriceData` (simulate `lastprice` via RPC)
3. The SEP-40 `Asset` enum shape matches the `lending` contract's `Asset` type

Add a one-off `tools/scripts/verify-reflector.sh`:
```bash
# Simulates lastprice for BENJI on mainnet and prints price + timestamp
stellar contract invoke \
    --network mainnet --id "$REFLECTOR" -- \
    lastprice --asset '{"Other":"BENJI"}' 2>&1
```

If the feed is unavailable, document the fallback (use XLM/USD as collateral feed for
the first mainnet batch; BENJI feed goes live when Reflector adds it).

---

## Phase 5 — Anonymity-set metric (indexer)

### 5A. Indexer `/anonymity-set` endpoint

In `indexer/` (Node.js), add a route that returns:
```json
{
  "commitment_count": 142,
  "root": "0x...",
  "growth_24h": 17,
  "growth_7d": 89,
  "last_updated": "2026-06-19T12:00:00Z"
}
```

The `commitment_count` is `NEXT_INDEX` read from the persisted local tree (not from
on-chain — the indexer already tracks every insert event). `growth_*` is derived from
the event timestamps stored in the indexer DB.

This satisfies PRD §6 success metric ("anonymity set growth trend, no de-anon incident").

### 5B. De-anon signal watch (monitoring)

Add a simple heuristic: if any single `(commitment, nullifier)` pair can be linked by
amount equality within a 10-minute window, emit a warning log. This is a best-effort
signal, not a proof — its purpose is to surface early "small anonymity set" conditions
so the team can advise users to wait before spending.

---

## Exit gate (all must be green before M8 begins)

- [ ] `circuits/settle_or_refund.circom` compiled + witness tests pass + ceremony key pinned
- [ ] `circuits/repay.circom` compiled + witness tests pass + ceremony key pinned
- [ ] Liquidation `// VERIFY` closed (either circuit implemented or decision documented)
- [ ] `veil_core.propose_admin` / `accept_admin` pass negative tests
- [ ] `veil_core.bump_ttl` test asserts TTL extended correctly
- [ ] `tools/vk-verify` exits 0 on `circuit-keys/manifest.sha256`
- [ ] `veil e2e tampered-proof-rejected --network testnet` green for all circuits
- [ ] Mainnet key gate logic in place (refuses dev-key hashes)
- [ ] `deployments/mainnet.json` exists with pinned BENJI asset_id + Reflector address
- [ ] Reflector mainnet feed confirmed (simulate `lastprice` returns valid data)
- [ ] Indexer `/anonymity-set` endpoint live on testnet

---

## Dependency graph

```
1A settle_or_refund ──┐
1B repay circuit    ──┼──► all circuits frozen ──► 3A vk-verify ──► 3B tampered-proof e2e
1C liquidation      ──┘
2A set_admin two-step ──► (no dependency)
2B bump_ttl          ──► (no dependency)
4A BENJI asset_id ──► 4B Reflector verify ──► deployments/mainnet.json
5A anonymity-set ──► 5B de-anon watch
[all above] ──► M8 gate
```

## Not in M7 (do not build)

- Multi-party Phase-2 ceremony (external, human contributors — M8 dependency)
- External audit engagement (M8 dependency)
- Bug bounty platform (M8 dependency)
- Actual mainnet deploy (M8)
- BENJI deposit / swap / withdraw on mainnet (M8 e2e)
