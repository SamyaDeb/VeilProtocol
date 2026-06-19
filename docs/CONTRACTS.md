# CONTRACTS — Veil Protocol (Soroban / Rust)

> All claims about Soroban storage tiers, `extend_ttl`/`get_ttl`, and host
> functions are grounded in developers.stellar.org (REFERENCES.md). Anything not
> yet verified is marked `// VERIFY`. SDK types: `Env`, `Address`, `BytesN<N>`,
> `Bytes`, `Vec`, `Map`, `Symbol` per `soroban-sdk`.

## 0. Cross-cutting conventions
- **Errors:** every contract has one `#[contracterror] enum XError { ... }` with
  stable integer codes. No `panic!`/`unwrap()` on user paths; return `Result`.
- **Auth:** mutating module→core calls do `caller.require_auth()` AND check the
  caller is registered (`Perms`). Admin/operator/committee/auditor actions
  `require_auth` the respective privileged address.
- **Field elements:** `BytesN<32>`, big-endian, assumed reduced mod BN254 scalar
  field; the verifier wrapper reduces/validates on entry.
- **Events:** every leaf insert and nullifier write emits an event the indexer
  consumes (RPC retains ~7d → indexer persists; see PRD US-7).

---

## 1. `veil_core`

### Storage layout
| Key | Tier | Type | Notes |
|-----|------|------|-------|
| `ADMIN` | instance | `Address` | protocol admin |
| `MODULES` | persistent | `Map<Address, Perms>` | registered module/committee ACL |
| `TREE_NODES` | persistent | `Map<u64, BytesN<32>>` | Merkle nodes (incremental tree) |
| `NEXT_INDEX` | persistent | `u64` | next leaf index |
| `ROOTS` | persistent | `Vec<BytesN<32>>` | recent-root ring buffer (size N) |
| `SPENT` | persistent | `Map<BytesN<32>, ()>` | spent nullifier set (RULE 3) |
| `LOCKED` | persistent | `Map<BytesN<32>, ()>` | locked nullifier set (RULE 3) |
| `AUDITOR_CT` | persistent | `Map<u64, Bytes>` | ciphertext per leaf index (RULE 4) |
| `AUDITOR_PK` | instance | `BytesN<32>` | auditor encryption pubkey |
| `VK` | instance | `Map<VkId, Bytes>` | encoded Groth16 vkeys per circuit |

> **Why persistent (not temporary):** the tree, nullifier sets, and ciphertext
> store are consensus-critical and must never be silently archived-and-lost.
> Temporary storage auto-deletes on TTL expiry — unacceptable here. (REFERENCES:
> state-archival + choosing-the-right-storage.)

### Functions
| Fn | Params | Returns | Errors |
|----|--------|---------|--------|
| `deposit` | `proof, public:DepositPublic, asp_proof, auditor_ct:Bytes` | `u64` (index) | `AspRejected, BadProof, BadAuditorCt` |
| `insert_commitment` | `caller, leaf:BytesN<32>, auditor_ct:Bytes` | `u64` | `Unauthorized, MissingAuditorCt, TreeFull` |
| `current_root` | — | `BytesN<32>` | — |
| `root_is_known` | `root` | `bool` | — |
| `verify_groth16` | `vk_id, proof, public_inputs:Vec<BytesN<32>>` | `bool` | `UnknownVk, MalformedProof` |
| `spend` | `caller, nf:BytesN<32>` | `()` | `Unauthorized, AlreadySpent, IsLocked` |
| `lock` | `caller, nf:BytesN<32>` | `()` | `Unauthorized, AlreadySpent, AlreadyLocked` |
| `unlock` | `caller, nf:BytesN<32>` | `()` | `Unauthorized, NotLocked` |
| `register_module` | `admin, module, perms` | `()` | `Unauthorized` |
| `set_admin` / `set_auditor_pubkey` | `admin, new` | `()` | `Unauthorized` |

**Invariants enforced in code:**
- `insert_commitment` requires non-empty `auditor_ct` (RULE 4) and a registered
  caller with `INSERT` perm.
- `spend(nf)` fails if `nf ∈ SPENT ∨ nf ∈ LOCKED` (RULE 3).
- `lock(nf)` fails if `nf ∈ SPENT ∨ nf ∈ LOCKED`.
- `deposit` MUST call `asp.check_entry` and propagate failure (RULE 1).
- `verify_groth16` is the only proof path; modules never re-implement pairing.

### TTL / state-archival strategy
- Tree/nullifier/ciphertext entries: **persistent**, with rent topped up. Each
  mutating call `extend_ttl`s the entries it touches to a high threshold so the
  hot set never expires mid-life. A keeper job + on-call `bump_ttl(keys)` admin
  fn re-extends cold-but-critical entries before archival.
- Reads check `get_ttl`; if an entry is near archival the caller is asked to
  restore (pay rent) before the op. // VERIFY restore-on-access flow for Map sub-entries
- Instance storage (`ADMIN`, `VK`, `AUDITOR_PK`) extended on every invocation.

---

## 2. `asp`

### Storage
| Key | Tier | Type |
|-----|------|------|
| `OPERATOR` | instance | `Address` |
| `APPROVED_ROOT` | persistent | `BytesN<32>` |
| `BLOCKED_ROOT` | persistent | `BytesN<32>` |
| `ROOT_HISTORY` | persistent | `Vec<(BytesN<32>,BytesN<32>)>` (recent roots) |

### Functions
| Fn | Params | Returns | Errors |
|----|--------|---------|--------|
| `approved_root` / `blocked_root` | — | `BytesN<32>` | — |
| `update_approved` | `op, new_root, attest:Bytes` | `()` | `Unauthorized, StaleUpdate` |
| `update_blocked` | `op, new_root, attest:Bytes` | `()` | `Unauthorized` |
| `check_entry` | `caller, p:AspMembershipProof` | `Result<(),AspError>` | `NotApproved, IsBlocked, UnknownRoot` |

`check_entry` verifies the membership + non-membership proof against a root in
`ROOT_HISTORY` (tolerates recent updates). Called by `veil_core.deposit` only;
`require_auth(veil_core)`.

---

## 3. `amm_pool`

### Storage
| Key | Tier | Type | Notes |
|-----|------|------|-------|
| `CORE` | instance | `Address` | veil_core address |
| `COMMITTEE` | instance | `Address` | settlement committee |
| `COMMITTEE_PK` | instance | `BytesN<32>` | flow-encryption pubkey |
| `CUR_BATCH` | persistent | `BatchId` | open batch id |
| `ORDERS` | persistent | `Map<OrderId,(Bytes,BytesN<32>)>` | enc_order + nf, current batch |
| `ENC_RESERVES` | persistent | `EncReserves` | encrypted pool reserves |
| `LP` | persistent | `Map<BytesN<32>,()>` | LP commitments |

### Functions
| Fn | Params | Returns | Errors |
|----|--------|---------|--------|
| `submit_order` | `proof, enc_order:Bytes, nf, root` | `OrderId` | `UnknownRoot, BadProof` |
| `current_batch` | — | `BatchId` | — |
| `settle_batch` | `committee, batch, clearing, settle_proof, outputs:Vec<(BytesN<32>,Bytes)>` | `()` | `Unauthorized, BadProof, BatchClosed, ReserveMismatch` |
| `add_liquidity` | `proof, nf, lp_commit, auditor_ct` | `()` | `BadProof` |
| `remove_liquidity` | `proof, nf` | `()` | `BadProof, UnknownLp` |
| `encrypted_reserves` | — | `EncReserves` | — |

`submit_order` flow: `core.root_is_known(root)` → `core.verify_groth16(SWAP,..)`
→ `core.spend(nf)` → store order. `settle_batch`: `require_auth(COMMITTEE)` →
`core.verify_groth16(BATCH_SETTLE,..)` → `core.insert_commitment` per output
(each with its `auditor_ct`, RULE 4) → update `ENC_RESERVES` → open next batch.

---

## 4. `lending`

### Storage
| Key | Tier | Type | Notes |
|-----|------|------|-------|
| `CORE` | instance | `Address` | |
| `ORACLE` | instance | `Address` | Reflector contract |
| `LTV_MAX_BPS` | instance | `u32` | per-asset max LTV, basis points |
| `STALENESS` | instance | `u64` | max oracle age (ledgers/seconds) |
| `LOANS` | persistent | `Map<LoanId, LoanRec>` | collat_nf, borrow_cm, price, asset |

### Functions
| Fn | Params | Returns | Errors |
|----|--------|---------|--------|
| `open_loan` | `proof, collat_nf, borrow_commit, auditor_ct, oracle_asset, root` | `LoanId` | `UnknownRoot, StaleOracle, LtvExceeded(BadProof), BadAuditorCt` |
| `repay` | `proof, repay_nf, collat_unlock` | `()` | `BadProof, NotLocked` |
| `liquidate` | `proof, loan, oracle_asset` | `()` | `Healthy, BadProof, StaleOracle` |
| `read_oracle_price` | `asset` | `PriceData` | `NoPrice, StaleOracle` |

**Oracle binding (critical):** `open_loan` reads Reflector
`lastprice(asset) -> Option<PriceData{price:i128,timestamp}>`, rejects if older
than `STALENESS`, and **asserts the proof's `oracle_price` public input equals
the freshly-read price** (and `oracle_decimals` matches). This prevents proving
LTV against a stale/favorable price (see CIRCUITS §4, THREAT_MODEL oracle).
`open_loan` then `core.lock(collat_nf)` (RULE 3) and `core.insert_commitment`
(borrow note, RULE 4). `repay` `core.spend(repay_nf)` + `core.unlock(collat_nf)`.

---

## 5. `viewkey` (library + core-stored state)

No standalone mutable funds. `set_auditor_pubkey` (admin) lives on `veil_core`;
`ciphertext_at(idx)` reads `AUDITOR_CT`. Decryption is **off-chain** with the
auditor secret key. Disclosure requests SHOULD be logged via an event for audit
trail. The library provides the canonical encrypt/serialize routine shared by
every module so all `auditor_ct` payloads are uniformly decryptable (RULE 4).

---

## 6. Cross-contract auth summary
| Caller | Callee.fn | Auth check |
|--------|-----------|------------|
| `veil_core.deposit` | `asp.check_entry` | `asp` trusts `require_auth(veil_core)` |
| `amm_pool` | `veil_core.{verify,spend,insert,root}` | `MODULES[amm]` perms + `require_auth(amm)` |
| `lending` | `veil_core.{verify,lock,unlock,spend,insert}` | `MODULES[lending]` perms + `require_auth(lending)` |
| committee | `amm_pool.settle_batch` | `require_auth(COMMITTEE)` |
| `lending` | `reflector.lastprice` | read-only, no auth |
| admin | `*.set_*`, `register_module`, ASP root updates | `require_auth(admin/operator)` |

## 7. Resource / cost notes
- `verify_groth16` (BN254 pairing) is the dominant CPU cost per tx; budget
  against Soroban resource limits and confirm headroom on testnet (TEST_PLAN).
- `batch_settle` verifies one proof for K orders → amortizes pairing cost across
  the batch; pick K so a settle tx fits comfortably in limits. // VERIFY limits
- Map-based sets (`SPENT`,`LOCKED`) grow unbounded → rely on per-key persistent
  entries + rent, not a single giant value, to stay within entry-size limits.
  // VERIFY per-entry vs single-map size limits before implementation.
