# M0 Build Plan — Veil Protocol

Milestone M0 exit gate: `veil e2e deposit --network testnet` green.
Read alongside CLAUDE.md, ARCHITECTURE.md (§2.1, §2.2, §7), CONTRACTS.md (§1, §2, §5),
CIRCUITS.md (§0, §1, §5), and TEST_PLAN.md (M0).

---

## Resolved design decisions

| Decision | Choice | Reason |
|----------|--------|--------|
| Hash function | **Standard Poseidon** (circomlib-compatible) | circomlib has production-ready templates; SPP uses it; well-audited. Poseidon2 has no circomlib support yet. |
| Poseidon params | **t=3, d=5, rounds_f=8, rounds_p=57** for 2→1; **t=5, d=5, rounds_f=8, rounds_p=60** for 4→1 (BN254 field) | Matches circomlib defaults; these are hardcoded in `poseidon2/params.json` and in every contract Poseidon call. |
| Auditor encryption | **X25519 + ChaCha20-Poly1305 (ECIES)** | `AUDITOR_PK` is 32 bytes = X25519 public key; browser Web Crypto + `@noble/curves`; auditor decrypts offline with standard tooling. No BN254 needed for this path. |
| BN254 pairing API | `env.crypto().bn254().pairing_check(g1_vec, g2_vec) -> bool` | Verified from soroban-sdk 26.0.1 source. Multi-pair product=1. Groth16: `[-A, α, vk_x, C]` × `[B, β, γ, δ]`. |
| G1 serialization | 64 bytes uncompressed `X‖Y` big-endian | Ethereum-compatible; matches snarkjs output directly. |
| G2 serialization | 128 bytes `X_c1‖X_c0‖Y_c1‖Y_c0` big-endian | Ethereum-compatible; matches snarkjs output directly. |
| Poseidon on-chain | `CryptoHazmat::poseidon_permutation(...)` with `hazmat-crypto` feature | Verified from soroban-sdk 26.0.1. Caller supplies MDS + round constants; we supply circomlib-matching params. |
| soroban-sdk version | **26.0.1** | Already in local cargo registry. |
| Merkle tree depth | **D = 32** | Fixed per CIRCUITS.md §0; determines anonymity-set ceiling. |
| Dev ceremony | solo contributor zkey (testnet only) | Mainnet requires multi-party Phase-2 (M7). A hard config gate prevents dev keys from reaching mainnet. |

---

## Hard rules (CLAUDE.md — never violate in any task below)

- **RULE 1:** every `veil_core.deposit` call MUST first pass `asp.check_entry`. No bypass.
- **RULE 4:** `insert_commitment` requires a non-empty `auditor_ct`. Contract enforces this; no caller can omit it.
- RULE 2 + RULE 3 are not exercised in M0 but nothing built here may block them (nullifier storage keys defined, spend/lock stubs present).

---

## Phase 0 — Toolchain + Scaffolding

No blockers. Do this first.

- [ ] **T0.0** Install `circom` globally (build from source or via npm) and `snarkjs` globally (`npm install -g snarkjs`). Verify with `circom --version` and `snarkjs --version`.
- [ ] **T0.1** Create the full directory tree:
  ```
  circuits/lib/
  contracts/veil_core/src/
  contracts/asp/src/
  app/src/{prover,wallet,store,viewkey,ui}/
  poseidon2/
  circuit-keys/dev/
  tools/vk-convert/src/
  indexer/src/
  e2e-tests/
  deployments/
  ```
- [ ] **T0.2** `contracts/Cargo.toml` — Cargo workspace declaring `veil_core` and `asp` members.
- [ ] **T0.3** `poseidon2/params.json` — pin the Poseidon parameters used by every circuit and every on-chain Poseidon call:
  ```json
  {
    "field": "BN254",
    "t3":  { "t": 3, "d": 5, "rounds_f": 8, "rounds_p": 57 },
    "t5":  { "t": 5, "d": 5, "rounds_f": 8, "rounds_p": 60 },
    "mds_t3": "... circomlib BN254 MDS for t=3 ...",
    "mds_t5": "... circomlib BN254 MDS for t=5 ...",
    "round_constants_t3": "...",
    "round_constants_t5": "..."
  }
  ```
  Source: extract from circomlib `poseidon_constants.circom` and commit verbatim. This file is the single source of truth — contracts and circuits both read from it (or embed it).
- [ ] **T0.4** Download `powersOfTau28_hez_final_17.ptau` (Hermez perpetual PoT, supports up to 2^17 constraints) into `circuit-keys/dev/`. Verify sha256 against the published Hermez manifest. This is the Phase-1 input for the dev ceremony.

---

## Phase 1 — Circuit Base Libraries

Blocks on: T0.3 (Poseidon params must be set before writing any Poseidon circuit).

Each file in `circuits/lib/` has a header comment listing its template name, inputs, outputs, and which public signals it contributes to.

- [ ] **T1.0** `circuits/lib/poseidon.circom` — thin wrapper calling circomlib `Poseidon(n)`. Imports the standard circomlib template. All other circuits import this file (not circomlib directly) so there is one import point to update if params change.
- [ ] **T1.1** `circuits/lib/commitment_hasher.circom` — `cm = Poseidon([amount, asset_id, blinding, owner_pk])` using t=5. Template `CommitmentHasher()`; input signals: `amount, asset_id, blinding, owner_pk`; output: `cm`.
- [ ] **T1.2** `circuits/lib/merkle_tree_checker.circom` — D=32 binary Merkle path verifier using `Poseidon([left, right])` (t=3) at each level. Template `MerkleTreeChecker(depth)`; inputs: `leaf, pathElements[depth], pathIndices[depth]`; output: `root`. Reuse SPP design (https://github.com/NethermindEth/stellar-private-payments).
- [ ] **T1.3** `circuits/lib/nullifier.circom` — `nf = Poseidon([owner_sk, leaf_index, cm])` (t=4→use t=5 padded or verify t=4 params). Template `NullifierHasher()`; inputs: `owner_sk, leaf_index, cm`; output: `nf`. Defined here for M0 even though `spend` is M1 — deposit circuit imports it.
- [ ] **T1.4** `circuits/lib/range_check.circom` — prove `0 ≤ x < 2^64` via 64-bit binary decomposition. Template `RangeCheck64()`; input: `x`; no output (constraint only). Use standard `Num2Bits(64)` from circomlib.
- [ ] **T1.5** `circuits/lib/non_membership.circom` — sorted indexed Merkle non-membership proof. Template `NonMembership(depth)`; inputs: `value, lower_leaf, upper_leaf, lower_path[depth], upper_path[depth], lower_idx[depth], upper_idx[depth]`; output: `root`. Reuse SPP ASP non-membership design.
- [ ] **T1.6** Tests for Phase 1 (run with `circom_tester` / `snarkjs` in Jest or Mocha):
  - `CommitmentHasher`: valid witness generated; output matches expected `Poseidon([amount,asset,blind,pk])`.
  - `MerkleTreeChecker`: valid path accepted; flipped bit in path rejected.
  - `NullifierHasher`: deterministic; different `owner_sk` yields different `nf`.
  - `RangeCheck64`: `2^64 - 1` accepted; `2^64` rejected.
  - `NonMembership`: valid gap proof accepted; inserting the value into the tree and re-proving rejected.

---

## Phase 2 — Top-Level Circuits

Blocks on: Phase 1.

Header comment format (required per CLAUDE.md conventions):
```
// Public inputs (in order — this order IS the vkey binding):
//   1. ...
```

- [ ] **T2.0** `circuits/kyc_credential.circom` — per CIRCUITS.md §5.
  - Private: `cred_secret`, issuer attestation witness, approved Merkle path, blocked non-membership witness.
  - Public (in order): `asp_approved_root`, `asp_blocked_root`, `nullifier_kyc`, `issuer_pk`.
  - Constraints: attestation check (simplified for M0: `Poseidon([cred_secret, issuer_pk]) === credential_leaf`), approved membership, blocked non-membership, `nullifier_kyc = Poseidon([cred_secret, domain_kyc])`.
- [ ] **T2.1** `circuits/deposit.circom` — per CIRCUITS.md §1.
  - Private: `amount, asset_id, blinding, owner_pk`, ASP credential leaf + path, blocked non-membership path.
  - Public (in order): `cm`, `public_amount`, `asp_approved_root`, `asp_blocked_root`.
  - Constraints: `CommitmentHasher(amount,asset_id,blinding,owner_pk) === cm`; `RangeCheck64(amount)`; `amount === public_amount`; `MerkleTreeChecker(credLeaf, asp_path, asp_idx) === asp_approved_root`; `NonMembership(credLeaf, ...) === asp_blocked_root`.
- [ ] **T2.2** Compile both circuits and run tests:
  ```
  circom circuits/deposit.circom --r1cs --wasm --sym -o circuits/build/
  circom circuits/kyc_credential.circom --r1cs --wasm --sym -o circuits/build/
  ```
  Negative tests (must FAIL to satisfy):
  - Wrong `cm` (tampered amount).
  - `amount` out of 64-bit range.
  - `public_amount != amount`.
  - Depositor credential not in approved root.
  - Depositor credential in blocked root.
- [ ] **T2.3** Dev ceremony (testnet only — never reuse for mainnet):
  ```
  snarkjs groth16 setup circuits/build/deposit.r1cs circuit-keys/dev/pot17.ptau circuit-keys/dev/deposit_0000.zkey
  snarkjs zkey contribute circuit-keys/dev/deposit_0000.zkey circuit-keys/dev/deposit_final.zkey --name="dev"
  snarkjs zkey export verificationkey circuit-keys/dev/deposit_final.zkey circuit-keys/dev/vk_deposit.json

  # repeat for kyc_credential
  snarkjs groth16 setup circuits/build/kyc_credential.r1cs circuit-keys/dev/pot17.ptau circuit-keys/dev/kyc_0000.zkey
  snarkjs zkey contribute circuit-keys/dev/kyc_0000.zkey circuit-keys/dev/kyc_final.zkey --name="dev"
  snarkjs zkey export verificationkey circuit-keys/dev/kyc_final.zkey circuit-keys/dev/vk_kyc.json
  ```
- [ ] **T2.4** `tools/vk-convert/` — Rust binary. Reads `vk_deposit.json` (snarkjs format: alpha/beta/gamma/delta in G1/G2, IC points) and emits:
  - `alpha_g1`: `BytesN<64>` (G1 uncompressed)
  - `beta_g2`: `BytesN<128>` (G2 uncompressed)
  - `gamma_g2`: `BytesN<128>`
  - `delta_g2`: `BytesN<128>`
  - `ic: Vec<BytesN<64>>` (one per public input + 1)
  Output format: a Rust `const` blob and a binary file used to initialize `veil_core` VK storage.
- [ ] **T2.5** `circuit-keys/manifest.sha256` — sha256 of every file in `circuit-keys/dev/`. CI job verifies on every PR. A deliberately tampered proof must be rejected by the verifier (tested in T3.3).

---

## Phase 3 — Contracts

T3.0 blocks on: T0.3 (Poseidon params). T3.3+ blocks on: T2.4 (vk bytes). The rest blocks on: T3.1.

All contracts: `no_std`, `soroban-sdk = { version = "26", features = ["hazmat-crypto"] }`. No `unwrap()`/`panic!` on user-reachable paths. Errors via `#[contracterror] enum`.

### `asp` contract (`contracts/asp/`)

- [ ] **T3.0** Implement `asp`:
  - Storage: `OPERATOR` (instance, `Address`); `APPROVED_ROOT` + `BLOCKED_ROOT` (persistent, `BytesN<32>`); `ROOT_HISTORY` (persistent, `Vec<(BytesN<32>, BytesN<32>)>`, last 50 pairs).
  - `approved_root()`, `blocked_root()` — read-only.
  - `update_approved(op, new_root, attest)` / `update_blocked(...)` — `require_auth(op)`, push to `ROOT_HISTORY`.
  - `check_entry(caller, p: AspMembershipProof)` — `require_auth(veil_core)`; verify Merkle membership against a root in `ROOT_HISTORY` using `CryptoHazmat::poseidon_permutation` with params from T0.3; verify non-membership for blocked root; return `Ok(())` or `AspError`. This is the **only** place on-chain Poseidon Merkle verification is done for the ASP; circuits do it off-chain.
  - `cargo test`: approved+non-blocked → Ok; not approved → Err; in blocked root → Err; stale root not in history → Err; unauthorized `update_approved` → Err.

### `veil_core` contract (`contracts/veil_core/`)

- [ ] **T3.1** Scaffolding: error enum `VeilError`, storage key constants, `Perms` bitfield type, `VkId` enum (starts with `Deposit` and `KycCredential`).
- [ ] **T3.2** Incremental Merkle tree:
  - `TREE_NODES: Map<u64, BytesN<32>>` — 1-indexed binary tree. Node `i` has children `2i` and `2i+1`; leaf `k` maps to node `TREE_SIZE + k` where `TREE_SIZE = 2^32`. Insert: update leaf node, recompute path to root using `CryptoHazmat::poseidon_permutation` (t=3, two-to-one).
  - `NEXT_INDEX: u64` — next leaf slot, starts at 0.
  - `ROOTS: Vec<BytesN<32>>` — ring buffer of last 50 roots. `root_is_known(root) -> bool` scans this vec.
  - `current_root() -> BytesN<32>` — last entry.
  - Unit tests: insert 0, 1, 2, 3 leaves; roots change correctly; `root_is_known` returns true for recent roots and false for evicted ones.
- [ ] **T3.3** `verify_groth16(vk_id, proof, public_inputs)`:
  - Load VK bytes for `vk_id` from `VK: Map<VkId, Bytes>` (instance storage).
  - Deserialize: alpha `Bn254G1Affine`, beta/gamma/delta `Bn254G2Affine`, IC `Vec<Bn254G1Affine>`.
  - Compute `vk_x = IC[0] + Σ IC[i+1] * public_inputs[i]` using `bn254().g1_msm` + `g1_add`.
  - Groth16 pairing check: `bn254().pairing_check([-A, alpha, vk_x, C], [B, beta, gamma, delta])`.
  - Return `true` / `false`; error on malformed bytes or unknown vk_id.
  - Unit test: a real snarkjs-generated proof (from T2.3) verifies; a byte-flipped proof does not.
- [ ] **T3.4** Auditor ciphertext store:
  - `AUDITOR_PK: BytesN<32>` (instance) — X25519 public key.
  - `AUDITOR_CT: Map<u64, Bytes>` (persistent) — ciphertext per leaf index.
  - `insert_commitment(caller, leaf, auditor_ct)`: reject empty `auditor_ct` (RULE 4), reject unregistered caller, insert leaf into tree (T3.2), store `auditor_ct` at that index, emit event `{leaf, idx, auditor_ct}`.
  - Unit test: empty `auditor_ct` → `MissingAuditorCt`; unregistered caller → `Unauthorized`.
- [ ] **T3.5** `deposit(proof, public: DepositPublic, asp_proof, auditor_ct)`:
  - `DepositPublic { cm, public_amount, asp_approved_root, asp_blocked_root }` (matches circuit public input order).
  - Cross-contract call: `asp.check_entry(asp_proof)` — propagate failure as `AspRejected` (RULE 1).
  - `verify_groth16(VkId::Deposit, proof, [cm, public_amount, asp_approved_root, asp_blocked_root])`.
  - `insert_commitment(env.current_contract_address(), cm, auditor_ct)`.
  - Return `CommitmentIndex`.
  - Unit tests: non-approved asp_proof → rejected; bad proof → rejected; empty auditor_ct → rejected; valid path → leaf inserted + ciphertext stored.
- [ ] **T3.6** Module ACL:
  - `MODULES: Map<Address, u32>` (persistent) — bitmask of `Perms`.
  - `register_module(admin, module, perms)` — `require_auth(admin)`.
  - `set_admin(admin, new_admin)` — `require_auth(admin)`.
  - `set_auditor_pubkey(admin, pk)` — `require_auth(admin)`.
  - All mutating fns on `veil_core` check `MODULES[caller].has(required_perm)` before acting.
- [ ] **T3.7** Stubs for M1 (define storage keys + return `Unauthorized` or the correct error):
  - `SPENT: Map<BytesN<32>, ()>` (persistent) — define key, no logic yet.
  - `LOCKED: Map<BytesN<32>, ()>` (persistent) — define key, no logic yet.
  - `spend(caller, nf)` → `VeilError::Unauthorized` (placeholder).
  - `lock(caller, nf)` → `VeilError::Unauthorized`.
  - `unlock(caller, nf)` → `VeilError::Unauthorized`.
  - `is_spent(nf) -> bool` → `false`.
  - `is_locked(nf) -> bool` → `false`.
- [ ] **T3.8** Final `cargo test` sweep — every checklist item from CONTRACTS.md §1 (security section) has a corresponding passing test. TTL: `extend_ttl` called on `TREE_NODES`, `AUDITOR_CT`, `SPENT`, `LOCKED` touched entries.

---

## Phase 4 — Frontend

T4.0–T4.1 have no blockers. T4.2+ blocks on: T2.3 (zkeys available).

- [ ] **T4.0** `app/` scaffold: `npm create vite@latest app -- --template react-ts`. Add dependencies:
  ```
  @stellar/freighter-api
  @stellar/stellar-sdk
  snarkjs
  @noble/curves
  @noble/ciphers
  ```
- [ ] **T4.1** `app/src/wallet/freighter.ts` — thin wrapper: `isConnected()`, `getPublicKey()`, `signTransaction(xdr, network)`. Type the return shapes. No logic beyond what Freighter API exposes.
- [ ] **T4.2** `app/src/prover/deposit.ts` — WASM prover:
  - Lazy-import `circuits/build/deposit_js/deposit.wasm` and `circuit-keys/dev/deposit_final.zkey` via dynamic import / fetch.
  - `proveDeposit(inputs) -> { proof, publicSignals }` using `snarkjs.groth16.fullProve(inputs, wasm, zkey)`.
  - Serialize proof to the byte format `verify_groth16` expects: `A` as 64-byte G1, `B` as 128-byte G2, `C` as 64-byte G1 (concatenated = 256 bytes total).
- [ ] **T4.3** `app/src/viewkey/encrypt.ts` — auditor ECIES:
  - `encryptNote(note, auditorPk: Uint8Array) -> Uint8Array`:
    1. Generate ephemeral X25519 keypair.
    2. ECDH: `sharedSecret = x25519(ephemeralSk, auditorPk)`.
    3. Derive key: `HKDF-SHA256(sharedSecret, salt="veil-auditor-v1")` → 32-byte ChaCha20-Poly1305 key.
    4. Encrypt: `ChaCha20-Poly1305(key, nonce=0, plaintext=encode(note))`.
    5. Output: `ephemeralPk (32) ‖ nonce (12) ‖ ciphertext+tag`.
  - `decryptNote(ct, auditorSk) -> Note` — inverse (for auditor CLI, not in main UI).
- [ ] **T4.4** `app/src/store/notes.ts` — localStorage note store:
  - `saveNote(note, ownerSk)` — encrypt note with `ChaCha20-Poly1305(HKDF(ownerSk, "veil-note-store-v1"))` before writing.
  - `loadNotes(ownerSk) -> Note[]` — decrypt and parse.
  - Notes are recoverable deterministically from `ownerSk` + tree scan; localStorage is a cache only.
- [ ] **T4.5** `app/src/ui/DepositForm.tsx` — deposit UI:
  1. Connect Freighter; read wallet address.
  2. Input: asset, amount. Derive `owner_pk = Poseidon([owner_sk])` (use `circomlib/src/poseidon.js` in browser).
  3. Generate random `blinding`; compute `cm = Poseidon([amount, asset_id, blinding, owner_pk])`.
  4. Fetch current ASP roots from contract; build ASP membership witness (from indexer or hardcoded test path for M0).
  5. `proveDeposit({amount, asset_id, blinding, owner_pk, ...aspWitness})`.
  6. `encryptNote(note, auditorPk)` → `auditor_ct`.
  7. Build Soroban `invokeContract` tx for `veil_core.deposit`; sign via Freighter; submit.
  8. On success: `saveNote(note, owner_sk)`; show commitment index.

---

## Phase 5 — Indexer

Blocks on: T3.4 (event schema must be defined before indexer can parse events).

- [ ] **T5.0** `indexer/` scaffold: `npm init -y`, TypeScript, dependencies:
  ```
  @stellar/stellar-sdk   # Soroban RPC client
  better-sqlite3         # SQLite persistence
  ```
- [ ] **T5.1** `indexer/src/events.ts` — poll `getEvents(startLedger, contractId, topic="CommitmentInserted")` every 5 seconds. Parse event fields: `leaf: BytesN<32>`, `idx: u64`, `auditor_ct: Bytes`. Deduplicate by `idx`.
- [ ] **T5.2** `indexer/src/tree.ts` — Merkle tree reconstruction:
  - Load all stored leaves from SQLite ordered by `idx`.
  - Recompute tree nodes using the same Poseidon t=3 params as the contract.
  - Expose `currentRoot() -> Buffer` and `getLeaf(idx) -> Buffer`.
  - `currentRoot()` must match `veil_core.current_root()` on-chain (asserted by e2e test).
- [ ] **T5.3** SQLite schema: `commitments (idx INTEGER PRIMARY KEY, leaf BLOB, auditor_ct BLOB, ledger INTEGER)`. `indexer/src/db.ts` handles init + upsert + query. Expose a `/root` HTTP endpoint (minimal Express) for the e2e test to query.

---

## Phase 6 — Deploy + E2E

Blocks on: all prior phases green.

- [ ] **T6.0** Deploy to testnet:
  ```
  stellar contract build --manifest-path contracts/asp/Cargo.toml
  stellar contract build --manifest-path contracts/veil_core/Cargo.toml
  stellar contract deploy --wasm target/wasm32-unknown-unknown/release/asp.wasm --network testnet
  stellar contract deploy --wasm target/wasm32-unknown-unknown/release/veil_core.wasm --network testnet
  ```
  Save contract IDs to `deployments/testnet.json`.
- [ ] **T6.1** Initialize on testnet:
  ```
  # set admin
  stellar contract invoke --id $VEIL_CORE_ID -- set_admin --admin $ADMIN --new_admin $ADMIN
  # register asp as trusted caller of veil_core
  stellar contract invoke --id $VEIL_CORE_ID -- register_module --admin $ADMIN --module $ASP_ID --perms 0
  # set auditor pubkey (X25519 pub, 32 bytes)
  stellar contract invoke --id $VEIL_CORE_ID -- set_auditor_pubkey --admin $ADMIN --pk $AUDITOR_PK_HEX
  # init ASP: set approved root = Merkle root of [test_credential]; blocked root = empty tree root
  stellar contract invoke --id $ASP_ID -- update_approved --op $OPERATOR --new_root $APPROVED_ROOT --attest 0x
  stellar contract invoke --id $ASP_ID -- update_blocked  --op $OPERATOR --new_root $BLOCKED_ROOT  --attest 0x
  # load VK bytes into veil_core
  tools/vk-convert/target/release/vk-convert --vk circuit-keys/dev/vk_deposit.json --vk-id Deposit | \
    stellar contract invoke --id $VEIL_CORE_ID -- init_vk ...
  ```
- [ ] **T6.2** `e2e-tests/` — `veil` CLI entry point (`e2e-tests/src/cli.ts`, exposed as `veil` binary via `package.json#bin`). Playwright for headless browser proof generation.
- [ ] **T6.3** `e2e-tests/src/deposit.test.ts` — assertions per TEST_PLAN.md M0:
  1. **Rejected deposit**: submit deposit from an address NOT in the approved ASP root → transaction fails on-chain with `AspRejected`.
  2. **Approved deposit**: submit deposit from the test-credential address → transaction succeeds; `veil_core.current_root()` changes; leaf at returned index is `cm`.
  3. **Auditor decrypt**: fetch `ciphertext_at(idx)` from `veil_core`; decrypt with auditor secret key → plaintext matches the original `(amount, asset_id, blinding, owner_pk)`.
  4. **Indexer root**: `indexer /root` == `veil_core.current_root()` after indexer has processed the event.

---

## Dependency graph

```
T0.0 ─► T0.1 ─► T0.2
T0.3 ─► T1.0 ─► T1.1 ─► T1.2 ─► T1.3 ─► T1.4 ─► T1.5 ─► T1.6
                                                              │
                                                              ▼
                                                    T2.0 ─► T2.1 ─► T2.2 ─► T2.3 ─► T2.4 ─► T2.5
                                                                                        │
T0.3 ─► T3.0 (asp)                                                                     │
T0.3 ─► T3.1 ─► T3.2 ─► T3.3 ◄────────────────────────────────────────────────── T2.4 ┤
                     └──► T3.4 ─► T3.5 ─► T3.6 ─► T3.7 ─► T3.8                       │
                                                                                        │
T4.0 ─► T4.1                                                                           │
T2.3 ─► T4.2 ─► T4.3 ─► T4.4 ─► T4.5                                                 │
                                                                                        │
T3.4 ─► T5.0 ─► T5.1 ─► T5.2 ─► T5.3                                                 │
                                                                                        │
[all above] ─► T6.0 ─► T6.1 ─► T6.2 ─► T6.3  (exit gate: veil e2e deposit green) ◄──┘
```

---

## Not in M0 (do not build)

- `amm_pool`, `lending` contracts — M3+
- `spend`, `lock`, `unlock` logic — M1
- Shielded withdraw — M2
- Multi-party Phase-2 ceremony — M7
- BENJI / Reflector integration — M8
- `batch_settle.circom`, `lend.circom`, `swap.circom` — M3+

---

## How to check you are done

```bash
veil e2e deposit --network testnet
```

Must exit 0. All four assertions in T6.3 must pass. If any fail, the milestone is not done.
