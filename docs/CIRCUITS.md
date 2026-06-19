# CIRCUITS — Veil Protocol

Language: **Circom 2**. Proof system: **Groth16** over **BN254**. Hash:
**Poseidon** with params that MUST match the on-chain CAP-0075 host function
(see REFERENCES.md — verify arity/round constants before locking keys).

## 0. Shared definitions (used by every circuit)

**Note (UTXO):** `note = (amount, asset_id, blinding, owner_pk)`
- `amount`: field element, range-checked `0 ≤ amount < 2^64`.
- `asset_id`: field element identifying the asset (e.g. Poseidon of issuer+code).
- `blinding`: random field element (note secret).
- `owner_pk`: Poseidon-based public key; `owner_pk = Poseidon(owner_sk)`.

**Commitment:** `cm = Poseidon(amount, asset_id, blinding, owner_pk)`.

**Nullifier:** `nf = Poseidon(owner_sk, leaf_index, cm)` — deterministic per note,
unlinkable to `cm` without `owner_sk`, and unique so double-spend is detectable.

**Merkle membership:** `MerkleProof(leaf, pathElements, pathIndices) == root`,
Poseidon two-to-one at each level, fixed depth `D = 32`.

**Reusable templates (from SPP, REFERENCES.md):** `Note()`, `CommitmentHasher()`,
`MerkleTreeChecker()`, `Nullifier()`. We add `NotInSet()` checks below.

> **Convention:** every circuit file starts with a header comment listing public
> inputs in order — that order is the contract's `public_inputs` vector and the
> vkey binding. Changing it changes the vkey.

---

## 1. `deposit.circom` (REUSE/EXTEND SPP)

Creates a new commitment from funds entering the pool; gated by ASP.

**Private inputs:** `amount, asset_id, blinding, owner_pk`,
ASP witness `(asp_path[], asp_idx[])`, blocked-set non-membership witness.

**Public inputs:** `cm` (output commitment), `public_amount` (funds deposited,
visible), `asp_approved_root`, `asp_blocked_root`.

**Constraints (plain language):**
1. `cm == Poseidon(amount, asset_id, blinding, owner_pk)`.
2. `amount` is in range `[0, 2^64)`.
3. `public_amount == amount` (deposit fully funds the note).
4. Depositor identity/credential is a member of `asp_approved_root`.
5. Depositor credential is NOT a member of `asp_blocked_root` (non-membership).

**Constraint list:**
- `CommitmentHasher(amount, asset_id, blinding, owner_pk) === cm`
- `RangeCheck64(amount)`
- `amount === public_amount`
- `MerkleTreeChecker(credLeaf, asp_path, asp_idx) === asp_approved_root`
- `NonMembership(credLeaf, blocked_path, ...) === asp_blocked_root`

---

## 2. `swap.circom` (NEW — extends transact)

Spends one shielded input note and binds a flow-encrypted swap intent for the
batch auction. Output commitments are produced at `settle_batch` time, not here.

**Private inputs:** input `note_in = (amount_in, asset_in, blinding_in, owner_sk)`,
`leaf_index`, Merkle witness `(path[], idx[])`, intent `(asset_out, min_out,
out_blinding, out_owner_pk)`, encryption randomness `r_enc`.

**Public inputs:** `root`, `nf_in` (input nullifier), `enc_order_hash`
(commitment to the flow-encrypted intent), `committee_pk`.

**Constraints (plain language):**
1. Input commitment is in the tree at `root`.
2. `nf_in` is the correct nullifier of the input note.
3. The spender owns the note (`owner_pk == Poseidon(owner_sk)`).
4. `amount_in` in range; `min_out` in range.
5. `enc_order_hash` is the hash of the correctly flow-encrypted intent under
   `committee_pk` with `r_enc` — binds the on-chain ciphertext to this proof so
   the committee cannot be fed a different order.
6. **(RULE 3)** Two-set check is enforced on-chain via `nf_in` lookup; the circuit
   additionally proves the note was never created as locked-only collateral
   (domain-separated owner check) — see `NotInSet` note below.

**Constraint list:**
- `MerkleTreeChecker(cm_in, path, idx) === root`
- `Nullifier(owner_sk, leaf_index, cm_in) === nf_in`
- `Poseidon(owner_sk) === owner_pk_in`
- `RangeCheck64(amount_in)`, `RangeCheck64(min_out)`
- `EncOrderHasher(asset_out, min_out, out_blinding, out_owner_pk, committee_pk, r_enc) === enc_order_hash`

> **Two-set enforcement:** Soroban-side, `veil_core.spend` rejects if `nf_in ∈
> spent` OR `nf_in ∈ locked`. The circuit cannot read on-chain sets, so the
> on-chain check is the authority; the circuit's job is only to produce a valid,
> owner-bound `nf_in`. THREAT_MODEL covers why this split is safe.

---

## 3. `batch_settle.circom` (NEW)

Proves a batch clearing is balance-preserving and well-formed. Produced by the
committee after threshold-decrypting the batch.

**Private inputs:** decrypted intents `[(asset_out_j, min_out_j, out_blinding_j,
out_owner_pk_j)]`, pre-reserves, post-reserves, clearing price(s),
per-output amounts `amount_out_j`.

**Public inputs:** `batch_id`, `enc_order_hash_j` (∀ j, ties each output to its
submitted order), `clearing` (public clearing parameters), output commitments
`cm_out_j`, pre/post reserve commitments.

**Constraints (plain language):**
1. Each `enc_order_hash_j` decrypts to the claimed intent (decryption correctness
   under the committee key) — links settlement to the exact orders submitted.
2. Value conservation across the batch: `Σ inputs (per asset) == Σ outputs (per
   asset) + fees`, at the single `clearing` price (no per-trader price discr.).
3. Each `min_out_j ≤ amount_out_j` (slippage bound honored).
4. Each `cm_out_j == Poseidon(amount_out_j, asset_out_j, out_blinding_j,
   out_owner_pk_j)` and `amount_out_j` in range.
5. `post_reserves == pre_reserves + Σ inputs − Σ outputs` (reserve consistency).

**Constraint list (sketch):**
- `∀j: Decrypt(enc_order_hash_j, committee_sk_share-aggregate) === intent_j`
- `Σ_asset in_amt === Σ_asset out_amt + fee_asset`
- `∀j: LessEqThan(min_out_j, amount_out_j)`
- `∀j: CommitmentHasher(amount_out_j, asset_out_j, out_blinding_j, out_owner_pk_j) === cm_out_j`
- `ReserveTransition(pre_reserves, in_sums, out_sums) === post_reserves`

> Batch size is fixed per circuit (e.g. K=8/16/32 orders). Multiple
> fixed-size variants, or recursion to fold variable batches, are an
> optimization milestone (ROADMAP) — start with one fixed K.

---

## 4. `lend.circom` (NEW)

Proves a borrow is within LTV against a public oracle price, locking collateral.

**Private inputs:** collateral note `(collat_amount, collat_asset, collat_blinding,
owner_sk)`, `leaf_index`, Merkle witness, borrow note `(borrow_amount,
borrow_asset, borrow_blinding, owner_pk)`.

**Public inputs:** `root`, `collat_nf` (→ locked set), `borrow_cm` (output),
`oracle_price`, `oracle_decimals`, `ltv_max_bps`, `borrow_price`.

**Constraints (plain language):**
1. Collateral commitment is in the tree at `root`; spender owns it.
2. `collat_nf` is the correct nullifier of the collateral note (→ `lock`, RULE 3).
3. `borrow_cm` is the correct commitment of the borrow note; amounts in range.
4. **LTV range proof:** `borrow_amount × borrow_price ≤ (ltv_max_bps / 10_000)
   × collat_amount × oracle_price`, computed with the public, oracle-supplied
   `oracle_price`/`oracle_decimals` — **without revealing either amount**.

**Constraint list:**
- `MerkleTreeChecker(collat_cm, path, idx) === root`
- `Poseidon(owner_sk) === owner_pk`
- `Nullifier(owner_sk, leaf_index, collat_cm) === collat_nf`
- `CommitmentHasher(borrow_amount, borrow_asset, borrow_blinding, owner_pk) === borrow_cm`
- `RangeCheck64(collat_amount)`, `RangeCheck64(borrow_amount)`
- `LessEqThan(borrow_amount * borrow_price * 10_000,
              collat_amount * oracle_price * ltv_max_bps)`  // scaled, overflow-safe

> The oracle price is a **public input** the contract supplies from Reflector at
> proof-verification time; the contract MUST check the `oracle_price` public
> input equals the freshly-read on-chain price within a staleness window
> (CONTRACTS.md), else a user could prove against a stale favorable price.

---

## 5. `kyc_credential.circom` (NEW — Module 3)

Proves the holder possesses a valid, non-revoked KYC credential in the approved
set without revealing which one. Used to derive the ASP membership leaf consumed
by `deposit.circom`.

**Private inputs:** `cred_secret`, issuer signature/attestation witness, approved
witness `(path[], idx[])`, blocked non-membership witness.

**Public inputs:** `asp_approved_root`, `asp_blocked_root`, `nullifier_kyc`
(prevents one credential gating unlimited Sybil identities if policy requires
rate-limiting), `issuer_pk`.

**Constraints (plain language):**
1. Credential is validly issued by `issuer_pk` (attestation check).
2. Credential leaf ∈ `asp_approved_root`.
3. Credential leaf ∉ `asp_blocked_root`.
4. `nullifier_kyc` correctly derived from `cred_secret` (revocation / rate-limit).

**Constraint list:**
- `AttestationCheck(cred_secret, issuer_pk, sig) === 1`
- `MerkleTreeChecker(credLeaf, path, idx) === asp_approved_root`
- `NonMembership(credLeaf, blocked_path, ...) === asp_blocked_root`
- `Poseidon(cred_secret, domain) === nullifier_kyc`

---

## 6. `NotInSet` / non-membership helper

SPP's ASP uses a non-membership (sorted/indexed Merkle) structure. We reuse it for
the blocked set. The spent/locked nullifier "not in set" check is **not** done in
circuit (sets are large, mutable, on-chain) — it is enforced by `veil_core` on the
public `nf` value. Document this split explicitly in every circuit header.

---

## 7. Proving / verification flow

```
build:    circom c.circom --r1cs --wasm --sym
setup:    snarkjs groth16 setup c.r1cs pot_final.ptau c_0000.zkey   (Phase-1 reuse)
phase2:   tools/ceremony-cli contributes -> c_final.zkey            (own Phase-2)
export:   snarkjs zkey export verificationkey c_final.zkey vk.json
          -> convert vk to Soroban vk bytes (see §8), pin in circuit-keys/ + sha256
prove (browser):  witness = c.wasm(inputs); proof = snarkjs.groth16.prove(c_final.zkey, witness)
verify (off):     snarkjs.groth16.verify(vk.json, public, proof)    // dev sanity
verify (on-chain): veil_core.verify_groth16(vk_id, proof, public)   // BN254 host fn
```

## 8. circom → Soroban conversion step

snarkjs emits a Groth16 vkey and proof in JSON over BN254. The on-chain verifier
needs them as field/curve-point bytes the CAP-0074 host functions accept.

1. **vkey:** parse `vk.json` (alpha/beta/gamma/delta in G1/G2, IC points). Encode
   each coordinate as the host-fn's expected `BytesN` field encoding
   (big-endian, correct field). Store the encoded vk under a `VkId` in
   `veil_core` (instance/persistent storage). **Pin the source `vk.json` +
   sha256 in `circuit-keys/`** so the on-chain vk is reproducible.
2. **proof:** browser serializes `(A∈G1, B∈G2, C∈G1)` to the same byte encoding;
   passed as `Proof` to `verify_groth16`.
3. **public inputs:** the ordered public-signal list (from each circuit's header
   comment) is serialized as `Vec<BytesN<32>>`, each reduced mod scalar field,
   in the exact circuit order. **Order is part of the security boundary.**
4. **Pairing check:** `verify_groth16` computes the Groth16 pairing equation via
   the BN254 pairing host function (CAP-0074). // VERIFY exact host-fn signature
   and pairing-product convention against developers.stellar.org/docs/build/apps/zk
   before finalizing — do NOT assume the EIP-197 argument order.

> A small `tools/vk-convert` script (extends SPP tooling) performs (1)+(2) and
> emits a Rust constant / storage-init blob. Output is committed and hash-checked
> so the conversion is auditable.
