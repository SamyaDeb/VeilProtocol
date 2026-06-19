#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    symbol_short, Address, Bytes, BytesN, Env, IntoVal, Symbol, Vec,
};

// ─── errors ───────────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Clone, Debug, PartialEq)]
pub enum AmmError {
    Unauthorized      = 1,
    BadProof          = 2,
    UnknownRoot       = 3,
    BatchFull         = 4,
    AlreadySettled    = 5,
    NotExpired        = 6,
    UnknownOrder      = 7,
    AlreadyRefunded   = 8,
    CoreCallFailed    = 9,
    MissingAuditorCt  = 10,
    WrongOutputCount  = 11,
    BatchNotFull      = 12,
    ReserveMismatch   = 13,
    UnknownLp         = 14,
}

// Mirror of veil_core::VeilError integer codes — used as E type in try_invoke_contract.
// MUST stay in sync with veil_core::VeilError; checked by failing tests if they diverge.
#[contracterror]
#[derive(Clone, Debug, PartialEq)]
pub enum ExtError {
    Unauthorized     = 1,
    AspRejected      = 2,
    BadProof         = 3,
    MissingAuditorCt = 4,
    AlreadySpent     = 5,
    IsLocked         = 6,
    AlreadyLocked    = 7,
    NotLocked        = 8,
    UnknownVk        = 9,
    MalformedProof   = 10,
    TreeFull         = 11,
    UnknownRoot      = 12,
}

// ─── storage keys ─────────────────────────────────────────────────────────────

// instance
const CORE:      Symbol = symbol_short!("CORE");
const COMMITTEE: Symbol = symbol_short!("COMM");
const COMM_PK:   Symbol = symbol_short!("COMM_PK");
const BATCH_K:   Symbol = symbol_short!("BATCH_K");

// persistent
const BATCH_SEQ: Symbol = symbol_short!("BATCH_SEQ");

// per-batch, per-order: (ORDER_PFX, batch_id: u64, slot: u32) -> OrderRecord
const ORDER_PFX: Symbol = symbol_short!("ORD");
// per-batch order count: (BCNT_PFX, batch_id) -> u32
const BCNT_PFX:  Symbol = symbol_short!("BCNT");
// per-batch settled: (BSET_PFX, batch_id) -> bool
const BSET_PFX:  Symbol = symbol_short!("BSET");
// per-batch timeout ledger: (BTMO_PFX, batch_id) -> u32
const BTMO_PFX:  Symbol = symbol_short!("BTMO");
// per-order refunded: (REFD_PFX, batch_id, slot) -> bool
const REFD_PFX:  Symbol = symbol_short!("REFD");

const ENC_RESERVES: Symbol = symbol_short!("ENCRESV");

// Ledgers after first order before a non-settled batch allows refunds (~5-8 min).
const BATCH_TIMEOUT_LEDGERS: u32 = 100;

// ─── shared types (mirrors veil_core — contracttype serializes by name) ───────

/// VkId variants must match veil_core::VkId exactly (same names, same contracttype).
/// Soroban serialises #[contracttype] enums by variant name, so name matching
/// is the only requirement for cross-contract interop.
#[contracttype]
#[derive(Clone, PartialEq)]
pub enum VkId {
    Deposit,
    KycCredential,
    Transfer,
    Withdraw,
    Swap,
    BatchSettle,
    AddLiquidity,
    RemoveLiquidity,
    SettleOrRefund,
    Repay,
}

/// Groth16 proof — same layout as veil_core::Proof.
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    pub a: BytesN<64>,
    pub b: BytesN<128>,
    pub c: BytesN<64>,
}

// ─── contract storage types ───────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub struct OrderRecord {
    /// Raw ciphertext bytes the committee threshold-decrypts to recover the intent.
    /// M3 mock: plaintext JSON; real encryption is ElGamal-on-BN254 G1 (M4).
    /// // VERIFY: CAP-0074 G1 scalar-mul host function before implementing real
    /// flow encryption (REFERENCES.md CAP-0074 link).
    pub enc_order: Bytes,
    /// Nullifier that was spent at submission (already in veil_core SPENT set).
    pub nf_in: BytesN<32>,
    /// Poseidon(amount_in, asset_out, min_out, out_blinding, out_owner_pk, committee_pk, r_enc).
    /// Public input to batch_settle.circom — links settlement to the submitted intent.
    pub enc_order_hash: BytesN<32>,
    /// Stellar address of the submitter, stored for refund authorisation (M3).
    /// Production refund must use a ZK proof of note ownership instead of
    /// address auth (THREAT_MODEL §6 — soundness-critical audit item).
    /// // VERIFY: replace with settle-or-refund circuit before mainnet.
    pub submitter: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct EncReserves {
    pub reserve_cm: BytesN<32>,
    pub enc_data: Bytes,
}

// ─── contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct AmmPool;

#[contractimpl]
impl AmmPool {
    // ── init ─────────────────────────────────────────────────────────────────

    pub fn initialize(
        env: Env,
        admin: Address,
        core: Address,
        committee: Address,
        comm_pk: BytesN<32>,
        batch_k: u32,
    ) {
        if env.storage().instance().has(&CORE) {
            panic!("already initialized");
        }
        admin.require_auth();
        env.storage().instance().set(&CORE, &core);
        env.storage().instance().set(&COMMITTEE, &committee);
        env.storage().instance().set(&COMM_PK, &comm_pk);
        env.storage().instance().set(&BATCH_K, &batch_k);
        env.storage().persistent().set(&BATCH_SEQ, &0u64);
    }

    pub fn initialize_reserves(
        env: Env,
        reserve_cm: BytesN<32>,
        enc_data: Bytes,
    ) {
        let committee: Address = env.storage().instance().get(&COMMITTEE).unwrap();
        committee.require_auth();
        if env.storage().persistent().has(&ENC_RESERVES) {
            panic!("already initialized reserves");
        }
        env.storage().persistent().set(&ENC_RESERVES, &EncReserves { reserve_cm, enc_data });
    }

    // ── views ─────────────────────────────────────────────────────────────────

    pub fn current_batch(env: Env) -> u64 {
        env.storage().persistent().get(&BATCH_SEQ).unwrap_or(0u64)
    }

    /// Ledger sequence after which refunds are allowed for a non-settled batch.
    pub fn batch_timeout_ledger(env: Env, batch_id: u64) -> u32 {
        let key = (BTMO_PFX, batch_id);
        env.storage().persistent().get(&key).unwrap_or(0u32)
    }

    /// Encrypted pool reserves (committee-decryptable only).
    pub fn encrypted_reserves(env: Env) -> Bytes {
        if let Some(r) = env.storage().persistent().get::<_, EncReserves>(&ENC_RESERVES) {
            r.enc_data
        } else {
            Bytes::new(&env)
        }
    }

    pub fn order_count(env: Env, batch_id: u64) -> u32 {
        env.storage().persistent().get(&(BCNT_PFX, batch_id)).unwrap_or(0u32)
    }

    pub fn batch_k(env: Env) -> u32 {
        env.storage().instance().get(&BATCH_K).unwrap_or(4u32)
    }

    // ── submit_order ──────────────────────────────────────────────────────────

    /// Submit a shielded swap order into the current batch.
    ///
    /// Verifies the swap Groth16 proof (public: root, nf_in, enc_order_hash,
    /// committee_pk), spends the input nullifier (RULE 3), and stores the
    /// encrypted intent for the committee.
    ///
    /// Returns the slot index within the batch.
    pub fn submit_order(
        env: Env,
        submitter: Address,
        proof: Proof,
        enc_order: Bytes,
        nf_in: BytesN<32>,
        enc_order_hash: BytesN<32>,
        root: BytesN<32>,
    ) -> Result<u32, AmmError> {
        submitter.require_auth();

        let core: Address = env.storage().instance().get(&CORE).unwrap();
        let comm_pk: BytesN<32> = env.storage().instance().get(&COMM_PK).unwrap();

        // Verify root is known in veil_core
        if !Self::core_root_is_known(&env, &core, root.clone())? {
            return Err(AmmError::UnknownRoot);
        }

        // Verify swap proof — public inputs: [root, nf_in, enc_order_hash, committee_pk]
        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(root);
        pub_inputs.push_back(nf_in.clone());
        pub_inputs.push_back(enc_order_hash.clone());
        pub_inputs.push_back(comm_pk);

        if !Self::core_verify(&env, &core, VkId::Swap, &proof, &pub_inputs)? {
            return Err(AmmError::BadProof);
        }

        // RULE 3: spend the input nullifier (rejects if in SPENT or LOCKED)
        Self::core_spend(&env, &core, nf_in.clone())?;

        // Slot allocation within current batch
        let batch_id: u64 = env.storage().persistent().get(&BATCH_SEQ).unwrap_or(0u64);
        let k: u32 = env.storage().instance().get(&BATCH_K).unwrap_or(4u32);
        let cnt_key = (BCNT_PFX, batch_id);
        let slot: u32 = env.storage().persistent().get(&cnt_key).unwrap_or(0u32);

        if slot >= k {
            return Err(AmmError::BatchFull);
        }

        // Set batch timeout on first order
        if slot == 0 {
            let tmo = env.ledger().sequence() + BATCH_TIMEOUT_LEDGERS;
            env.storage().persistent().set(&(BTMO_PFX, batch_id), &tmo);
        }

        let rec = OrderRecord {
            enc_order,
            nf_in,
            enc_order_hash,
            submitter,
        };
        env.storage().persistent().set(&(ORDER_PFX, batch_id, slot), &rec);
        env.storage().persistent().set(&cnt_key, &(slot + 1u32));

        env.events().publish(
            (symbol_short!("amm"), symbol_short!("order")),
            (batch_id, slot),
        );

        Ok(slot)
    }

    // ── settle_batch ──────────────────────────────────────────────────────────

    /// Committee posts a balance-preserving settlement proof for the current batch.
    ///
    /// Verifies the batch_settle Groth16 proof against the stored enc_order_hashes
    /// and the provided output commitments, then inserts each output into veil_core.
    /// Advances the batch counter.
    ///
    /// `outputs`: K pairs of (cm_out: BytesN<32>, auditor_ct: Bytes) in slot order.
    ///
    /// Public inputs to batch_settle.circom (in order):
    ///   enc_order_hash[0..K], cm_out[0..K], committee_pk, batch_id_as_field
    pub fn settle_batch(
        env: Env,
        batch_id: u64,
        proof: Proof,
        outputs: Vec<(BytesN<32>, Bytes)>,
        post_reserve_cm: BytesN<32>,
        post_enc_reserves: Bytes,
    ) -> Result<(), AmmError> {
        let committee: Address = env.storage().instance().get(&COMMITTEE).unwrap();
        committee.require_auth();

        // AlreadySettled must be checked before the batch-id match so that a
        // second settle on a completed (and thus counter-advanced) batch returns
        // AlreadySettled rather than UnknownOrder.
        if env.storage().persistent().has(&(BSET_PFX, batch_id)) {
            return Err(AmmError::AlreadySettled);
        }

        let cur: u64 = env.storage().persistent().get(&BATCH_SEQ).unwrap_or(0u64);
        if batch_id != cur {
            return Err(AmmError::UnknownOrder);
        }

        let k: u32 = env.storage().instance().get(&BATCH_K).unwrap_or(4u32);
        let cnt: u32 = env.storage().persistent().get(&(BCNT_PFX, batch_id)).unwrap_or(0u32);
        if cnt < k {
            return Err(AmmError::BatchNotFull);
        }

        if outputs.len() != k {
            return Err(AmmError::WrongOutputCount);
        }

        let core: Address = env.storage().instance().get(&CORE).unwrap();
        let comm_pk: BytesN<32> = env.storage().instance().get(&COMM_PK).unwrap();

        let current_reserves: EncReserves = env.storage().persistent()
            .get(&ENC_RESERVES)
            .ok_or(AmmError::ReserveMismatch)?;

        // Build public_inputs for batch_settle.circom:
        //   enc_order_hash[0..K], cm_out[0..K], committee_pk, batch_id_field
        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);

        for slot in 0u32..k {
            let rec: OrderRecord = env.storage().persistent()
                .get(&(ORDER_PFX, batch_id, slot))
                .unwrap();
            pub_inputs.push_back(rec.enc_order_hash);
        }

        for i in 0u32..k {
            let (cm, _) = outputs.get(i).unwrap();
            // RULE 4: each output must have an auditor ciphertext
            let (_, auditor_ct) = outputs.get(i).unwrap();
            if auditor_ct.len() == 0 {
                return Err(AmmError::MissingAuditorCt);
            }
            pub_inputs.push_back(cm);
        }

        pub_inputs.push_back(comm_pk);
        pub_inputs.push_back(Self::u64_to_bytes32(&env, batch_id));
        pub_inputs.push_back(current_reserves.reserve_cm);
        pub_inputs.push_back(post_reserve_cm.clone());

        if !Self::core_verify(&env, &core, VkId::BatchSettle, &proof, &pub_inputs)? {
            return Err(AmmError::BadProof);
        }

        // RULE 2 + RULE 4: insert each output into the shared veil_core tree
        for i in 0u32..k {
            let (cm, auditor_ct) = outputs.get(i).unwrap();
            Self::core_insert(&env, &core, cm, auditor_ct)?;
        }

        // Mark settled and advance batch counter
        env.storage().persistent().set(&(BSET_PFX, batch_id), &true);
        env.storage().persistent().set(&BATCH_SEQ, &(batch_id + 1));
        env.storage().persistent().set(&ENC_RESERVES, &EncReserves {
            reserve_cm: post_reserve_cm,
            enc_data: post_enc_reserves,
        });

        env.events().publish(
            (symbol_short!("amm"), symbol_short!("settled")),
            batch_id,
        );

        Ok(())
    }

    // ── add_liquidity ─────────────────────────────────────────────────────────

    pub fn add_liquidity(
        env: Env,
        proof: Proof,
        root: BytesN<32>,
        nf_in_0: BytesN<32>,
        nf_in_1: BytesN<32>,
        lp_commit: BytesN<32>,
        auditor_ct: Bytes,
        post_reserve_cm: BytesN<32>,
        post_enc_reserves: Bytes,
    ) -> Result<(), AmmError> {
        let core: Address = env.storage().instance().get(&CORE).unwrap();

        if !Self::core_root_is_known(&env, &core, root.clone())? {
            return Err(AmmError::UnknownRoot);
        }

        let current_reserves: EncReserves = env.storage().persistent()
            .get(&ENC_RESERVES)
            .ok_or(AmmError::ReserveMismatch)?;

        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(root);
        pub_inputs.push_back(nf_in_0.clone());
        pub_inputs.push_back(nf_in_1.clone());
        pub_inputs.push_back(lp_commit.clone());
        pub_inputs.push_back(current_reserves.reserve_cm);
        pub_inputs.push_back(post_reserve_cm.clone());

        if !Self::core_verify(&env, &core, VkId::AddLiquidity, &proof, &pub_inputs)? {
            return Err(AmmError::BadProof);
        }

        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if nf_in_0 != zero {
            Self::core_spend(&env, &core, nf_in_0.clone())?;
        }
        if nf_in_1 != zero {
            Self::core_spend(&env, &core, nf_in_1.clone())?;
        }

        Self::core_insert(&env, &core, lp_commit.clone(), auditor_ct)?;

        env.storage().persistent().set(&ENC_RESERVES, &EncReserves {
            reserve_cm: post_reserve_cm,
            enc_data: post_enc_reserves,
        });

        // record `lp_commit` in `LP` map.
        env.storage().persistent().set(&(symbol_short!("LP"), lp_commit.clone()), &true);

        env.events().publish(
            (symbol_short!("amm"), symbol_short!("add_lp")),
            (),
        );

        Ok(())
    }

    // ── remove_liquidity ──────────────────────────────────────────────────────

    pub fn remove_liquidity(
        env: Env,
        proof: Proof,
        root: BytesN<32>,
        lp_nf: BytesN<32>,
        cm_out_0: BytesN<32>,
        cm_out_1: BytesN<32>,
        out_0_ct: Bytes,
        out_1_ct: Bytes,
        post_reserve_cm: BytesN<32>,
        post_enc_reserves: Bytes,
        lp_commit: BytesN<32>,
    ) -> Result<(), AmmError> {
        let core: Address = env.storage().instance().get(&CORE).unwrap();

        if !env.storage().persistent().has(&(symbol_short!("LP"), lp_commit.clone())) {
            return Err(AmmError::UnknownLp);
        }

        if !Self::core_root_is_known(&env, &core, root.clone())? {
            return Err(AmmError::UnknownRoot);
        }

        let current_reserves: EncReserves = env.storage().persistent()
            .get(&ENC_RESERVES)
            .ok_or(AmmError::ReserveMismatch)?;

        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(root);
        pub_inputs.push_back(lp_nf.clone());
        pub_inputs.push_back(cm_out_0.clone());
        pub_inputs.push_back(cm_out_1.clone());
        pub_inputs.push_back(current_reserves.reserve_cm);
        pub_inputs.push_back(post_reserve_cm.clone());

        if !Self::core_verify(&env, &core, VkId::RemoveLiquidity, &proof, &pub_inputs)? {
            return Err(AmmError::BadProof);
        }

        Self::core_spend(&env, &core, lp_nf.clone())?;

        let zero = BytesN::from_array(&env, &[0u8; 32]);
        if cm_out_0 != zero {
            Self::core_insert(&env, &core, cm_out_0, out_0_ct)?;
        }
        if cm_out_1 != zero {
            Self::core_insert(&env, &core, cm_out_1, out_1_ct)?;
        }

        env.storage().persistent().set(&ENC_RESERVES, &EncReserves {
            reserve_cm: post_reserve_cm,
            enc_data: post_enc_reserves,
        });

        // emit fee-accrual event
        env.events().publish(
            (symbol_short!("amm"), symbol_short!("rem_lp")),
            (),
        );

        Ok(())
    }

    // ── refund_order ──────────────────────────────────────────────────────────

    /// Re-mints a note after a batch timeout with no settlement.
    ///
    /// M7: replaced M3 address-auth with a ZK settle-or-refund proof that proves
    /// note ownership without revealing the submitter (THREAT_MODEL §6 — soundness
    /// critical; closes the // VERIFY comment from M3).
    ///
    /// Public inputs to settle_or_refund.circom (in order):
    ///   [batch_id_field, rec.nf_in, cm_refund, root, batch_deadline_field]
    ///
    /// The contract constructs batch_id and batch_deadline from on-chain state
    /// (not caller-supplied), so the proof is bound to the correct batch.
    /// The caller supplies root (validated via root_is_known) and cm_refund.
    ///
    /// Soundness guard: settle marks BSET_PFX; refund checks it; refund marks
    /// REFD_PFX so the same order cannot both settle AND refund (THREAT_MODEL §6).
    pub fn refund_order(
        env: Env,
        batch_id: u64,
        slot: u32,
        proof: Proof,
        root: BytesN<32>,
        cm_refund: BytesN<32>,
        auditor_ct: Bytes,
    ) -> Result<u64, AmmError> {
        // Cannot refund a settled batch (settle-or-refund soundness guard)
        if env.storage().persistent().has(&(BSET_PFX, batch_id)) {
            return Err(AmmError::AlreadySettled);
        }

        // Timeout must have elapsed
        let tmo: u32 = env.storage().persistent()
            .get(&(BTMO_PFX, batch_id))
            .unwrap_or(0u32);
        if env.ledger().sequence() <= tmo {
            return Err(AmmError::NotExpired);
        }

        // Order must exist and not already be refunded
        if !env.storage().persistent().has(&(ORDER_PFX, batch_id, slot)) {
            return Err(AmmError::UnknownOrder);
        }
        if env.storage().persistent().has(&(REFD_PFX, batch_id, slot)) {
            return Err(AmmError::AlreadyRefunded);
        }

        let rec: OrderRecord = env.storage().persistent()
            .get(&(ORDER_PFX, batch_id, slot))
            .unwrap();

        if auditor_ct.len() == 0 {
            return Err(AmmError::MissingAuditorCt);
        }

        let core: Address = env.storage().instance().get(&CORE).unwrap();

        // Validate root is in the recent-root window
        if !Self::core_root_is_known(&env, &core, root.clone())? {
            return Err(AmmError::UnknownRoot);
        }

        // Build public inputs for settle_or_refund.circom in circuit order:
        //   [batch_id, nf_in, cm_refund, root, batch_deadline]
        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(Self::u64_to_bytes32(&env, batch_id));
        pub_inputs.push_back(rec.nf_in.clone());
        pub_inputs.push_back(cm_refund.clone());
        pub_inputs.push_back(root);
        pub_inputs.push_back(Self::u32_to_bytes32(&env, tmo));

        if !Self::core_verify(&env, &core, VkId::SettleOrRefund, &proof, &pub_inputs)? {
            return Err(AmmError::BadProof);
        }

        // Mark refunded before external call (checks-effects-interactions)
        env.storage().persistent().set(&(REFD_PFX, batch_id, slot), &true);

        // RULE 2 + RULE 4: insert the refund note into the shared veil_core tree
        let idx = Self::core_insert(&env, &core, cm_refund, auditor_ct)?;

        env.events().publish(
            (symbol_short!("amm"), symbol_short!("refund")),
            (batch_id, slot, idx),
        );

        Ok(idx)
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn core_root_is_known(env: &Env, core: &Address, root: BytesN<32>) -> Result<bool, AmmError> {
        let f = Symbol::new(env, "root_is_known");
        let args = soroban_sdk::vec![env, root.into_val(env)];
        env.try_invoke_contract::<bool, ExtError>(core, &f, args)
            .map_err(|_| AmmError::CoreCallFailed)?
            .map_err(|_| AmmError::CoreCallFailed)
    }

    fn core_verify(
        env: &Env,
        core: &Address,
        vk_id: VkId,
        proof: &Proof,
        inputs: &Vec<BytesN<32>>,
    ) -> Result<bool, AmmError> {
        let f = Symbol::new(env, "verify_groth16");
        let args = soroban_sdk::vec![
            env,
            vk_id.into_val(env),
            proof.clone().into_val(env),
            inputs.clone().into_val(env),
        ];
        env.try_invoke_contract::<bool, ExtError>(core, &f, args)
            .map_err(|_| AmmError::BadProof)?
            .map_err(|_| AmmError::BadProof)
    }

    fn core_spend(env: &Env, core: &Address, nf: BytesN<32>) -> Result<(), AmmError> {
        let f = Symbol::new(env, "spend");
        let amm = env.current_contract_address();
        let args = soroban_sdk::vec![env, amm.into_val(env), nf.into_val(env)];
        // Any inner error (AlreadySpent, IsLocked) maps to BadProof: the swap
        // proof should have been rejected before spending a locked nullifier.
        env.try_invoke_contract::<(), ExtError>(core, &f, args)
            .map_err(|_| AmmError::CoreCallFailed)?
            .map_err(|_| AmmError::BadProof)
    }

    fn core_insert(env: &Env, core: &Address, leaf: BytesN<32>, ct: Bytes) -> Result<u64, AmmError> {
        let f = Symbol::new(env, "insert_commitment");
        let amm = env.current_contract_address();
        let args = soroban_sdk::vec![env, amm.into_val(env), leaf.into_val(env), ct.into_val(env)];
        env.try_invoke_contract::<u64, ExtError>(core, &f, args)
            .map_err(|_| AmmError::CoreCallFailed)?
            .map_err(|_| AmmError::CoreCallFailed)
    }

    /// Convert u64 to a big-endian BytesN<32> field element for use as a public input.
    fn u64_to_bytes32(env: &Env, v: u64) -> BytesN<32> {
        let mut arr = [0u8; 32];
        let be = v.to_be_bytes();
        arr[24..].copy_from_slice(&be);
        BytesN::from_array(env, &arr)
    }

    /// Convert u32 to a big-endian BytesN<32> field element for use as a public input.
    fn u32_to_bytes32(env: &Env, v: u32) -> BytesN<32> {
        let mut arr = [0u8; 32];
        let be = v.to_be_bytes();
        arr[28..].copy_from_slice(&be);
        BytesN::from_array(env, &arr)
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::{Address as _, Ledger as _}, Env};
    use veil_core::{VeilCore, VeilCoreClient};

    // Permission bits from veil_core (private consts — use their values directly)
    const PERM_INSERT: u32 = 0b001;
    const PERM_SPEND:  u32 = 0b010;

    fn dummy_proof(env: &Env) -> Proof {
        Proof {
            a: BytesN::from_array(env, &[0u8; 64]),
            b: BytesN::from_array(env, &[0u8; 128]),
            c: BytesN::from_array(env, &[0u8; 64]),
        }
    }

    fn make_bytes32(env: &Env, val: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[31] = val;
        BytesN::from_array(env, &arr)
    }

    fn make_ct(env: &Env) -> Bytes {
        let mut b = Bytes::new(env);
        b.push_back(0xca);
        b.push_back(0xfe);
        b
    }

    fn make_enc_order(env: &Env) -> Bytes {
        let mut b = Bytes::new(env);
        b.push_back(0xde);
        b
    }

    /// Set up veil_core + amm_pool and register amm_pool as a module.
    fn setup(env: &Env) -> (Address, Address, Address, Address, AmmPoolClient) {
        // Disable footprint-entry limits for all tests — budget().reset_unlimited()
        // only resets CPU/memory; the ledger-entry footprint limit (default 100)
        // is a separate InvocationResourceLimits field that we must disable here
        // so that settle_batch (K=4 × depth-32 tree) doesn't hit the cap.
        env.cost_estimate().disable_resource_limits();

        let admin     = Address::generate(env);
        let committee = Address::generate(env);
        let comm_pk   = make_bytes32(env, 0x01);

        let core_id = env.register(VeilCore, ());
        let core_client = VeilCoreClient::new(env, &core_id);
        core_client.initialize(&admin);

        let amm_id = env.register(AmmPool, ());
        let amm_client = AmmPoolClient::new(env, &amm_id);
        amm_client.initialize(&admin, &core_id, &committee, &comm_pk, &4u32);

        // Register amm_pool in veil_core with INSERT+SPEND permissions
        core_client.register_module(&admin, &amm_id, &(PERM_INSERT | PERM_SPEND));

        amm_client.initialize_reserves(&make_bytes32(env, 0), &Bytes::new(env));

        (admin, core_id, committee, amm_id, amm_client)
    }

    #[test]
    fn test_submit_order_spends_nullifier_and_stores_record() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        let submitter = Address::generate(&env);
        let nf_in = make_bytes32(&env, 42);
        let enc_order_hash = make_bytes32(&env, 99);
        let enc_order = make_enc_order(&env);

        let slot = amm.submit_order(
            &submitter,
            &dummy_proof(&env),
            &enc_order,
            &nf_in,
            &enc_order_hash,
            &root,
        );

        assert_eq!(slot, 0u32);
        assert!(core.is_spent(&nf_in), "nullifier must be spent after submit");
        assert_eq!(amm.order_count(&0u64), 1u32);
    }

    #[test]
    fn test_double_submit_same_nullifier_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        let submitter = Address::generate(&env);
        let nf_in = make_bytes32(&env, 11);

        amm.submit_order(
            &submitter,
            &dummy_proof(&env),
            &make_enc_order(&env),
            &nf_in,
            &make_bytes32(&env, 55),
            &root,
        );

        let result = amm.try_submit_order(
            &submitter,
            &dummy_proof(&env),
            &make_enc_order(&env),
            &nf_in,
            &make_bytes32(&env, 56),
            &root,
        );
        assert!(result.is_err(), "double-submit with same nullifier must fail (RULE 3)");
    }

    #[test]
    fn test_settle_batch_inserts_outputs_and_advances_batch() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, committee, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        // Submit K=4 orders
        for i in 0u8..4 {
            let submitter = Address::generate(&env);
            amm.submit_order(
                &submitter,
                &dummy_proof(&env),
                &make_enc_order(&env),
                &make_bytes32(&env, 10 + i),   // distinct nullifiers
                &make_bytes32(&env, 20 + i),   // distinct enc_order_hashes
                &root,
            );
        }

        assert_eq!(amm.order_count(&0u64), 4u32);

        // Build K=4 outputs
        let mut outputs: Vec<(BytesN<32>, Bytes)> = Vec::new(&env);
        for i in 0u8..4 {
            outputs.push_back((make_bytes32(&env, 30 + i), make_ct(&env)));
        }

        let root_before = core.current_root();
        amm.settle_batch(&0u64, &dummy_proof(&env), &outputs, &make_bytes32(&env, 0), &Bytes::new(&env));

        // Batch counter advanced
        assert_eq!(amm.current_batch(), 1u64);

        // Output commitments were inserted (tree root changed)
        assert_ne!(core.current_root(), root_before);
    }

    #[test]
    fn test_settle_requires_full_batch() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        // Submit only 2 of required 4
        for i in 0u8..2 {
            amm.submit_order(
                &Address::generate(&env),
                &dummy_proof(&env),
                &make_enc_order(&env),
                &make_bytes32(&env, 5 + i),
                &make_bytes32(&env, 15 + i),
                &root,
            );
        }

        let mut outputs: Vec<(BytesN<32>, Bytes)> = Vec::new(&env);
        for i in 0u8..4 { outputs.push_back((make_bytes32(&env, 40 + i), make_ct(&env))); }

        let result = amm.try_settle_batch(&0u64, &dummy_proof(&env), &outputs, &make_bytes32(&env, 0), &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(AmmError::BatchNotFull))));
    }

    #[test]
    fn test_settle_rejects_missing_auditor_ct() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        for i in 0u8..4 {
            amm.submit_order(
                &Address::generate(&env),
                &dummy_proof(&env),
                &make_enc_order(&env),
                &make_bytes32(&env, 60 + i),
                &make_bytes32(&env, 70 + i),
                &root,
            );
        }

        // One output missing auditor_ct (RULE 4 violation)
        let mut outputs: Vec<(BytesN<32>, Bytes)> = Vec::new(&env);
        outputs.push_back((make_bytes32(&env, 80), Bytes::new(&env)));
        for i in 1u8..4 { outputs.push_back((make_bytes32(&env, 80 + i), make_ct(&env))); }

        let result = amm.try_settle_batch(&0u64, &dummy_proof(&env), &outputs, &make_bytes32(&env, 0), &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(AmmError::MissingAuditorCt))));
    }

    #[test]
    fn test_double_settle_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        for i in 0u8..4 {
            amm.submit_order(
                &Address::generate(&env),
                &dummy_proof(&env),
                &make_enc_order(&env),
                &make_bytes32(&env, 90 + i),
                &make_bytes32(&env, 100 + i),
                &root,
            );
        }

        let mut outputs: Vec<(BytesN<32>, Bytes)> = Vec::new(&env);
        for i in 0u8..4 { outputs.push_back((make_bytes32(&env, 110 + i), make_ct(&env))); }

        amm.settle_batch(&0u64, &dummy_proof(&env), &outputs.clone(), &make_bytes32(&env, 0), &Bytes::new(&env));

        let result = amm.try_settle_batch(&0u64, &dummy_proof(&env), &outputs, &make_bytes32(&env, 0), &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(AmmError::AlreadySettled))));
    }

    #[test]
    fn test_refund_after_timeout_inserts_note() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        let submitter = Address::generate(&env);
        let nf_in = make_bytes32(&env, 77);

        amm.submit_order(
            &submitter,
            &dummy_proof(&env),
            &make_enc_order(&env),
            &nf_in,
            &make_bytes32(&env, 88),
            &root,
        );

        let tmo = amm.batch_timeout_ledger(&0u64);

        // Advance ledger past timeout
        env.ledger().with_mut(|li| {
            li.sequence_number = tmo + 1;
        });

        let cm_refund = make_bytes32(&env, 111);
        let root_before = core.current_root();
        // M7: ZK proof replaces address auth (proof bypassed in testutils mode)
        let idx = amm.refund_order(&0u64, &0u32, &dummy_proof(&env), &root, &cm_refund, &make_ct(&env));

        assert_eq!(idx, 0u64, "refund note inserted at index 0");
        // Root must have advanced (refund note inserted)
        assert_ne!(core.current_root(), root_before);
    }

    #[test]
    fn test_refund_before_timeout_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        amm.submit_order(
            &Address::generate(&env),
            &dummy_proof(&env),
            &make_enc_order(&env),
            &make_bytes32(&env, 55),
            &make_bytes32(&env, 66),
            &root,
        );

        // Do NOT advance ledger — timeout has not elapsed
        let result = amm.try_refund_order(&0u64, &0u32, &dummy_proof(&env), &root, &make_bytes32(&env, 77), &make_ct(&env));
        assert!(matches!(result, Err(Ok(AmmError::NotExpired))));
    }

    #[test]
    fn test_refund_after_settle_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        for i in 0u8..4 {
            amm.submit_order(
                &Address::generate(&env),
                &dummy_proof(&env),
                &make_enc_order(&env),
                &make_bytes32(&env, 120 + i),
                &make_bytes32(&env, 130 + i),
                &root,
            );
        }

        let mut outputs: Vec<(BytesN<32>, Bytes)> = Vec::new(&env);
        for i in 0u8..4 { outputs.push_back((make_bytes32(&env, 140 + i), make_ct(&env))); }
        amm.settle_batch(&0u64, &dummy_proof(&env), &outputs, &make_bytes32(&env, 0), &Bytes::new(&env));

        // Try to refund an order from the now-settled batch
        let tmo = amm.batch_timeout_ledger(&0u64);
        env.ledger().with_mut(|li| { li.sequence_number = tmo + 1; });

        let result = amm.try_refund_order(&0u64, &0u32, &dummy_proof(&env), &root, &make_bytes32(&env, 77), &make_ct(&env));
        assert!(
            matches!(result, Err(Ok(AmmError::AlreadySettled))),
            "same order cannot both settle AND refund (THREAT_MODEL §6)"
        );
    }

    #[test]
    fn test_double_refund_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _comm, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        amm.submit_order(
            &Address::generate(&env),
            &dummy_proof(&env),
            &make_enc_order(&env),
            &make_bytes32(&env, 33),
            &make_bytes32(&env, 44),
            &root,
        );

        let tmo = amm.batch_timeout_ledger(&0u64);
        env.ledger().with_mut(|li| { li.sequence_number = tmo + 1; });

        amm.refund_order(&0u64, &0u32, &dummy_proof(&env), &root, &make_bytes32(&env, 50), &make_ct(&env));

        let result = amm.try_refund_order(&0u64, &0u32, &dummy_proof(&env), &root, &make_bytes32(&env, 51), &make_ct(&env));
        assert!(matches!(result, Err(Ok(AmmError::AlreadyRefunded))));
    }

    #[test]
    fn test_add_and_remove_liquidity() {
        let env = Env::default();
        env.mock_all_auths();
        env.cost_estimate().budget().reset_unlimited();

        let (_admin, core_id, _committee, _amm_id, amm) = setup(&env);
        let core = VeilCoreClient::new(&env, &core_id);
        let root = core.current_root();

        let lp_commit = make_bytes32(&env, 100);
        let nf_in_0 = make_bytes32(&env, 101);
        let nf_in_1 = make_bytes32(&env, 102);
        
        let mut enc_res_data = Bytes::new(&env);
        enc_res_data.push_back(1); // dummy

        amm.add_liquidity(
            &dummy_proof(&env),
            &root,
            &nf_in_0,
            &nf_in_1,
            &lp_commit,
            &make_ct(&env),
            &make_bytes32(&env, 200),
            &enc_res_data,
        );

        assert!(core.is_spent(&nf_in_0));
        assert!(core.is_spent(&nf_in_1));

        let lp_nf = make_bytes32(&env, 103);
        let cm_out_0 = make_bytes32(&env, 104);
        let cm_out_1 = make_bytes32(&env, 105);

        let root2 = core.current_root();

        amm.remove_liquidity(
            &dummy_proof(&env),
            &root2,
            &lp_nf,
            &cm_out_0,
            &cm_out_1,
            &make_ct(&env),
            &make_ct(&env),
            &make_bytes32(&env, 201),
            &enc_res_data,
            &lp_commit,
        );

        assert!(core.is_spent(&lp_nf));

        // Double remove -> AlreadySpent (maps to BadProof in core_spend)
        let result = amm.try_remove_liquidity(
            &dummy_proof(&env),
            &root2,
            &lp_nf,
            &make_bytes32(&env, 106),
            &make_bytes32(&env, 107),
            &make_ct(&env),
            &make_ct(&env),
            &make_bytes32(&env, 202),
            &enc_res_data,
            &lp_commit,
        );
        assert!(result.is_err());

        // UnknownLp
        let result2 = amm.try_remove_liquidity(
            &dummy_proof(&env),
            &root2,
            &make_bytes32(&env, 108),
            &make_bytes32(&env, 109),
            &make_bytes32(&env, 110),
            &make_ct(&env),
            &make_ct(&env),
            &make_bytes32(&env, 203),
            &enc_res_data,
            &make_bytes32(&env, 255), // wrong lp_commit
        );
        assert!(matches!(result2, Err(Ok(AmmError::UnknownLp))));
    }
}
