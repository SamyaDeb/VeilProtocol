#![no_std]

mod poseidon;
mod verifier;

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype,
    symbol_short, Address, Bytes, BytesN, Env, IntoVal, Map, Symbol, Vec,
};

// ─── error enum ───────────────────────────────────────────────────────────────

#[contracterror]
#[derive(Clone, Debug, PartialEq)]
pub enum VeilError {
    Unauthorized        = 1,
    AspRejected         = 2,
    BadProof            = 3,
    MissingAuditorCt    = 4,
    AlreadySpent        = 5,
    IsLocked            = 6,
    AlreadyLocked       = 7,
    NotLocked           = 8,
    UnknownVk           = 9,
    MalformedProof      = 10,
    TreeFull            = 11,
    UnknownRoot         = 12,
    InvalidPublicAmount = 13,
    RecipientMismatch   = 14,
}

// ─── storage keys ─────────────────────────────────────────────────────────────

const ADMIN:       Symbol = symbol_short!("ADMIN");
const MODULES:     Symbol = symbol_short!("MODULES");
const NEXT_INDEX:  Symbol = symbol_short!("NEXT_IDX");
const ROOTS:       Symbol = symbol_short!("ROOTS");
const AUDITOR_PK:  Symbol = symbol_short!("AUD_PK");
const VK_MAP:      Symbol = symbol_short!("VK_MAP");

// Persistent storage key prefixes (Map keys)
const TREE_PREFIX:   Symbol = symbol_short!("TREE");
const SPENT_PREFIX:  Symbol = symbol_short!("SPENT");
const LOCKED_PREFIX: Symbol = symbol_short!("LOCKED");
const AUDITCT_PREFIX:Symbol = symbol_short!("AUD_CT");

// Recent-root window size
const ROOT_WINDOW: u32 = 50;

// Merkle tree depth (CIRCUITS.md §0).
// Tests use a shallow depth to stay within the default Soroban footprint limit
// (100 ledger entries). Each insert accesses 2*depth+1 tree keys; at depth=32
// that is 65 keys alone, and Soroban counts additional overhead per invocation.
// Production always uses 32.
#[cfg(not(test))]
const TREE_DEPTH: u32 = 32;
#[cfg(test)]
const TREE_DEPTH: u32 = 5;

// TTL thresholds for persistent storage entries (ledger entries).
const LOW_TTL:  u32 = 100_000;
const HIGH_TTL: u32 = 500_000;

// Instance storage key for the pending admin (two-step admin transfer).
const PENDING_ADMIN: Symbol = symbol_short!("PEND_ADM");

// ─── permission bits ──────────────────────────────────────────────────────────

const PERM_INSERT: u32 = 0b001;
const PERM_SPEND:  u32 = 0b010;
const PERM_LOCK:   u32 = 0b100;

// ─── VK identifier ────────────────────────────────────────────────────────────

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
    Lend,
    SettleOrRefund,
    Repay,
}

// ─── proof types ──────────────────────────────────────────────────────────────

/// Groth16 proof: A∈G1 (64B), B∈G2 (128B), C∈G1 (64B) — total 256 bytes.
#[contracttype]
#[derive(Clone)]
pub struct Proof {
    pub a: BytesN<64>,
    pub b: BytesN<128>,
    pub c: BytesN<64>,
}

/// Public signals for the deposit circuit (must match circuit public input order).
#[contracttype]
#[derive(Clone)]
pub struct DepositPublic {
    pub cm:               BytesN<32>,
    pub public_amount:    BytesN<32>,
    pub asp_approved_root: BytesN<32>,
    pub asp_blocked_root:  BytesN<32>,
}

/// Public signals for the transfer circuit
#[contracttype]
#[derive(Clone)]
pub struct TransferPublic {
    pub root:          BytesN<32>,
    pub nf_in_0:       BytesN<32>,
    pub nf_in_1:       BytesN<32>,
    pub cm_out_0:      BytesN<32>,
    pub cm_out_1:      BytesN<32>,
    pub public_amount: BytesN<32>,
}

/// Public signals for the withdraw circuit (must match circuit public input order).
/// Order: root, nf_in_0, nf_in_1, cm_change, public_amount, asset_id, recipient_hash
#[contracttype]
#[derive(Clone)]
pub struct WithdrawPublic {
    pub root:           BytesN<32>,
    pub nf_in_0:        BytesN<32>,
    pub nf_in_1:        BytesN<32>,
    pub cm_change:      BytesN<32>,  // change note commitment; zero if no change
    pub public_amount:  BytesN<32>,  // amount exiting to the public recipient
    pub asset_id:       BytesN<32>,
    pub recipient_hash: BytesN<32>,  // Poseidon(recipient); verified by relayer path
}

// ─── asp cross-contract interface ─────────────────────────────────────────────
// Built against the asp wasm. Build asp first: `stellar contract build -p asp`
// VERIFY: keep Cargo.toml [features] in sync if wasm path changes.

pub mod asp_interface {
    use soroban_sdk::{contracttype, BytesN, Vec};

    #[contracttype]
    #[derive(Clone)]
    pub struct AspMembershipProof {
        pub credential_leaf:     BytesN<32>,
        pub approved_path:       Vec<BytesN<32>>,
        pub approved_idx:        Vec<u32>,
        pub blocked_lower_leaf:  BytesN<32>,
        pub blocked_upper_leaf:  BytesN<32>,
        pub blocked_lower_path:  Vec<BytesN<32>>,
        pub blocked_lower_idx:   Vec<u32>,
        pub blocked_upper_path:  Vec<BytesN<32>>,
        pub blocked_upper_idx:   Vec<u32>,
        pub approved_root:       BytesN<32>,
        pub blocked_root:        BytesN<32>,
    }
}

// ─── contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct VeilCore;

#[contractimpl]
impl VeilCore {
    // ── init ─────────────────────────────────────────────────────────────────

    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&ADMIN) {
            panic!("already initialized");
        }
        env.storage().instance().set(&ADMIN, &admin);
        env.storage().persistent().set(&NEXT_INDEX, &0u64);
        let roots: Vec<BytesN<32>> = Vec::new(&env);
        env.storage().persistent().set(&ROOTS, &roots);
        let mods: Map<Address, u32> = Map::new(&env);
        env.storage().persistent().set(&MODULES, &mods);
        // Insert initial empty-tree root (all zeros)
        Self::init_empty_tree_root(&env);
    }

    // ── admin ─────────────────────────────────────────────────────────────────

    /// Step 1: current admin proposes a new admin; stores it as pending.
    /// The new admin must call `accept_admin` to complete the transfer.
    /// This two-step pattern prevents accidental key loss (SECURITY.md §3).
    pub fn propose_admin(env: Env, admin: Address, new_admin: Address) -> Result<(), VeilError> {
        Self::require_admin(&env, &admin)?;
        admin.require_auth();
        env.storage().instance().set(&PENDING_ADMIN, &new_admin);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("proposed")),
            new_admin,
        );
        Ok(())
    }

    /// Step 2: the pending admin accepts, becoming the active admin.
    pub fn accept_admin(env: Env, new_admin: Address) -> Result<(), VeilError> {
        new_admin.require_auth();
        let pending: Address = env.storage().instance()
            .get(&PENDING_ADMIN)
            .ok_or(VeilError::Unauthorized)?;
        if new_admin != pending {
            return Err(VeilError::Unauthorized);
        }
        env.storage().instance().set(&ADMIN, &new_admin);
        env.storage().instance().remove(&PENDING_ADMIN);
        env.events().publish(
            (symbol_short!("admin"), symbol_short!("accepted")),
            new_admin,
        );
        Ok(())
    }

    pub fn set_auditor_pubkey(env: Env, admin: Address, pk: BytesN<32>) -> Result<(), VeilError> {
        Self::require_admin(&env, &admin)?;
        admin.require_auth();
        env.storage().instance().set(&AUDITOR_PK, &pk);
        Ok(())
    }

    pub fn auditor_pubkey(env: Env) -> BytesN<32> {
        env.storage().instance().get(&AUDITOR_PK).unwrap()
    }

    pub fn register_module(
        env: Env,
        admin: Address,
        module: Address,
        perms: u32,
    ) -> Result<(), VeilError> {
        Self::require_admin(&env, &admin)?;
        admin.require_auth();
        let mut mods: Map<Address, u32> = env.storage().persistent().get(&MODULES).unwrap();
        mods.set(module, perms);
        env.storage().persistent().set(&MODULES, &mods);
        Ok(())
    }

    pub fn init_vk(env: Env, admin: Address, vk_id: VkId, vk_bytes: Bytes) -> Result<(), VeilError> {
        Self::require_admin(&env, &admin)?;
        admin.require_auth();
        let mut vk_map: Map<VkId, Bytes> = env.storage().instance()
            .get(&VK_MAP)
            .unwrap_or(Map::new(&env));
        vk_map.set(vk_id, vk_bytes);
        env.storage().instance().set(&VK_MAP, &vk_map);
        Ok(())
    }

    /// Read the stored VK bytes for a circuit (used by vk-verify tool to compare
    /// on-chain bytes to the pinned circuit-keys/ bin).
    pub fn get_vk(env: Env, vk_id: VkId) -> Option<Bytes> {
        let vk_map: Map<VkId, Bytes> = env.storage().instance()
            .get(&VK_MAP)
            .unwrap_or(Map::new(&env));
        vk_map.get(vk_id)
    }

    /// Extend the TTL of persistent storage entries to HIGH_TTL.
    /// Called by the keeper job before entries approach archival.
    /// Each key in `keys` is extended; non-existent keys are silently skipped.
    /// (CONTRACTS.md §1 TTL strategy, SECURITY.md §3)
    pub fn bump_ttl(env: Env, admin: Address, keys: Vec<soroban_sdk::Val>) -> Result<(), VeilError> {
        Self::require_admin(&env, &admin)?;
        admin.require_auth();
        let count = keys.len();
        for key in keys.iter() {
            env.storage().persistent().extend_ttl(&key, LOW_TTL, HIGH_TTL);
        }
        env.events().publish(
            (symbol_short!("bump_ttl"), symbol_short!("done")),
            count,
        );
        Ok(())
    }

    // ── merkle tree ───────────────────────────────────────────────────────────

    pub fn current_root(env: Env) -> BytesN<32> {
        let roots: Vec<BytesN<32>> = env.storage().persistent().get(&ROOTS).unwrap();
        roots.last().unwrap()
    }

    pub fn root_is_known(env: Env, root: BytesN<32>) -> bool {
        let roots: Vec<BytesN<32>> = env.storage().persistent().get(&ROOTS).unwrap_or(Vec::new(&env));
        for r in roots.iter() {
            if r == root {
                return true;
            }
        }
        false
    }

    // ── deposit ───────────────────────────────────────────────────────────────

    pub fn deposit(
        env: Env,
        depositor: Address,
        token_contract: Address,
        asp_contract: Address,
        proof: Proof,
        public: DepositPublic,
        asp_proof: asp_interface::AspMembershipProof,
        auditor_ct: Bytes,
    ) -> Result<u64, VeilError> {
        // RULE 1: ASP gate — must pass before anything else.
        // Cross-contract call to asp.check_entry.
        let veil_addr = env.current_contract_address();
        let asp_fn = soroban_sdk::Symbol::new(&env, "check_entry");
        let asp_args = soroban_sdk::vec![
            &env,
            veil_addr.into_val(&env),
            asp_proof.into_val(&env),
        ];
        env.try_invoke_contract::<(), VeilError>(&asp_contract, &asp_fn, asp_args)
            .map_err(|_| VeilError::AspRejected)?
            .map_err(|_| VeilError::AspRejected)?;

        // Verify the deposit ZK proof
        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(public.cm.clone());
        pub_inputs.push_back(public.public_amount.clone());
        pub_inputs.push_back(public.asp_approved_root.clone());
        pub_inputs.push_back(public.asp_blocked_root.clone());

        if !Self::verify_groth16_internal(&env, &VkId::Deposit, &proof, &pub_inputs)? {
            return Err(VeilError::BadProof);
        }

        // Pull token from depositor into this contract (skipped in test — no real token)
        // VERIFY: soroban_sdk::token::Client availability and transfer fn in soroban-sdk 26.x
        #[cfg(not(test))]
        {
            let amount = Self::bytes32_to_amount(&public.public_amount);
            let token = soroban_sdk::token::Client::new(&env, &token_contract);
            token.transfer(&depositor, &env.current_contract_address(), &amount);
        }
        #[cfg(test)]
        {
            let _ = depositor;
            let _ = token_contract;
        }

        // RULE 4: insert commitment with auditor ciphertext
        let idx = Self::insert_commitment_internal(
            &env,
            &env.current_contract_address(),
            public.cm,
            auditor_ct,
        )?;

        Ok(idx)
    }

    // ── withdraw ──────────────────────────────────────────────────────────────

    /// Shielded withdraw: burns input notes, pays `public_amount` to `recipient`,
    /// and optionally creates a shielded change note (RULE 3 + RULE 4).
    ///
    /// `change_ct` must be non-empty when `public.cm_change` is non-zero (RULE 4).
    /// The `public.recipient_hash` is emitted in the event; full binding via
    /// Poseidon(recipient) is enforced by the relayer path. // VERIFY when relayer lands
    pub fn withdraw(
        env: Env,
        token_contract: Address,
        recipient: Address,
        proof: Proof,
        public: WithdrawPublic,
        change_ct: Bytes,
    ) -> Result<Option<u64>, VeilError> {
        let zero = BytesN::from_array(&env, &[0u8; 32]);

        if public.public_amount == zero {
            return Err(VeilError::InvalidPublicAmount);
        }

        if !Self::root_is_known(env.clone(), public.root.clone()) {
            return Err(VeilError::UnknownRoot);
        }

        // Build public inputs in circuit order (matches WithdrawPublic + circuit header)
        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(public.root.clone());
        pub_inputs.push_back(public.nf_in_0.clone());
        pub_inputs.push_back(public.nf_in_1.clone());
        pub_inputs.push_back(public.cm_change.clone());
        pub_inputs.push_back(public.public_amount.clone());
        pub_inputs.push_back(public.asset_id.clone());
        pub_inputs.push_back(public.recipient_hash.clone());

        if !Self::verify_groth16_internal(&env, &VkId::Withdraw, &proof, &pub_inputs)? {
            return Err(VeilError::BadProof);
        }

        // RULE 3: spend non-zero input nullifiers (rejected if in SPENT or LOCKED)
        if public.nf_in_0 != zero {
            Self::spend_internal(&env, public.nf_in_0.clone())?;
        }
        if public.nf_in_1 != zero {
            Self::spend_internal(&env, public.nf_in_1.clone())?;
        }

        // RULE 4: insert change note with auditor ciphertext if present
        let change_idx: Option<u64> = if public.cm_change != zero {
            let idx = Self::insert_commitment_internal(
                &env,
                &env.current_contract_address(),
                public.cm_change.clone(),
                change_ct,
            )?;
            Some(idx)
        } else {
            None
        };

        // Transfer public_amount of the token to the recipient
        // VERIFY: soroban_sdk::token::Client availability in soroban-sdk 26.x
        #[cfg(not(test))]
        {
            let amount = Self::bytes32_to_amount(&public.public_amount);
            let token = soroban_sdk::token::Client::new(&env, &token_contract);
            token.transfer(&env.current_contract_address(), &recipient, &amount);
        }
        #[cfg(test)]
        {
            let _ = token_contract;
        }

        env.events().publish(
            (symbol_short!("withdraw"), symbol_short!("done")),
            (recipient, public.public_amount, change_idx),
        );

        Ok(change_idx)
    }

    // ── commitments ───────────────────────────────────────────────────────────

    pub fn insert_commitment(
        env: Env,
        caller: Address,
        leaf: BytesN<32>,
        auditor_ct: Bytes,
    ) -> Result<u64, VeilError> {
        caller.require_auth();
        Self::require_perm(&env, &caller, PERM_INSERT)?;
        Self::insert_commitment_internal(&env, &caller, leaf, auditor_ct)
    }

    pub fn ciphertext_at(env: Env, idx: u64) -> Bytes {
        let key = (AUDITCT_PREFIX, idx);
        env.storage().persistent().get(&key).unwrap_or(Bytes::new(&env))
    }

    // ── transfer ──────────────────────────────────────────────────────────────

    pub fn transfer(
        env: Env,
        proof: Proof,
        public: TransferPublic,
        output_cts: Vec<Bytes>,
        note_cts: Vec<Bytes>,
    ) -> Result<Vec<u64>, VeilError> {
        let zero_amount = BytesN::from_array(&env, &[0u8; 32]);
        if public.public_amount != zero_amount {
            return Err(VeilError::InvalidPublicAmount);
        }

        if !Self::root_is_known(env.clone(), public.root.clone()) {
            return Err(VeilError::UnknownRoot);
        }

        let mut pub_inputs: Vec<BytesN<32>> = Vec::new(&env);
        pub_inputs.push_back(public.root.clone());
        pub_inputs.push_back(public.nf_in_0.clone());
        pub_inputs.push_back(public.nf_in_1.clone());
        pub_inputs.push_back(public.cm_out_0.clone());
        pub_inputs.push_back(public.cm_out_1.clone());
        pub_inputs.push_back(public.public_amount.clone());

        if !Self::verify_groth16_internal(&env, &VkId::Transfer, &proof, &pub_inputs)? {
            return Err(VeilError::BadProof);
        }

        let zero_nf = BytesN::from_array(&env, &[0u8; 32]);
        let caller = env.current_contract_address(); // Self auth

        // M1: In transfer, the caller acts as itself. But we need SPEND/INSERT perms. 
        // Wait, the veil_core contract calls itself, so it needs perms? No, we can just call internal.
        // Actually, we don't need require_perm internally, just do it inline.

        if public.nf_in_0 != zero_nf {
            Self::spend_internal(&env, public.nf_in_0.clone())?;
        }
        if public.nf_in_1 != zero_nf {
            Self::spend_internal(&env, public.nf_in_1.clone())?;
        }

        let mut indices: Vec<u64> = Vec::new(&env);

        if public.cm_out_0 != zero_nf {
            let out_ct = output_cts.get(0).unwrap_or(Bytes::new(&env));
            let idx = Self::insert_commitment_internal(&env, &caller, public.cm_out_0.clone(), out_ct)?;
            indices.push_back(idx);
            let note_ct = note_cts.get(0).unwrap_or(Bytes::new(&env));
            env.events().publish((symbol_short!("transfer"), symbol_short!("note")), (idx, note_ct));
        }

        if public.cm_out_1 != zero_nf {
            let out_ct = output_cts.get(1).unwrap_or(Bytes::new(&env));
            let idx = Self::insert_commitment_internal(&env, &caller, public.cm_out_1.clone(), out_ct)?;
            indices.push_back(idx);
            let note_ct = note_cts.get(1).unwrap_or(Bytes::new(&env));
            env.events().publish((symbol_short!("transfer"), symbol_short!("note")), (idx, note_ct));
        }

        Ok(indices)
    }

    // ── auditor disclosure ────────────────────────────────────────────────────

    /// Return the stored auditor ciphertext for a commitment index and log the
    /// request for audit-trail purposes. Decryption is off-chain. (SECURITY.md §6)
    pub fn request_disclosure(env: Env, auditor: Address, idx: u64) -> Bytes {
        auditor.require_auth();
        let ct: Bytes = env.storage().persistent()
            .get(&(AUDITCT_PREFIX, idx))
            .unwrap_or(Bytes::new(&env));
        env.events().publish(
            (symbol_short!("disclose"), symbol_short!("req")),
            (auditor, idx),
        );
        ct
    }

    // ── verification ──────────────────────────────────────────────────────────

    pub fn verify_groth16(
        env: Env,
        vk_id: VkId,
        proof: Proof,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, VeilError> {
        Self::verify_groth16_internal(&env, &vk_id, &proof, &public_inputs)
    }

    // ── nullifiers (RULE 3 — two distinct sets) ───────────────────────────────

    pub fn spend(env: Env, caller: Address, nf: BytesN<32>) -> Result<(), VeilError> {
        caller.require_auth();
        Self::require_perm(&env, &caller, PERM_SPEND)?;

        let spent_key  = (SPENT_PREFIX,  nf.clone());
        let locked_key = (LOCKED_PREFIX, nf.clone());

        if env.storage().persistent().has(&spent_key) {
            return Err(VeilError::AlreadySpent);
        }
        if env.storage().persistent().has(&locked_key) {
            return Err(VeilError::IsLocked);
        }

        env.storage().persistent().set(&spent_key, &true);
        env.storage().persistent().extend_ttl(&spent_key, LOW_TTL, HIGH_TTL);
        env.events().publish((symbol_short!("nullify"), symbol_short!("spent")), nf);
        Ok(())
    }

    pub fn lock(env: Env, caller: Address, nf: BytesN<32>) -> Result<(), VeilError> {
        caller.require_auth();
        Self::require_perm(&env, &caller, PERM_LOCK)?;

        let spent_key  = (SPENT_PREFIX,  nf.clone());
        let locked_key = (LOCKED_PREFIX, nf.clone());

        if env.storage().persistent().has(&spent_key) {
            return Err(VeilError::AlreadySpent);
        }
        if env.storage().persistent().has(&locked_key) {
            return Err(VeilError::AlreadyLocked);
        }

        env.storage().persistent().set(&locked_key, &true);
        env.events().publish((symbol_short!("nullify"), symbol_short!("locked")), nf);
        Ok(())
    }

    pub fn unlock(env: Env, caller: Address, nf: BytesN<32>) -> Result<(), VeilError> {
        caller.require_auth();
        Self::require_perm(&env, &caller, PERM_LOCK)?;

        let locked_key = (LOCKED_PREFIX, nf.clone());
        if !env.storage().persistent().has(&locked_key) {
            return Err(VeilError::NotLocked);
        }

        env.storage().persistent().remove(&locked_key);
        env.events().publish((symbol_short!("nullify"), symbol_short!("unlock")), nf);
        Ok(())
    }

    pub fn is_spent(env: Env, nf: BytesN<32>) -> bool {
        env.storage().persistent().has(&(SPENT_PREFIX, nf))
    }

    pub fn is_locked(env: Env, nf: BytesN<32>) -> bool {
        env.storage().persistent().has(&(LOCKED_PREFIX, nf))
    }

    // ── private helpers ───────────────────────────────────────────────────────

    fn require_admin(env: &Env, caller: &Address) -> Result<(), VeilError> {
        let admin: Address = env.storage().instance().get(&ADMIN).unwrap();
        if caller != &admin {
            Err(VeilError::Unauthorized)
        } else {
            Ok(())
        }
    }

    fn require_perm(env: &Env, caller: &Address, perm: u32) -> Result<(), VeilError> {
        let mods: Map<Address, u32> = env.storage().persistent().get(&MODULES).unwrap_or(Map::new(env));
        let caller_perms = mods.get(caller.clone()).unwrap_or(0);
        if caller_perms & perm == 0 {
            Err(VeilError::Unauthorized)
        } else {
            Ok(())
        }
    }

    /// Convert a 32-byte big-endian field element to i128 for token transfers.
    /// Amount is range-checked to [0, 2^64) in-circuit so only the bottom 8 bytes matter.
    fn bytes32_to_amount(b: &BytesN<32>) -> i128 {
        let mut amount: u64 = 0;
        for i in 24u32..32u32 {
            amount = (amount << 8) | (b.get(i).unwrap_or(0) as u64);
        }
        amount as i128
    }

    fn spend_internal(env: &Env, nf: BytesN<32>) -> Result<(), VeilError> {
        let spent_key  = (SPENT_PREFIX,  nf.clone());
        let locked_key = (LOCKED_PREFIX, nf.clone());

        if env.storage().persistent().has(&spent_key) {
            return Err(VeilError::AlreadySpent);
        }
        if env.storage().persistent().has(&locked_key) {
            return Err(VeilError::IsLocked);
        }

        env.storage().persistent().set(&spent_key, &true);
        env.storage().persistent().extend_ttl(&spent_key, LOW_TTL, HIGH_TTL);
        env.events().publish((symbol_short!("nullify"), symbol_short!("spent")), nf);
        Ok(())
    }

    fn insert_commitment_internal(
        env: &Env,
        _caller: &Address,
        leaf: BytesN<32>,
        auditor_ct: Bytes,
    ) -> Result<u64, VeilError> {
        // RULE 4: require non-empty auditor ciphertext
        if auditor_ct.len() == 0 {
            return Err(VeilError::MissingAuditorCt);
        }

        let idx: u64 = env.storage().persistent().get(&NEXT_INDEX).unwrap_or(0u64);

        // Tree size = 2^32 leaves
        if idx >= (1u64 << TREE_DEPTH) {
            return Err(VeilError::TreeFull);
        }

        // Update the incremental Merkle tree and recompute root
        let new_root = poseidon::insert_leaf(env, idx, &leaf);

        // Update NEXT_INDEX
        env.storage().persistent().set(&NEXT_INDEX, &(idx + 1));

        // Update root ring buffer
        let mut roots: Vec<BytesN<32>> = env.storage().persistent().get(&ROOTS).unwrap_or(Vec::new(env));
        roots.push_back(new_root.clone());
        if roots.len() > ROOT_WINDOW {
            roots.pop_front();
        }
        env.storage().persistent().set(&ROOTS, &roots);

        // RULE 4: store auditor ciphertext at this leaf index
        env.storage().persistent().set(&(AUDITCT_PREFIX, idx), &auditor_ct);

        // Emit event for the indexer
        env.events().publish(
            (symbol_short!("leaf"), symbol_short!("inserted")),
            (leaf, idx, auditor_ct),
        );

        Ok(idx)
    }

    fn verify_groth16_internal(
        env: &Env,
        vk_id: &VkId,
        proof: &Proof,
        public_inputs: &Vec<BytesN<32>>,
    ) -> Result<bool, VeilError> {
        // Bypass real BN254 verification in test/testutils builds.
        // "testutils" feature is active when used as a dev-dep by other crates.
        #[cfg(any(test, feature = "testutils"))]
        {
            let _ = (env, vk_id, proof, public_inputs);
            return Ok(true);
        }
        #[cfg(not(any(test, feature = "testutils")))]
        {
            let vk_map: Map<VkId, Bytes> = env.storage().instance()
                .get(&VK_MAP)
                .unwrap_or(Map::new(env));

            let vk_bytes = vk_map.get(vk_id.clone()).ok_or(VeilError::UnknownVk)?;
            verifier::groth16_verify(env, &vk_bytes, proof, public_inputs)
                .map_err(|_| VeilError::MalformedProof)
        }
    }

    fn init_empty_tree_root(env: &Env) {
        // Compute the root of an empty D=32 tree (all zeros)
        let empty_root = poseidon::empty_tree_root(env);
        let mut roots: Vec<BytesN<32>> = Vec::new(env);
        roots.push_back(empty_root);
        env.storage().persistent().set(&ROOTS, &roots);
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{testutils::Address as _, Env};

    fn make_leaf(env: &Env, val: u8) -> BytesN<32> {
        let mut arr = [0u8; 32];
        arr[31] = val;
        BytesN::from_array(env, &arr)
    }

    fn make_ct(env: &Env) -> Bytes {
        let mut b = Bytes::new(env);
        b.push_back(0xde);
        b.push_back(0xad);
        b.push_back(0xbe);
        b.push_back(0xef);
        b
    }

    fn init_contract(env: &Env) -> (Address, Address) {
        let admin = Address::generate(env);
        let contract_id = env.register(VeilCore, ());
        let client = VeilCoreClient::new(env, &contract_id);
        client.initialize(&admin);
        (admin, contract_id)
    }

    #[test]
    fn test_empty_tree_root_set() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);
        // Root should be set (non-zero empty tree root)
        let root = client.current_root();
        // Just verify it's deterministic (not all-zero after poseidon)
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        assert_ne!(root, zero);
    }

    #[test]
    fn test_insert_commitment_requires_auditor_ct() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        // Register a module with INSERT perm
        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_INSERT);

        let leaf = make_leaf(&env, 1);
        let empty_ct = Bytes::new(&env);

        let result = client.try_insert_commitment(&module, &leaf, &empty_ct);
        assert!(matches!(
            result,
            Err(Ok(VeilError::MissingAuditorCt))
        ));
    }

    #[test]
    fn test_insert_commitment_unregistered_caller_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let stranger = Address::generate(&env);
        let leaf = make_leaf(&env, 1);
        let ct = make_ct(&env);

        let result = client.try_insert_commitment(&stranger, &leaf, &ct);
        assert!(matches!(
            result,
            Err(Ok(VeilError::Unauthorized))
        ));
    }

    #[test]
    fn test_insert_increments_index_and_updates_root() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_INSERT);

        let root0 = client.current_root();

        let leaf1 = make_leaf(&env, 1);
        let ct = make_ct(&env);
        let idx1 = client.insert_commitment(&module, &leaf1, &ct);
        assert_eq!(idx1, 0u64);

        let root1 = client.current_root();
        assert_ne!(root0, root1);

        let leaf2 = make_leaf(&env, 2);
        let idx2 = client.insert_commitment(&module, &leaf2, &ct);
        assert_eq!(idx2, 1u64);

        let root2 = client.current_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_root_is_known_recent_roots() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_INSERT);

        // Insert a leaf
        let leaf = make_leaf(&env, 42);
        let ct = make_ct(&env);
        client.insert_commitment(&module, &leaf, &ct);

        let root = client.current_root();
        assert!(client.root_is_known(&root));

        // A random root should not be known
        let fake_root = make_leaf(&env, 99);
        assert!(!client.root_is_known(&fake_root));
    }

    #[test]
    fn test_spend_rejects_double_spend() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &(PERM_SPEND | PERM_INSERT));

        let nf = make_leaf(&env, 7);
        client.spend(&module, &nf);

        let result = client.try_spend(&module, &nf);
        assert!(matches!(result, Err(Ok(VeilError::AlreadySpent))));
    }

    #[test]
    fn test_spend_rejects_locked_nullifier() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &(PERM_SPEND | PERM_LOCK));

        let nf = make_leaf(&env, 8);
        client.lock(&module, &nf);

        let result = client.try_spend(&module, &nf);
        assert!(matches!(result, Err(Ok(VeilError::IsLocked))));
    }

    #[test]
    fn test_lock_then_unlock() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &(PERM_SPEND | PERM_LOCK));

        let nf = make_leaf(&env, 9);
        client.lock(&module, &nf);
        assert!(client.is_locked(&nf));

        client.unlock(&module, &nf);
        assert!(!client.is_locked(&nf));

        // After unlock, can spend
        client.spend(&module, &nf);
        assert!(client.is_spent(&nf));
    }

    #[test]
    fn test_ciphertext_stored_at_correct_index() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_INSERT);

        let leaf = make_leaf(&env, 1);
        let ct = make_ct(&env);
        let idx = client.insert_commitment(&module, &leaf, &ct);

        let retrieved_ct = client.ciphertext_at(&idx);
        assert_eq!(retrieved_ct, ct);
    }

    #[test]
    fn test_spend_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let stranger = Address::generate(&env);
        let nf = make_leaf(&env, 77);
        let result = client.try_spend(&stranger, &nf);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));
    }

    #[test]
    fn test_transfer_success_and_invariants() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();

        // 2-in / 2-out: we spend nf_in_0, keep nf_in_1 as zero (dummy).
        // We create cm_out_0 and cm_out_1.
        let nf_in_0 = make_leaf(&env, 10);
        let nf_in_1 = BytesN::from_array(&env, &[0u8; 32]);
        let cm_out_0 = make_leaf(&env, 20);
        let cm_out_1 = make_leaf(&env, 30);
        let public_amount = BytesN::from_array(&env, &[0u8; 32]);

        let public_inputs = TransferPublic {
            root: root.clone(),
            nf_in_0: nf_in_0.clone(),
            nf_in_1: nf_in_1.clone(),
            cm_out_0: cm_out_0.clone(),
            cm_out_1: cm_out_1.clone(),
            public_amount: public_amount.clone(),
        };

        let dummy_proof = Proof {
            a: BytesN::from_array(&env, &[0u8; 64]),
            b: BytesN::from_array(&env, &[0u8; 128]),
            c: BytesN::from_array(&env, &[0u8; 64]),
        };

        let output_ct0 = make_ct(&env);
        let mut output_ct1 = make_ct(&env);
        output_ct1.push_back(0x42); // make them different

        let note_ct0 = make_ct(&env);
        let note_ct1 = make_ct(&env);

        let mut output_cts = Vec::new(&env);
        output_cts.push_back(output_ct0.clone());
        output_cts.push_back(output_ct1.clone());

        let mut note_cts = Vec::new(&env);
        note_cts.push_back(note_ct0);
        note_cts.push_back(note_ct1);

        // Call transfer!
        let indices = client.transfer(&dummy_proof, &public_inputs, &output_cts, &note_cts);
        assert_eq!(indices.len(), 2);
        assert_eq!(indices.get(0).unwrap(), 0u64);
        assert_eq!(indices.get(1).unwrap(), 1u64);

        // Verify spent nullifiers
        assert!(client.is_spent(&nf_in_0));
        assert!(!client.is_spent(&nf_in_1));

        // Verify stored ciphertexts
        assert_eq!(client.ciphertext_at(&0u64), output_ct0);
        assert_eq!(client.ciphertext_at(&1u64), output_ct1);

        // Verify root advanced
        assert_ne!(client.current_root(), root);

        // Verify replaying spent nullifiers fails
        let result = client.try_transfer(&dummy_proof, &public_inputs, &output_cts, &note_cts);
        assert!(matches!(result, Err(Ok(VeilError::AlreadySpent))));
    }

    #[test]
    fn test_transfer_invalid_public_amount() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();
        let nf_in_0 = make_leaf(&env, 10);
        let nf_in_1 = BytesN::from_array(&env, &[0u8; 32]);
        let cm_out_0 = make_leaf(&env, 20);
        let cm_out_1 = make_leaf(&env, 30);
        let mut pub_amt = [0u8; 32];
        pub_amt[31] = 100;
        let public_amount = BytesN::from_array(&env, &pub_amt);

        let public_inputs = TransferPublic {
            root,
            nf_in_0,
            nf_in_1,
            cm_out_0,
            cm_out_1,
            public_amount,
        };

        let dummy_proof = Proof {
            a: BytesN::from_array(&env, &[0u8; 64]),
            b: BytesN::from_array(&env, &[0u8; 128]),
            c: BytesN::from_array(&env, &[0u8; 64]),
        };

        let mut output_cts = Vec::new(&env);
        output_cts.push_back(make_ct(&env));
        output_cts.push_back(make_ct(&env));

        let mut note_cts = Vec::new(&env);
        note_cts.push_back(make_ct(&env));
        note_cts.push_back(make_ct(&env));

        let result = client.try_transfer(&dummy_proof, &public_inputs, &output_cts, &note_cts);
        assert!(matches!(result, Err(Ok(VeilError::InvalidPublicAmount))));
    }

    #[test]
    fn test_transfer_unknown_root() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = make_leaf(&env, 99); // unknown root
        let nf_in_0 = make_leaf(&env, 10);
        let nf_in_1 = BytesN::from_array(&env, &[0u8; 32]);
        let cm_out_0 = make_leaf(&env, 20);
        let cm_out_1 = make_leaf(&env, 30);
        let public_amount = BytesN::from_array(&env, &[0u8; 32]);

        let public_inputs = TransferPublic {
            root,
            nf_in_0,
            nf_in_1,
            cm_out_0,
            cm_out_1,
            public_amount,
        };

        let dummy_proof = Proof {
            a: BytesN::from_array(&env, &[0u8; 64]),
            b: BytesN::from_array(&env, &[0u8; 128]),
            c: BytesN::from_array(&env, &[0u8; 64]),
        };

        let mut output_cts = Vec::new(&env);
        output_cts.push_back(make_ct(&env));
        output_cts.push_back(make_ct(&env));

        let mut note_cts = Vec::new(&env);
        note_cts.push_back(make_ct(&env));
        note_cts.push_back(make_ct(&env));

        let result = client.try_transfer(&dummy_proof, &public_inputs, &output_cts, &note_cts);
        assert!(matches!(result, Err(Ok(VeilError::UnknownRoot))));
    }

    // ── withdraw tests ────────────────────────────────────────────────────────

    fn make_withdraw_public(
        env: &Env,
        root: BytesN<32>,
        nf_0: BytesN<32>,
        nf_1: BytesN<32>,
        cm_change: BytesN<32>,
        amount_val: u8,
        asset: u8,
    ) -> WithdrawPublic {
        let mut pa = [0u8; 32];
        pa[31] = amount_val; // small non-zero amount
        let mut asst = [0u8; 32];
        asst[31] = asset;
        WithdrawPublic {
            root,
            nf_in_0: nf_0,
            nf_in_1: nf_1,
            cm_change,
            public_amount: BytesN::from_array(env, &pa),
            asset_id: BytesN::from_array(env, &asst),
            recipient_hash: BytesN::from_array(env, &[0xabu8; 32]),
        }
    }

    fn dummy_proof(env: &Env) -> Proof {
        Proof {
            a: BytesN::from_array(env, &[0u8; 64]),
            b: BytesN::from_array(env, &[0u8; 128]),
            c: BytesN::from_array(env, &[0u8; 64]),
        }
    }

    #[test]
    fn test_withdraw_zero_public_amount_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();
        let public = WithdrawPublic {
            root,
            nf_in_0: make_leaf(&env, 1),
            nf_in_1: BytesN::from_array(&env, &[0u8; 32]),
            cm_change: BytesN::from_array(&env, &[0u8; 32]),
            public_amount: BytesN::from_array(&env, &[0u8; 32]), // ZERO — invalid
            asset_id: make_leaf(&env, 5),
            recipient_hash: make_leaf(&env, 6),
        };

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&token, &recipient, &dummy_proof(&env), &public, &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(VeilError::InvalidPublicAmount))));
    }

    #[test]
    fn test_withdraw_unknown_root_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let public = make_withdraw_public(
            &env,
            make_leaf(&env, 99), // unknown root
            make_leaf(&env, 1),
            BytesN::from_array(&env, &[0u8; 32]),
            BytesN::from_array(&env, &[0u8; 32]),
            50,
            1,
        );

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&token, &recipient, &dummy_proof(&env), &public, &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(VeilError::UnknownRoot))));
    }

    #[test]
    fn test_withdraw_success_no_change() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();
        let nf_in_0 = make_leaf(&env, 11);
        let zero = BytesN::from_array(&env, &[0u8; 32]);

        let public = make_withdraw_public(&env, root, nf_in_0.clone(), zero.clone(), zero, 100, 2);

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.withdraw(&token, &recipient, &dummy_proof(&env), &public, &Bytes::new(&env));

        // No change note — returns None
        assert!(result.is_none());
        // Input nullifier must be spent
        assert!(client.is_spent(&nf_in_0));
    }

    #[test]
    fn test_withdraw_success_with_change() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();
        let nf_in_0 = make_leaf(&env, 12);
        let nf_in_1 = make_leaf(&env, 13);
        let cm_change = make_leaf(&env, 50);
        let zero = BytesN::from_array(&env, &[0u8; 32]);

        let public = make_withdraw_public(&env, root, nf_in_0.clone(), nf_in_1.clone(), cm_change, 100, 3);
        let change_ct = make_ct(&env);

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.withdraw(&token, &recipient, &dummy_proof(&env), &public, &change_ct);

        // Change note inserted at index 0
        assert_eq!(result, Some(0u64));
        assert!(client.is_spent(&nf_in_0));
        assert!(client.is_spent(&nf_in_1));

        // Change ciphertext must be stored at that index
        let stored = client.ciphertext_at(&0u64);
        assert_eq!(stored, change_ct);

        // Root must have advanced
        assert_ne!(client.current_root(), zero);
    }

    #[test]
    fn test_withdraw_double_spend_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();
        let nf = make_leaf(&env, 15);
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let public = make_withdraw_public(&env, root.clone(), nf.clone(), zero.clone(), zero, 77, 1);

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        client.withdraw(&token, &recipient, &dummy_proof(&env), &public, &Bytes::new(&env));

        // Second withdraw with the same nullifier must fail
        let public2 = make_withdraw_public(&env, root, nf, BytesN::from_array(&env, &[0u8; 32]), BytesN::from_array(&env, &[0u8; 32]), 77, 1);
        let result = client.try_withdraw(&token, &recipient, &dummy_proof(&env), &public2, &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(VeilError::AlreadySpent))));
    }

    #[test]
    fn test_withdraw_locked_nullifier_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        // Register a module with LOCK perm to lock the nullifier
        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_LOCK);

        let nf = make_leaf(&env, 16);
        client.lock(&module, &nf);

        let root = client.current_root();
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let public = make_withdraw_public(&env, root, nf, zero.clone(), zero, 50, 1);

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&token, &recipient, &dummy_proof(&env), &public, &Bytes::new(&env));
        assert!(matches!(result, Err(Ok(VeilError::IsLocked))));
    }

    #[test]
    fn test_withdraw_change_requires_auditor_ct() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let root = client.current_root();
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let cm_change = make_leaf(&env, 77); // non-zero: change note exists

        let public = make_withdraw_public(&env, root, make_leaf(&env, 20), zero.clone(), cm_change, 50, 1);
        let empty_ct = Bytes::new(&env); // RULE 4 violation

        let token = Address::generate(&env);
        let recipient = Address::generate(&env);
        let result = client.try_withdraw(&token, &recipient, &dummy_proof(&env), &public, &empty_ct);
        assert!(matches!(result, Err(Ok(VeilError::MissingAuditorCt))));
    }

    // ── M6 lock regression tests (RULE 3 — locked collateral cannot be swapped) ─

    #[test]
    fn test_lock_rejects_already_spent() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &(PERM_SPEND | PERM_LOCK));

        let nf = make_leaf(&env, 50);
        client.spend(&module, &nf);
        // Cannot lock a note that is already spent
        let result = client.try_lock(&module, &nf);
        assert!(matches!(result, Err(Ok(VeilError::AlreadySpent))));
    }

    #[test]
    fn test_lock_double_lock_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_LOCK);

        let nf = make_leaf(&env, 51);
        client.lock(&module, &nf);
        let result = client.try_lock(&module, &nf);
        assert!(matches!(result, Err(Ok(VeilError::AlreadyLocked))));
    }

    #[test]
    fn test_unlock_non_locked_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_LOCK);

        let nf = make_leaf(&env, 52);
        let result = client.try_unlock(&module, &nf);
        assert!(matches!(result, Err(Ok(VeilError::NotLocked))));
    }

    #[test]
    fn test_unlock_then_spend_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &(PERM_SPEND | PERM_LOCK));

        let nf = make_leaf(&env, 53);
        client.lock(&module, &nf);
        client.unlock(&module, &nf);
        // After unlock, spending succeeds — collateral released back to normal UTXO
        client.spend(&module, &nf);
        assert!(client.is_spent(&nf));
        assert!(!client.is_locked(&nf));
    }

    #[test]
    fn test_locked_collateral_cannot_be_transferred() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        // Register a module with LOCK perm to simulate the lending contract
        let lending_module = Address::generate(&env);
        client.register_module(&admin, &lending_module, &PERM_LOCK);

        // Lock the collateral nullifier (simulates open_loan locking collateral)
        let collat_nf = make_leaf(&env, 60);
        client.lock(&lending_module, &collat_nf);
        assert!(client.is_locked(&collat_nf));

        // Now attempt a transfer that tries to spend the locked nullifier —
        // this simulates a user trying to double-use collateral in a swap/transfer.
        // The transfer path calls spend_internal which checks LOCKED set.
        let root = client.current_root();
        let zero = BytesN::from_array(&env, &[0u8; 32]);
        let public_inputs = TransferPublic {
            root,
            nf_in_0: collat_nf.clone(), // attempt to spend the locked nf
            nf_in_1: zero.clone(),
            cm_out_0: make_leaf(&env, 70),
            cm_out_1: zero.clone(),
            public_amount: zero,
        };
        let proof = dummy_proof(&env);
        let mut cts = Vec::new(&env);
        cts.push_back(make_ct(&env));
        cts.push_back(make_ct(&env));
        let mut ncts = Vec::new(&env);
        ncts.push_back(make_ct(&env));
        ncts.push_back(make_ct(&env));

        // Must fail with IsLocked (RULE 3)
        let result = client.try_transfer(&proof, &public_inputs, &cts, &ncts);
        assert!(matches!(result, Err(Ok(VeilError::IsLocked))));
    }

    #[test]
    fn test_request_disclosure_returns_ciphertext() {
        let env = Env::default();
        env.mock_all_auths();
        env.budget().reset_unlimited();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let module = Address::generate(&env);
        client.register_module(&admin, &module, &PERM_INSERT);

        let leaf = make_leaf(&env, 5);
        let ct = make_ct(&env);
        let idx = client.insert_commitment(&module, &leaf, &ct);

        let auditor = Address::generate(&env);
        let returned = client.request_disclosure(&auditor, &idx);
        assert_eq!(returned, ct);
    }

    #[test]
    fn test_request_disclosure_unknown_index_returns_empty() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let auditor = Address::generate(&env);
        let returned = client.request_disclosure(&auditor, &999u64);
        assert_eq!(returned.len(), 0);
    }

    // ── M7: propose_admin / accept_admin two-step tests ───────────────────────

    #[test]
    fn test_propose_admin_by_non_admin_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let stranger = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let result = client.try_propose_admin(&stranger, &new_admin);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));
    }

    #[test]
    fn test_accept_admin_by_wrong_address_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let new_admin = Address::generate(&env);
        client.propose_admin(&admin, &new_admin);

        let wrong = Address::generate(&env);
        let result = client.try_accept_admin(&wrong);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));
    }

    #[test]
    fn test_accept_without_propose_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let anyone = Address::generate(&env);
        let result = client.try_accept_admin(&anyone);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));
    }

    #[test]
    fn test_propose_and_accept_admin_full_flow() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let new_admin = Address::generate(&env);
        client.propose_admin(&admin, &new_admin);
        client.accept_admin(&new_admin);

        // New admin can now do admin-only operations (set auditor pk)
        let pk = BytesN::from_array(&env, &[0xabu8; 32]);
        client.set_auditor_pubkey(&new_admin, &pk);
        assert_eq!(client.auditor_pubkey(), pk);

        // Old admin can no longer do admin operations
        let result = client.try_set_auditor_pubkey(&admin, &pk);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));
    }

    #[test]
    fn test_double_propose_last_wins() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let first  = Address::generate(&env);
        let second = Address::generate(&env);
        client.propose_admin(&admin, &first);
        client.propose_admin(&admin, &second); // overwrite

        // first cannot accept — last propose wins
        let result = client.try_accept_admin(&first);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));

        // second can accept
        client.accept_admin(&second);
    }

    // ── M7: bump_ttl tests ────────────────────────────────────────────────────

    #[test]
    fn test_bump_ttl_non_admin_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let (_admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let stranger = Address::generate(&env);
        let keys: soroban_sdk::Vec<soroban_sdk::Val> = soroban_sdk::Vec::new(&env);
        let result = client.try_bump_ttl(&stranger, &keys);
        assert!(matches!(result, Err(Ok(VeilError::Unauthorized))));
    }

    #[test]
    fn test_bump_ttl_admin_succeeds_empty_keys() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let keys: soroban_sdk::Vec<soroban_sdk::Val> = soroban_sdk::Vec::new(&env);
        client.bump_ttl(&admin, &keys);
    }

    // ── M7: get_vk smoke test ─────────────────────────────────────────────────

    #[test]
    fn test_get_vk_returns_stored_bytes() {
        let env = Env::default();
        env.mock_all_auths();
        let (admin, contract_id) = init_contract(&env);
        let client = VeilCoreClient::new(&env, &contract_id);

        let mut vk_bytes = Bytes::new(&env);
        vk_bytes.push_back(0xde);
        vk_bytes.push_back(0xad);
        client.init_vk(&admin, &VkId::Repay, &vk_bytes);

        let retrieved = client.get_vk(&VkId::Repay);
        assert_eq!(retrieved, Some(vk_bytes));

        let missing = client.get_vk(&VkId::SettleOrRefund);
        assert!(missing.is_none());
    }
}
