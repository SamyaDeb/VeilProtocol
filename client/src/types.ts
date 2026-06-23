// Shared domain types for the Veil app.

export type NetworkName = 'testnet' | 'mainnet';

export interface ContractIds {
  veil_core: string;
  asp: string;
  amm_pool: string;
  lending: string;
  viewkey: string;
}

/** Resolved, app-facing network configuration (derived from deployments/*.json). */
export interface NetworkConfig {
  network: NetworkName;
  rpcUrl: string;
  networkPassphrase: string;
  contracts: ContractIds;
  /** Auditor BN254 pubkey as a field element (hex, no 0x). */
  auditorPubkey: string;
  /** Token contract used for deposits/withdrawals on this network (may be empty on mainnet). */
  tokenContract: string;
  indexerUrl: string;
}

/**
 * A shielded note as persisted in the local store. Field-element values are kept
 * as decimal strings so they survive JSON round-trips; convert with `BigInt(...)`
 * before handing them to a prover. `leaf_idx`/`leaf_index` differ across the
 * legacy provers — the store normalizes reads via `noteLeafIndex()`.
 */
export interface StoredNote {
  amount: string;
  asset_id: string;
  blinding: string;
  owner_pk: string;
  owner_sk?: string;
  commitment: string;
  leaf_idx?: number;
  leaf_index?: number;
  spent?: boolean;
  pending?: boolean;
  /** Set for LP position notes to track deposit-time reserve values for fee display. */
  deposit_value_0?: string;
  deposit_value_1?: string;
  /** 'deposit' | 'swap_output' | 'borrow' | 'lp' | 'change' | 'withdraw_change' */
  note_type?: string;
}

export interface DecryptedNote {
  amount: bigint;
  asset_id: bigint;
  blinding: bigint;
  owner_pk: bigint;
}

export interface AnonymitySet {
  commitment_count: number;
  local_root: string;
  last_ledger: number;
  de_anon_risk: string;
  de_anon_warning?: string;
}

/** LTV-related data for a collateralized position. */
export interface LoanRecord {
  loanId: string;
  collatNf: string;
  borrowCm: string;
  collatAsset: string;
  borrowAsset: string;
  oraclePriceAtOpen: string;
  ltv: number;  // 0–100
  openedAt: number; // ledger
}

/** Swap order status. */
export type SwapStatus = 'submitted' | 'awaiting_settlement' | 'recovered' | 'refunded' | 'failed';

export interface PendingSwapOrder {
  orderId: string;
  inputNoteCommitment: string;
  intent: {
    asset_out: string;
    min_out: string;
    out_blinding: string;
    out_owner_pk: string;
  };
  status: SwapStatus;
  submittedAt: number; // Date.now()
}

/** Known asset name/id mappings for display. */
export interface AssetMeta {
  id: string;    // asset_id field element as decimal string
  code: string;  // e.g. "TEST-RWA"
  name: string;
}
