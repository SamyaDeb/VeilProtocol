/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Which deployment config to load: "testnet" (default) or "mainnet". */
  readonly VITE_NETWORK?: 'testnet' | 'mainnet';
  /** Optional override for the Soroban RPC URL. */
  readonly VITE_RPC_URL?: string;
  /** Optional override for the indexer base URL. */
  readonly VITE_INDEXER_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

// The shared crypto core (provers + auditor encryption) is plain JS shared with
// the Node e2e suites. `allowJs` lets the app import it; its exports come back
// loosely typed, so callers cast the result to a domain type (see src/types.ts).

// circomlibjs has no published @types — declare the minimal surface we use.
declare module 'circomlibjs' {
  interface PoseidonFn {
    (inputs: bigint[]): unknown;
    F: {
      toObject(v: unknown): bigint;
      toString(v: unknown): string;
    };
  }
  export function buildPoseidon(): Promise<PoseidonFn>;
}
