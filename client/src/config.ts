// Network configuration loader.
//
// Single source of truth = the repo's deployment manifests. We import them
// directly (Vite `server.fs.allow: ['..']`) rather than re-declaring contract
// IDs, so the app can never drift from what was actually deployed.

import testnetRaw from '../../deployments/testnet.json';
import mainnetRaw from '../../deployments/mainnet.json';
import type { NetworkConfig, NetworkName } from './types';

interface RawDeployment {
  network: string;
  rpc_url: string;
  network_passphrase: string;
  contracts: {
    veil_core: string;
    asp: string;
    amm_pool: string;
    lending: string;
    viewkey: string;
  };
  auditor?: { pubkey?: string };
  assets?: Record<string, { token_contract?: string }>;
  indexer_url?: string;
}

function resolve(raw: RawDeployment, name: NetworkName): NetworkConfig {
  // Prefer an explicit token contract from any asset entry that declares one.
  const tokenContract =
    Object.values(raw.assets ?? {}).find((a) => a.token_contract)?.token_contract ?? '';

  return {
    network: name,
    rpcUrl: import.meta.env.VITE_RPC_URL ?? raw.rpc_url,
    networkPassphrase: raw.network_passphrase,
    contracts: raw.contracts,
    auditorPubkey: (raw.auditor?.pubkey ?? '').replace(/^0x/, ''),
    tokenContract,
    indexerUrl: import.meta.env.VITE_INDEXER_URL ?? raw.indexer_url ?? 'http://localhost:3001',
  };
}

const CONFIGS: Record<NetworkName, NetworkConfig> = {
  testnet: resolve(testnetRaw as RawDeployment, 'testnet'),
  mainnet: resolve(mainnetRaw as RawDeployment, 'mainnet'),
};

export const ACTIVE_NETWORK: NetworkName = import.meta.env.VITE_NETWORK ?? 'testnet';

export const config: NetworkConfig = CONFIGS[ACTIVE_NETWORK];

export function getConfig(): NetworkConfig {
  return config;
}
