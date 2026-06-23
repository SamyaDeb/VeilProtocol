// Indexer HTTP client.
//
// The indexer is a background event-persister; its only browser-facing surface
// is `/anonymity-set` (pool metrics) and `/health`. Merkle paths are NOT served
// here — proving screens build them on-chain/locally (added with those screens).

import { config } from '../config';
import type { AnonymitySet } from '../types';

export async function getAnonymitySet(): Promise<AnonymitySet | null> {
  try {
    const res = await fetch(`${config.indexerUrl}/anonymity-set`);
    if (!res.ok) return null;
    return (await res.json()) as AnonymitySet;
  } catch {
    return null;
  }
}

export async function indexerHealthy(): Promise<boolean> {
  try {
    const res = await fetch(`${config.indexerUrl}/health`);
    return res.ok;
  } catch {
    return false;
  }
}
