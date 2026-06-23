import type { StoredNote } from '../types';

export interface SelectionResult {
  notes: StoredNote[];
  total: bigint;
  change: bigint;
}

export function selectInputs(
  notes: StoredNote[],
  assetId: string | bigint,
  amount: bigint,
): SelectionResult | null;

export function balanceForAsset(notes: StoredNote[], assetId: string | bigint): bigint;
