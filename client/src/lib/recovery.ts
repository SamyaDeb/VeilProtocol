// Note recovery — scan on-chain events to find leaf_idx for stored notes.
//
// Detects notes whose commitment matches a leaf in the on-chain event stream.
// Useful after a page refresh that doesn't lose localStorage (leaf_idx can be
// missing for notes saved before the indexer assigned it, or for newly minted
// change notes). Full re-scan from owner_sk is not possible with the current
// auditor-only encryption scheme (THREAT_MODEL §8) — that requires ECIES
// with an owner key in a future upgrade.

import { getLeaves } from './rpc';
import { loadNotes, addNote } from './notes';
import type { StoredNote } from '../types';

/**
 * For each locally-stored note that is missing a leaf_idx, scan on-chain
 * commitment events and fill it in if a matching commitment is found.
 * Updates the note store in place.
 *
 * @param sourceAddress — a Stellar address to simulate from (for getLeaves)
 * @param fromLedger — ledger number to start the event scan from (0 = genesis)
 */
export async function recoverLeafIndices(
  sourceAddress: string,
  fromLedger = 0,
): Promise<{ recovered: number; total: number }> {
  const notes = loadNotes();
  const missing = notes.filter((n) => n.leaf_idx == null && n.leaf_index == null);
  if (missing.length === 0) return { recovered: 0, total: notes.length };

  const leaves = await getLeaves(sourceAddress, fromLedger);
  const leafByCommitment = new Map(leaves.map((l) => [l.commitment, l]));

  let recovered = 0;
  for (const note of missing) {
    const leaf = leafByCommitment.get(note.commitment);
    if (leaf) {
      // Write back with leaf_idx filled in.
      const updated: StoredNote = { ...note, leaf_idx: leaf.idx };
      addNote(updated);
      recovered++;
    }
  }
  return { recovered, total: notes.length };
}

/**
 * Returns commitments from on-chain events that match locally-stored notes.
 * Useful for a "verify my notes are on-chain" check.
 */
export async function verifyNotesOnChain(sourceAddress: string): Promise<{
  found: string[];
  missing: string[];
}> {
  const notes = loadNotes().filter((n) => !n.spent);
  if (notes.length === 0) return { found: [], missing: [] };

  const leaves = await getLeaves(sourceAddress);
  const onChain = new Set(leaves.map((l) => l.commitment));

  const found: string[] = [];
  const missing: string[] = [];
  for (const note of notes) {
    (onChain.has(note.commitment) ? found : missing).push(note.commitment);
  }
  return { found, missing };
}
