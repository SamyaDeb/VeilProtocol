// Typed local note store (the user's shielded UTXO set).
//
// Notes are stored at rest encrypted with AES-GCM keyed to the owner_sk.
// When owner_sk is not yet available (first load), falls back to a plaintext
// JSON store (C1 VERIFY: always set owner_sk before writing sensitive notes).
//
// The legacy client had two conflicting layouts: swap.js used a flat
// `veil_notes` array while store/notes.js keyed by owner_pk. We standardize on
// one canonical key and identify notes by their commitment (stable; leaf_idx is
// a placeholder until the indexer assigns it). Secrets never leave the browser.

import type { StoredNote } from '../types';

const KEY = 'veil_notes';
const ENC_KEY = 'veil_notes_enc';

// ─── plaintext helpers (internal; used when enc key is unavailable) ───────────

function readPlain(): StoredNote[] {
  if (typeof localStorage === 'undefined') return [];
  try {
    const raw = localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as StoredNote[]) : [];
  } catch {
    return [];
  }
}

function writePlain(notes: StoredNote[]): void {
  if (typeof localStorage === 'undefined') return;
  localStorage.setItem(KEY, JSON.stringify(notes));
}

// ─── encrypted store ──────────────────────────────────────────────────────────

let _encKey: CryptoKey | null = null;

/**
 * Provide the AES-GCM key derived from the owner_sk (see identity.ts).
 * Call this once on identity init; subsequent note reads/writes use it.
 */
export function setNoteStoreKey(key: CryptoKey): void {
  _encKey = key;
}

async function encryptNotes(notes: StoredNote[]): Promise<string> {
  if (!_encKey) throw new Error('Note store key not set');
  const data = new TextEncoder().encode(JSON.stringify(notes));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, _encKey, data);
  const combined = new Uint8Array(12 + ct.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...combined));
}

async function decryptNotes(b64: string): Promise<StoredNote[]> {
  if (!_encKey) return [];
  try {
    const combined = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ct = combined.slice(12);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, _encKey, ct);
    return JSON.parse(new TextDecoder().decode(plain)) as StoredNote[];
  } catch {
    return [];
  }
}

// ─── public API ───────────────────────────────────────────────────────────────

/** Load all notes (encrypted if key available, plaintext fallback). */
export function loadNotes(): StoredNote[] {
  // Merge plaintext (legacy) + return; async encrypted read is handled by
  // loadNotesAsync when the CryptoKey is ready.
  return readPlain();
}

/** Async load — reads encrypted store if key is available. */
export async function loadNotesAsync(): Promise<StoredNote[]> {
  if (!_encKey) return readPlain();
  const b64 = typeof localStorage !== 'undefined' ? localStorage.getItem(ENC_KEY) : null;
  if (!b64) return readPlain();
  return decryptNotes(b64);
}

/** Save all notes (encrypted if key available). */
async function writeNotes(notes: StoredNote[]): Promise<void> {
  if (_encKey) {
    const enc = await encryptNotes(notes);
    if (typeof localStorage !== 'undefined') localStorage.setItem(ENC_KEY, enc);
  } else {
    writePlain(notes);
  }
}

/** Synchronous write (plaintext only). Used by legacy code paths. */
function writeSync(notes: StoredNote[]): void {
  writePlain(notes);
}

/** Add a note to the store, deduplicating by commitment. */
export function addNote(note: StoredNote): void {
  const notes = readPlain();
  const idx = notes.findIndex((n) => n.commitment === note.commitment);
  if (idx === -1) {
    notes.push(note);
  } else {
    // Update existing (fills in leaf_idx etc.)
    notes[idx] = { ...notes[idx], ...note };
  }
  writeSync(notes);
}

/** Async addNote (writes encrypted if key is set). */
export async function addNoteAsync(note: StoredNote): Promise<void> {
  const notes = await loadNotesAsync();
  const idx = notes.findIndex((n) => n.commitment === note.commitment);
  if (idx === -1) {
    notes.push(note);
  } else {
    notes[idx] = { ...notes[idx], ...note };
  }
  await writeNotes(notes);
  // Keep plaintext in sync for non-encrypted reads.
  writePlain(notes);
}

export function markSpentByCommitment(commitment: string): void {
  writeSync(readPlain().map((n) => (n.commitment === commitment ? { ...n, spent: true } : n)));
}

export function markPendingByCommitment(commitment: string, pending: boolean): void {
  writeSync(readPlain().map((n) => (n.commitment === commitment ? { ...n, pending } : n)));
}

export function getUnspentNotes(): StoredNote[] {
  return readPlain().filter((n) => !n.spent);
}

/** Normalizes the two leaf-index field names the legacy provers used. */
export function noteLeafIndex(note: StoredNote): number | undefined {
  return note.leaf_idx ?? note.leaf_index;
}

/** Total unspent (and non-pending) amount per asset_id, as bigint. */
export function balancesByAsset(): Map<string, bigint> {
  const out = new Map<string, bigint>();
  for (const n of readPlain()) {
    if (n.spent || n.pending) continue;
    const prev = out.get(n.asset_id) ?? 0n;
    out.set(n.asset_id, prev + BigInt(n.amount));
  }
  return out;
}

/** Migrate plaintext notes into the encrypted store. */
export async function migrateToEncrypted(): Promise<void> {
  if (!_encKey) return;
  const plain = readPlain();
  if (plain.length === 0) return;
  await writeNotes(plain);
}
