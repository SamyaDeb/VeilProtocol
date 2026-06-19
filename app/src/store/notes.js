/**
 * Local note store (localStorage-backed UTXO set).
 *
 * Each note = { amount, asset_id, blinding, owner_pk, leaf_idx, commitment }.
 * Notes are stored as JSON in localStorage keyed by owner_pk.
 * Recovery: owner_sk can re-derive all notes by trial-scanning the tree.
 */

const NOTES_PREFIX = 'veil_notes_';

/** Save a note for the given owner. */
export function saveNote(ownerPk, note) {
    const key = NOTES_PREFIX + ownerPk.toString(16);
    const existing = loadNotes(ownerPk);
    existing.push(serializeNote(note));
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem(key, JSON.stringify(existing));
    }
}

/** Load all notes for the given owner. */
export function loadNotes(ownerPk) {
    const key = NOTES_PREFIX + ownerPk.toString(16);
    if (typeof localStorage === 'undefined') return [];
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : [];
}

/** Mark a note as spent by leaf_idx. */
export function markSpent(ownerPk, leafIdx) {
    const key = NOTES_PREFIX + ownerPk.toString(16);
    const notes = loadNotes(ownerPk);
    const updated = notes.map(n =>
        n.leaf_idx === leafIdx ? { ...n, spent: true } : n
    );
    if (typeof localStorage !== 'undefined') {
        localStorage.setItem(key, JSON.stringify(updated));
    }
}

/** Get all unspent notes. */
export function getUnspentNotes(ownerPk) {
    return loadNotes(ownerPk).filter(n => !n.spent);
}

function serializeNote(note) {
    return {
        amount:     note.amount.toString(),
        asset_id:   note.asset_id.toString(),
        blinding:   note.blinding.toString(),
        owner_pk:   note.owner_pk.toString(),
        leaf_idx:   note.leaf_idx,
        commitment: note.commitment.toString(),
        spent:      false,
    };
}
