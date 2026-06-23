/**
 * Coin selection for shielded note inputs (RULE 2 — universal notes).
 *
 * selectInputs picks the minimum set of unspent notes of the given asset_id
 * that covers the requested amount, using a largest-first greedy strategy.
 * Works identically for notes from any module (deposit, swap output, LP removal).
 */

/**
 * @param {import('../types').StoredNote[]} notes — all notes from the note store
 * @param {string | bigint} assetId — the asset_id to select for (decimal string or BigInt)
 * @param {bigint} amount — amount needed
 * @returns {{ notes: import('../types').StoredNote[], total: bigint, change: bigint } | null}
 *   null if insufficient balance
 */
export function selectInputs(notes, assetId, amount) {
    const targetAsset = assetId.toString();
    const target = BigInt(amount);

    const candidates = notes
        .filter(n => n.asset_id.toString() === targetAsset && !n.spent && !n.pending)
        .sort((a, b) => {
            const diff = BigInt(b.amount) - BigInt(a.amount);
            return diff > 0n ? 1 : diff < 0n ? -1 : 0;
        });

    const selected = [];
    let total = 0n;

    for (const note of candidates) {
        if (total >= target) break;
        selected.push(note);
        total += BigInt(note.amount);
    }

    if (total < target) return null;
    return { notes: selected, total, change: total - target };
}

/**
 * Returns total unspent balance for a given asset_id.
 * @param {import('../types').StoredNote[]} notes
 * @param {string | bigint} assetId
 * @returns {bigint}
 */
export function balanceForAsset(notes, assetId) {
    const target = assetId.toString();
    return notes
        .filter(n => n.asset_id.toString() === target && !n.spent && !n.pending)
        .reduce((acc, n) => acc + BigInt(n.amount), 0n);
}
