/**
 * Veil Protocol — Merkle tree indexer.
 *
 * Polls Soroban RPC for `(leaf, inserted)` events from veil_core and maintains
 * a persistent SQLite copy of the full commitment tree. Soroban RPC retains
 * only ~7 days of events; this indexer is the long-term tree store (PRD US-7).
 *
 * Usage:
 *   VEIL_CORE=<contract-id> SOROBAN_RPC=<url> node src/index.js
 *
 * The indexer reconstructs the Merkle root from stored leaves via the same
 * Poseidon2-compatible hash used on-chain, so the root can be verified against
 * veil_core.current_root() at any time.
 */

import { SorobanRpc, Contract, xdr, StrKey } from '@stellar/stellar-sdk';
import Database from 'better-sqlite3';
import { buildPoseidon } from 'circomlibjs';
import { mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── config ──────────────────────────────────────────────────────────────────

const CORE_CONTRACT = process.env.VEIL_CORE ?? '';
const RPC_URL       = process.env.SOROBAN_RPC ?? 'https://soroban-testnet.stellar.org';
const DB_PATH       = process.env.DB_PATH ?? join(__dirname, '..', 'data', 'indexer.db');
const POLL_MS       = parseInt(process.env.POLL_MS ?? '5000', 10);
const TREE_DEPTH    = 32;

if (!CORE_CONTRACT) {
    console.error('VEIL_CORE env var required');
    process.exit(1);
}

// ─── DB ──────────────────────────────────────────────────────────────────────

function openDb(path) {
    const dir = dirname(path);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    const db = new Database(path);
    db.pragma('journal_mode = WAL');
    db.exec(`
        CREATE TABLE IF NOT EXISTS leaves (
            idx         INTEGER PRIMARY KEY,
            commitment  BLOB NOT NULL,
            auditor_ct  BLOB NOT NULL,
            ledger      INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    `);
    return db;
}

// ─── Poseidon helper ─────────────────────────────────────────────────────────

let _poseidon;
async function getPoseidon() {
    if (!_poseidon) _poseidon = await buildPoseidon();
    return _poseidon;
}

/** Hash two 32-byte Buffers with Poseidon(2) → 32-byte Buffer. */
async function poseidon2(left, right) {
    const poseidon = await getPoseidon();
    const l = BigInt('0x' + left.toString('hex'));
    const r = BigInt('0x' + right.toString('hex'));
    const h = poseidon([l, r]);
    const hex = poseidon.F.toString(h, 16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
}

// ─── tree reconstruction ──────────────────────────────────────────────────────

/** Compute the Merkle root from all leaves in the DB. */
async function computeRoot(db) {
    const zero = Buffer.alloc(32);
    const maxLeaves = 2 ** TREE_DEPTH;
    const rows = db.prepare('SELECT idx, commitment FROM leaves ORDER BY idx').all();

    // Build a map idx → leaf bytes
    const leafMap = new Map();
    for (const row of rows) {
        leafMap.set(row.idx, Buffer.from(row.commitment));
    }

    // Incremental tree: compute level by level
    // At depth 0 = leaves, depth TREE_DEPTH = root
    let level = new Array(maxLeaves).fill(zero);
    for (const [idx, leaf] of leafMap) {
        level[idx] = leaf;
    }

    for (let d = 0; d < TREE_DEPTH; d++) {
        const nextSize = Math.ceil(level.length / 2);
        const next = new Array(nextSize);
        for (let i = 0; i < nextSize; i++) {
            const l = level[2 * i] ?? zero;
            const r = level[2 * i + 1] ?? zero;
            next[i] = await poseidon2(l, r);
        }
        level = next;
    }

    return level[0] ?? zero;
}

// ─── event parsing ────────────────────────────────────────────────────────────

/** Parse a `(leaf, inserted)` contract event → { commitment, idx, auditorCt }. */
function parseLeafInsertedEvent(event) {
    try {
        const topics = event.topic;
        if (!topics || topics.length < 2) return null;

        // Topic[0] = Symbol("leaf"), Topic[1] = Symbol("inserted")
        // Value = [commitment_bytes, idx_u64, auditor_ct_bytes]
        const val = event.value;
        if (!val) return null;

        const vec = val._value;
        if (!vec || vec.length < 3) return null;

        const commitment = vec[0]._value;   // Bytes → Buffer
        const idx        = Number(vec[1]._value); // u64
        const auditorCt  = vec[2]._value;   // Bytes → Buffer

        return { commitment: Buffer.from(commitment), idx, auditorCt: Buffer.from(auditorCt) };
    } catch {
        return null;
    }
}

// ─── main loop ────────────────────────────────────────────────────────────────

async function main() {
    const db     = openDb(DB_PATH);
    const server = new SorobanRpc.Server(RPC_URL, { allowHttp: RPC_URL.startsWith('http://') });

    const stateGet = db.prepare('SELECT value FROM state WHERE key = ?');
    const stateSet = db.prepare('INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)');
    const insertLeaf = db.prepare(
        'INSERT OR IGNORE INTO leaves (idx, commitment, auditor_ct, ledger) VALUES (?, ?, ?, ?)'
    );

    const getLastLedger = () => parseInt(stateGet.get('last_ledger')?.value ?? '0', 10);
    const setLastLedger = (l) => stateSet.run('last_ledger', String(l));

    console.log(`Indexer starting. Contract=${CORE_CONTRACT} RPC=${RPC_URL}`);

    // eslint-disable-next-line no-constant-condition
    while (true) {
        try {
            const lastLedger = getLastLedger();
            const info = await server.getLatestLedger();
            const latestLedger = info.sequence;

            if (latestLedger <= lastLedger) {
                await sleep(POLL_MS);
                continue;
            }

            // Fetch events from veil_core for leaf insertions
            // VERIFY: getEvents pagination / startLedger semantics against Soroban RPC docs
            const eventsResp = await server.getEvents({
                startLedger: lastLedger + 1,
                filters: [{
                    type: 'contract',
                    contractIds: [CORE_CONTRACT],
                }],
                limit: 200,
            });

            let newLeaves = 0;
            const insertTx = db.transaction(() => {
                for (const event of eventsResp.events ?? []) {
                    const parsed = parseLeafInsertedEvent(event);
                    if (!parsed) continue;
                    insertLeaf.run(
                        parsed.idx,
                        parsed.commitment,
                        parsed.auditorCt,
                        event.ledger ?? latestLedger,
                    );
                    newLeaves++;
                }
                setLastLedger(latestLedger);
            });
            insertTx();

            if (newLeaves > 0) {
                const root = await computeRoot(db);
                stateSet.run('local_root', root.toString('hex'));
                console.log(`ledger=${latestLedger} +${newLeaves} leaves root=${root.toString('hex').slice(0, 16)}...`);
            } else {
                // Still update the ledger cursor even if no new leaves
                setLastLedger(latestLedger);
            }
        } catch (err) {
            console.error('Indexer error:', err.message);
        }
        await sleep(POLL_MS);
    }
}

/** Return the indexer's locally-stored root (for e2e assertion). */
export async function localRoot(db) {
    const row = db.prepare('SELECT value FROM state WHERE key = ?').get('local_root');
    return row ? Buffer.from(row.value, 'hex') : null;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

main().catch(e => { console.error(e); process.exit(1); });
