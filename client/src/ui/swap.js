/**
 * Swap UI — minimal form for submitting shielded swap orders.
 * Reads the user's note store, proves the swap in-browser (WASM), encrypts
 * the intent for the committee, and submits to amm_pool.submit_order.
 *
 * DOM elements expected in index.html:
 *   #swap-note-select, #swap-asset-out, #swap-min-out
 *   #swap-submit-btn, #swap-status, #swap-order-id
 */

import { proveSwap, serializeProof } from '../prover/swap.js';
import { buildPoseidon } from 'circomlibjs';

// ─── config (injected by the build or env) ────────────────────────────────────
const AMM_POOL_ID   = window.VEIL_AMM_POOL   ?? '';
const VEIL_CORE_ID  = window.VEIL_CORE        ?? '';
const COMMITTEE_PK  = BigInt(window.COMMITTEE_PK ?? '1'); // scalar field element
const NETWORK_PASSPHRASE = window.NETWORK_PASSPHRASE ?? '';

// ─── note store helpers ───────────────────────────────────────────────────────

function loadNotes() {
    try { return JSON.parse(localStorage.getItem('veil_notes') ?? '[]'); } catch { return []; }
}

function saveNotes(notes) {
    localStorage.setItem('veil_notes', JSON.stringify(notes, (_, v) =>
        typeof v === 'bigint' ? v.toString() : v
    ));
}

// ─── UI helpers ───────────────────────────────────────────────────────────────

function setStatus(msg, isError = false) {
    const el = document.querySelector('#swap-status');
    if (!el) return;
    el.textContent = msg;
    el.style.color = isError ? '#e53935' : '#43a047';
}

function populateNoteSelector(notes) {
    const sel = document.querySelector('#swap-note-select');
    if (!sel) return;
    sel.innerHTML = '';
    notes.forEach((n, i) => {
        const opt = document.createElement('option');
        opt.value = i;
        opt.text  = `Note ${i}: amount=${n.amount} asset=${n.asset_id} idx=${n.leaf_index}`;
        sel.appendChild(opt);
    });
}

// ─── core submit flow ─────────────────────────────────────────────────────────

async function submitSwapOrder() {
    setStatus('Proving…');

    const { rpc, Contract, TransactionBuilder, Networks, xdr, Keypair } =
        await import('@stellar/stellar-sdk');

    const notes = loadNotes();
    const noteIdx = parseInt(document.querySelector('#swap-note-select')?.value ?? '0');
    const note = notes[noteIdx];
    if (!note) { setStatus('No note selected', true); return; }

    const assetOut = BigInt(document.querySelector('#swap-asset-out')?.value ?? '0');
    const minOut   = BigInt(document.querySelector('#swap-min-out')?.value  ?? '0');

    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Generate fresh output note parameters
    const outBlinding  = BigInt(Math.floor(Math.random() * 1e15));
    const outOwnerPk   = BigInt(note.owner_pk); // send to self for demo
    const rEnc         = BigInt(Math.floor(Math.random() * 1e15));

    const intent = {
        asset_out:    assetOut,
        min_out:      minOut,
        out_blinding: outBlinding,
        out_owner_pk: outOwnerPk,
    };

    // Build input note for prover
    const inputNote = {
        amount:     BigInt(note.amount),
        asset_id:   BigInt(note.asset_id),
        blinding:   BigInt(note.blinding),
        owner_sk:   BigInt(note.owner_sk),
        leaf_index: BigInt(note.leaf_index),
        path:       note.path.map(BigInt),
        idx:        note.idx.map(Number),
    };

    // Fetch current root from veil_core
    const server = new rpc.Server(window.RPC_URL ?? '');
    // root fetched via off-chain indexer in production; using localStorage cache here
    const root = BigInt(localStorage.getItem('veil_root') ?? '0');

    let nf_in, enc_order_hash, proof;
    try {
        ({ nf_in, enc_order_hash, proof } =
            await proveSwap(inputNote, intent, root, COMMITTEE_PK, rEnc));
    } catch (e) {
        setStatus(`Proof failed: ${e.message}`, true);
        return;
    }
    setStatus('Proof ready, submitting…');

    // Serialise enc_order for committee (M3: plaintext JSON; M4: real ElGamal)
    // // VERIFY: replace with ElGamal-on-BN254 G1 when CAP-0074 G1 scalar-mul is confirmed.
    const encOrderBytes = Buffer.from(JSON.stringify({
        amount_in:    inputNote.amount.toString(),
        asset_out:    intent.asset_out.toString(),
        min_out:      intent.min_out.toString(),
        out_blinding: intent.out_blinding.toString(),
        out_owner_pk: intent.out_owner_pk.toString(),
        r_enc:        rEnc.toString(),
    }));

    const { a, b, c } = serializeProof(proof);

    function toBytesN(hex)    { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0'),  'hex')); }
    function toBytesN64(hex)  { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(128, '0'), 'hex')); }
    function toBytesN128(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(256, '0'), 'hex')); }
    function toBytes(buf)     { return xdr.ScVal.scvBytes(buf); }
    function toStruct(obj) {
        const entries = Object.keys(obj).sort().map(k =>
            new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: obj[k] })
        );
        return xdr.ScVal.scvMap(entries);
    }

    const kp = Keypair.fromSecret(window.USER_SECRET ?? '');
    const contract = new Contract(AMM_POOL_ID);
    const account = await server.getAccount(kp.publicKey());

    const submitterScVal = new (await import('@stellar/stellar-sdk')).Address(kp.publicKey()).toScVal();

    const tx = new TransactionBuilder(account, {
        fee: '1000000',
        networkPassphrase: NETWORK_PASSPHRASE,
    }).addOperation(contract.call('submit_order',
        submitterScVal,
        toStruct({ a: toBytesN64(a), b: toBytesN128(b), c: toBytesN64(c) }),
        toBytes(encOrderBytes),
        toBytesN(nf_in.toString(16)),
        toBytesN(enc_order_hash.toString(16)),
        toBytesN(root.toString(16)),
    )).setTimeout(30).build();

    const prepared = await server.prepareTransaction(tx);
    prepared.sign(kp);
    const result = await server.sendTransaction(prepared);

    if (result.status === 'ERROR') {
        setStatus(`Submit failed: ${result.errorResultXdr}`, true);
        return;
    }

    // Wait for confirmation
    let res = result;
    while (res.status === 'PENDING' || res.status === 'NOT_FOUND') {
        await new Promise(r => setTimeout(r, 2000));
        res = await server.getTransaction(result.hash);
    }

    if (res.status !== 'SUCCESS') {
        setStatus(`Tx failed: ${res.status}`, true);
        return;
    }

    const slotEl = document.querySelector('#swap-order-id');
    if (slotEl) slotEl.textContent = `Order submitted`;

    // Mark note as pending (spent locally)
    notes[noteIdx].pending = true;
    saveNotes(notes);

    setStatus('Order submitted — waiting for committee settlement.');
}

// ─── init ─────────────────────────────────────────────────────────────────────

export function initSwapUI() {
    const notes = loadNotes();
    populateNoteSelector(notes);
    document.querySelector('#swap-submit-btn')
        ?.addEventListener('click', submitSwapOrder);
}
