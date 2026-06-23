import { useState, useEffect } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { StatusBanner } from '../../components/StatusBanner';
import { NoteSelector } from '../../components/NoteSelector';
import { getUnspentNotes, noteLeafIndex } from '../../lib/notes';
import { getOrCreateOwnerSk } from '../../lib/identity';
import { getLeaves } from '../../lib/rpc';
import { useSwap, loadPendingOrders, type SwapStep } from './useSwap';
import type { StoredNote } from '../../types';

// Committee public key: comes from deployments/mainnet.json amm.committee_pk
// Testnet: use a dev scalar (1n) matching the e2e suite.
// VERIFY: read from deployments JSON before mainnet.
const DEV_COMMITTEE_PK = 1n;

function stepLabel(step: SwapStep): string {
  switch (step) {
    case 'building_inputs':       return 'Building circuit inputs & Merkle path…';
    case 'proving':               return 'Generating ZK swap proof (10–30 s)…';
    case 'submitting':            return 'Submitting encrypted order to AMM pool…';
    case 'awaiting_settlement':   return 'Order submitted — awaiting committee settlement…';
    case 'success':               return 'Swap output note recovered!';
    case 'error':                 return '';
    default:                      return '';
  }
}

export function SwapForm() {
  const { address, signXdr } = useWallet();
  const { state, submitOrder, reset } = useSwap();

  const [notes, setNotes] = useState<StoredNote[]>([]);
  const [selectedCm, setSelectedCm] = useState('');
  const [assetOut, setAssetOut] = useState('');
  const [minOut, setMinOut] = useState('');
  const [leaves, setLeaves] = useState<bigint[]>([]);
  const [leavesLoading, setLeavesLoading] = useState(false);
  const pendingOrders = loadPendingOrders();

  useEffect(() => {
    setNotes(getUnspentNotes());
  }, []);

  useEffect(() => {
    if (!address) return;
    setLeavesLoading(true);
    getLeaves(address)
      .then((evts) => setLeaves(evts.map((e) => BigInt('0x' + e.commitment))))
      .catch(() => setLeaves([]))
      .finally(() => setLeavesLoading(false));
  }, [address]);

  const selectedNote = notes.find((n) => n.commitment === selectedCm);
  const busy = !['idle', 'success', 'error', 'awaiting_settlement'].includes(state.step);

  async function handleSubmit() {
    if (!address || !signXdr || !selectedNote) return;
    const ownerSk = getOrCreateOwnerSk();
    await submitOrder({
      address,
      signXdr,
      inputNote: selectedNote,
      ownerSk,
      treeLeaves: leaves,
      assetOut: BigInt(assetOut.trim() || '0'),
      minOut: BigInt(minOut.trim() || '0'),
      committeePk: DEV_COMMITTEE_PK,
    });
  }

  return (
    <section className="veil-card">
      <h2>Shielded swap</h2>
      <p className="veil-muted">
        Submit a flow-encrypted swap order to the batch-auction AMM. Your input
        note is nullified immediately (RULE 3 — spent set). The committee
        threshold-decrypts the batch and settles at one clearing price; your
        output note is created at settlement.
      </p>

      {!address && <StatusBanner kind="warn">Connect Freighter to swap.</StatusBanner>}

      {pendingOrders.filter((o) => o.status === 'awaiting_settlement').length > 0 && (
        <StatusBanner kind="info">
          {pendingOrders.filter((o) => o.status === 'awaiting_settlement').length} order(s)
          awaiting committee settlement. Check back after the batch window closes.
        </StatusBanner>
      )}

      <label className="veil-field">
        Input note (unspent)
        <NoteSelector
          notes={notes}
          value={selectedCm}
          onChange={setSelectedCm}
          placeholder="— select a note to spend —"
        />
        {selectedNote && noteLeafIndex(selectedNote) == null && (
          <small className="veil-warn">
            This note has no leaf index — run recovery on the Wallet screen first.
          </small>
        )}
        {leavesLoading && (
          <small className="veil-muted">Fetching Merkle tree from chain…</small>
        )}
      </label>

      {selectedNote && (
        <dl className="veil-dl" style={{ marginBottom: 12 }}>
          <dt>Amount</dt><dd>{selectedNote.amount} <span className="veil-muted">(private)</span></dd>
          <dt>Asset</dt><dd className="veil-muted">{selectedNote.asset_id.slice(0, 16)}… (private)</dd>
        </dl>
      )}

      <label className="veil-field">
        Asset out (field element decimal)
        <input
          type="text"
          value={assetOut}
          onChange={(e) => setAssetOut(e.target.value)}
          disabled={busy}
          placeholder="Target asset_id"
        />
      </label>

      <label className="veil-field">
        Minimum output (slippage protection)
        <input
          type="number"
          min="0"
          value={minOut}
          onChange={(e) => setMinOut(e.target.value)}
          disabled={busy}
          placeholder="0"
        />
        <small className="veil-muted">
          Order is excluded from the batch if output would be below this — the
          slippage bound is enforced by the settlement ZK proof.
        </small>
      </label>

      {state.step !== 'idle' && (
        <StatusBanner
          kind={
            state.step === 'error'
              ? 'error'
              : state.step === 'awaiting_settlement'
              ? 'info'
              : 'info'
          }
        >
          {state.step === 'error' ? state.error : stepLabel(state.step)}
          {state.txHash && state.step !== 'error' && (
            <span> · tx {state.txHash.slice(0, 12)}…</span>
          )}
        </StatusBanner>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button
          className="veil-btn"
          onClick={handleSubmit}
          disabled={busy || !address || !selectedCm || !assetOut}
        >
          {busy ? 'Working…' : 'Submit swap order'}
        </button>
        {(state.step === 'error' || state.step === 'awaiting_settlement') && (
          <button className="veil-btn-ghost" onClick={reset}>
            New order
          </button>
        )}
      </div>

      <p className="veil-muted veil-small" style={{ marginTop: 12 }}>
        Private: trade size, asset, counterparty, balances, pool reserves.
        Public: a nullifier (spent note) + batch aggregate at settlement.
      </p>
    </section>
  );
}
