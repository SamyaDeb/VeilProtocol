import { useState, useEffect } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { StatusBanner } from '../../components/StatusBanner';
import { NoteSelector } from '../../components/NoteSelector';
import { getUnspentNotes } from '../../lib/notes';
import { getOrCreateOwnerSk } from '../../lib/identity';
import { getLeaves, getOraclePrice } from '../../lib/rpc';
import { useLend, type LendStep } from './useLend';
import type { StoredNote } from '../../types';

// VERIFY: LTV from deployments/mainnet.json lending.ltv_max_bps
const DEFAULT_LTV_BPS = 7500n; // 75%
const DEFAULT_ORACLE_ASSET = 'TEST-RWA';

function stepLabel(step: LendStep): string {
  switch (step) {
    case 'fetching_oracle':  return 'Fetching fresh oracle price from Reflector…';
    case 'building_inputs': return 'Building circuit inputs & Merkle path…';
    case 'proving':          return 'Generating ZK LTV proof (10–30 s)…';
    case 'encrypting':       return 'Encrypting borrow note for auditor (RULE 4)…';
    case 'submitting':       return 'Submitting open_loan transaction…';
    case 'success':          return 'Loan opened!';
    case 'error':            return '';
    default:                 return '';
  }
}

export function LendForm() {
  const { address, signXdr } = useWallet();
  const { state, openLoan, reset } = useLend();

  const [notes, setNotes] = useState<StoredNote[]>([]);
  const [selectedCm, setSelectedCm] = useState('');
  const [borrowAmount, setBorrowAmount] = useState('');
  const [borrowAsset, setBorrowAsset] = useState('');
  const [oracleAsset, setOracleAsset] = useState(DEFAULT_ORACLE_ASSET);
  const [leaves, setLeaves] = useState<bigint[]>([]);
  const [livePrice, setLivePrice] = useState<{ price: bigint; decimals: bigint } | null>(null);
  const [priceLoading, setPriceLoading] = useState(false);

  useEffect(() => { setNotes(getUnspentNotes()); }, []);

  useEffect(() => {
    if (!address) return;
    getLeaves(address)
      .then((evts) => setLeaves(evts.map((e) => BigInt('0x' + e.commitment))))
      .catch(() => setLeaves([]));
  }, [address]);

  // Show live oracle price for UX.
  useEffect(() => {
    if (!address || !oracleAsset) return;
    setPriceLoading(true);
    getOraclePrice(address, oracleAsset)
      .then(setLivePrice)
      .catch(() => setLivePrice(null))
      .finally(() => setPriceLoading(false));
  }, [address, oracleAsset]);

  const selectedNote = notes.find((n) => n.commitment === selectedCm);
  const busy = !['idle', 'success', 'error'].includes(state.step);

  // Estimated LTV display.
  const estimatedLtv = (() => {
    if (!selectedNote || !borrowAmount || !livePrice) return null;
    try {
      const collat = BigInt(selectedNote.amount);
      const borrow = BigInt(borrowAmount.trim());
      // Simplified LTV estimate (same unit for both sides — oracle prices cancel).
      const ltv = (borrow * 10000n) / collat;
      return `≈${Number(ltv) / 100}% LTV`;
    } catch {
      return null;
    }
  })();

  async function handleSubmit() {
    if (!address || !signXdr || !selectedNote) return;
    const ownerSk = getOrCreateOwnerSk();
    const borrow = BigInt(borrowAmount.trim());
    const borrowAssetId = BigInt(borrowAsset.trim() || '0');

    await openLoan({
      address,
      signXdr,
      collatNote: selectedNote,
      ownerSk,
      treeLeaves: leaves,
      borrowAmount: borrow,
      borrowAssetId,
      oracleAsset,
      ltvMaxBps: DEFAULT_LTV_BPS,
    });
  }

  return (
    <section className="veil-card">
      <h2>Private RWA-collateralized borrow</h2>
      <p className="veil-muted">
        Lock a shielded RWA note as collateral (RULE 3 — locked set) and mint a
        borrow note. The ZK proof shows borrow ≤ LTV × collateral at the current
        oracle price — without revealing either amount.
      </p>

      {!address && <StatusBanner kind="warn">Connect Freighter to borrow.</StatusBanner>}

      <label className="veil-field">
        Collateral note (RWA)
        <NoteSelector
          notes={notes}
          value={selectedCm}
          onChange={setSelectedCm}
          placeholder="— select collateral note —"
        />
      </label>

      {selectedNote && (
        <dl className="veil-dl" style={{ marginBottom: 12 }}>
          <dt>Collateral</dt>
          <dd>{selectedNote.amount} <span className="veil-muted">(private)</span></dd>
          {livePrice && (
            <>
              <dt>Oracle price</dt>
              <dd>
                {livePrice.price.toString()} (×10<sup>-{livePrice.decimals.toString()}</sup>)
                {priceLoading && <span className="veil-muted"> refreshing…</span>}
              </dd>
            </>
          )}
        </dl>
      )}

      <label className="veil-field">
        Oracle asset (e.g. TEST-RWA, BENJI)
        <input
          type="text"
          value={oracleAsset}
          onChange={(e) => setOracleAsset(e.target.value)}
          disabled={busy}
        />
        <small className="veil-muted">
          Oracle price is read on-chain at submission time and bound to the proof.
          Asset identity is public (THREAT_MODEL §1.3 — accepted for v1).
        </small>
      </label>

      <label className="veil-field">
        Borrow amount
        <input
          type="number"
          min="1"
          value={borrowAmount}
          onChange={(e) => setBorrowAmount(e.target.value)}
          disabled={busy}
        />
        {estimatedLtv && (
          <small className="veil-muted">Estimated {estimatedLtv} · max {Number(DEFAULT_LTV_BPS) / 100}%</small>
        )}
        <small className="veil-muted">
          Amount is <strong>private</strong> — the proof only reveals the LTV is valid.
        </small>
      </label>

      <label className="veil-field">
        Borrow asset ID (field element)
        <input
          type="text"
          value={borrowAsset}
          onChange={(e) => setBorrowAsset(e.target.value)}
          disabled={busy}
          placeholder="0"
        />
      </label>

      {state.step !== 'idle' && (
        <StatusBanner kind={state.step === 'error' ? 'error' : state.step === 'success' ? 'success' : 'info'}>
          {state.step === 'error' ? state.error : stepLabel(state.step)}
          {state.step === 'success' && state.txHash && (
            <span> · tx {state.txHash.slice(0, 12)}…</span>
          )}
          {state.step === 'success' && state.loanId && (
            <span> · loan opened</span>
          )}
        </StatusBanner>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button
          className="veil-btn"
          onClick={handleSubmit}
          disabled={busy || !address || !selectedCm || !borrowAmount}
        >
          {busy ? 'Working…' : 'Prove & borrow'}
        </button>
        {(state.step === 'success' || state.step === 'error') && (
          <button className="veil-btn-ghost" onClick={reset}>Reset</button>
        )}
      </div>

      <p className="veil-muted veil-small" style={{ marginTop: 12 }}>
        Private: collateral amount, borrow amount, owner identity.
        Public: oracle asset read (asset type may be inferred — THREAT_MODEL §1.3).
      </p>
    </section>
  );
}
