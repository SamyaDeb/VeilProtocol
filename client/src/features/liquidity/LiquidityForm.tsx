import { useState, useEffect } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { StatusBanner } from '../../components/StatusBanner';
import { NoteSelector } from '../../components/NoteSelector';
import { getUnspentNotes } from '../../lib/notes';
import { getOrCreateOwnerSk } from '../../lib/identity';
import { getLeaves } from '../../lib/rpc';
import { useLiquidity, type LiquidityStep } from './useLiquidity';
import type { StoredNote } from '../../types';

function stepLabel(step: LiquidityStep): string {
  switch (step) {
    case 'building_inputs': return 'Building circuit inputs…';
    case 'proving':          return 'Generating ZK liquidity proof (10–30 s)…';
    case 'encrypting':       return 'Encrypting LP note for auditor (RULE 4)…';
    case 'submitting':       return 'Submitting transaction…';
    case 'success':          return 'Done!';
    case 'error':            return '';
    default:                 return '';
  }
}

type LiquidityMode = 'add' | 'remove';

// Dev placeholders — in production read from AMM pool's encrypted_reserves via committee.
// VERIFY: get pre_reserves, pre_total_shares, reserve_blinding from AMM pool contract.
const DEV_RESERVES: [bigint, bigint] = [1000000n, 1000000n];
const DEV_TOTAL_SHARES = 1000000n;
const DEV_RESERVE_BLINDING = 42n;

export function LiquidityForm() {
  const { address, signXdr } = useWallet();
  const { state, addLiquidity, removeLiquidity, reset } = useLiquidity();

  const [mode, setMode] = useState<LiquidityMode>('add');
  const [notes, setNotes] = useState<StoredNote[]>([]);
  const [selectedCm0, setSelectedCm0] = useState('');
  const [selectedCm1, setSelectedCm1] = useState('');
  const [lpCm, setLpCm] = useState('');
  const [asset0, setAsset0] = useState('');
  const [asset1, setAsset1] = useState('');
  const [leaves, setLeaves] = useState<bigint[]>([]);

  const regularNotes = notes.filter((n) => n.note_type !== 'lp');
  const lpNotes = notes.filter((n) => n.note_type === 'lp');

  useEffect(() => { setNotes(getUnspentNotes()); }, []);

  useEffect(() => {
    if (!address) return;
    getLeaves(address)
      .then((evts) => setLeaves(evts.map((e) => BigInt('0x' + e.commitment))))
      .catch(() => setLeaves([]));
  }, [address]);

  const busy = !['idle', 'success', 'error'].includes(state.step);

  const selectedNote0 = notes.find((n) => n.commitment === selectedCm0);
  const selectedNote1 = notes.find((n) => n.commitment === selectedCm1);
  const selectedLpNote = lpNotes.find((n) => n.commitment === lpCm);

  async function handleAdd() {
    if (!address || !signXdr || !selectedNote0 || !selectedNote1) return;
    const ownerSk = getOrCreateOwnerSk();
    await addLiquidity({
      address, signXdr, ownerSk, treeLeaves: leaves,
      note0: selectedNote0,
      note1: selectedNote1,
      preReserves: DEV_RESERVES,
      preTotalShares: DEV_TOTAL_SHARES,
      reserveBlinding: DEV_RESERVE_BLINDING,
    });
  }

  async function handleRemove() {
    if (!address || !signXdr || !selectedLpNote) return;
    const ownerSk = getOrCreateOwnerSk();
    await removeLiquidity({
      address, signXdr, ownerSk, treeLeaves: leaves,
      lpNote: selectedLpNote,
      preReserves: DEV_RESERVES,
      preTotalShares: DEV_TOTAL_SHARES,
      reserveBlinding: DEV_RESERVE_BLINDING,
      asset0: BigInt(asset0.trim() || '0'),
      asset1: BigInt(asset1.trim() || '0'),
    });
  }

  return (
    <section className="veil-card">
      <h2>Shielded liquidity provision</h2>
      <p className="veil-muted">
        Add or remove liquidity with hidden position size. Notes from any module
        (deposit, swap, borrow) work as LP inputs without conversion (RULE 2).
        Fee accrual is computed locally from reserve snapshots.
      </p>

      {!address && <StatusBanner kind="warn">Connect Freighter to provide liquidity.</StatusBanner>}

      <div className="veil-tabs" style={{ marginTop: 0, marginBottom: 16 }}>
        <button
          className={`veil-tab ${mode === 'add' ? 'is-active' : ''}`}
          onClick={() => { setMode('add'); reset(); }}
        >
          Add liquidity
        </button>
        <button
          className={`veil-tab ${mode === 'remove' ? 'is-active' : ''}`}
          onClick={() => { setMode('remove'); reset(); }}
        >
          Remove liquidity
        </button>
      </div>

      {mode === 'add' && (
        <>
          <label className="veil-field">
            Token 0 note
            <NoteSelector notes={regularNotes} value={selectedCm0} onChange={setSelectedCm0} placeholder="— select token 0 note —" />
          </label>
          <label className="veil-field">
            Token 1 note
            <NoteSelector notes={regularNotes} value={selectedCm1} onChange={setSelectedCm1} placeholder="— select token 1 note —" />
          </label>
          {selectedNote0 && selectedNote1 && (
            <dl className="veil-dl" style={{ marginBottom: 12 }}>
              <dt>Token 0</dt><dd>{selectedNote0.amount} <span className="veil-muted">(private)</span></dd>
              <dt>Token 1</dt><dd>{selectedNote1.amount} <span className="veil-muted">(private)</span></dd>
            </dl>
          )}
          <p className="veil-muted veil-small">
            Reserves are committee-encrypted. Your LP share size is hidden on-chain.
          </p>
        </>
      )}

      {mode === 'remove' && (
        <>
          <label className="veil-field">
            LP note
            <NoteSelector notes={lpNotes} value={lpCm} onChange={setLpCm} placeholder="— select LP note —" />
          </label>
          <label className="veil-field">
            Output asset 0 (field element decimal)
            <input type="text" value={asset0} onChange={(e) => setAsset0(e.target.value)} disabled={busy} placeholder="0" />
          </label>
          <label className="veil-field">
            Output asset 1 (field element decimal)
            <input type="text" value={asset1} onChange={(e) => setAsset1(e.target.value)} disabled={busy} placeholder="0" />
          </label>
          {selectedLpNote && (
            <dl className="veil-dl" style={{ marginBottom: 12 }}>
              <dt>LP shares</dt><dd>{selectedLpNote.amount} <span className="veil-muted">(private)</span></dd>
              {selectedLpNote.deposit_value_0 && (
                <>
                  <dt>Deposit value (T0)</dt><dd>{selectedLpNote.deposit_value_0}</dd>
                  <dt>Deposit value (T1)</dt><dd>{selectedLpNote.deposit_value_1}</dd>
                </>
              )}
            </dl>
          )}
        </>
      )}

      {state.step === 'success' && state.feeInfo && (
        <StatusBanner kind="success">
          Removed! Fees earned: {state.feeInfo.fee0.toString()} T0 + {state.feeInfo.fee1.toString()} T1
        </StatusBanner>
      )}

      {state.step !== 'idle' && (
        <StatusBanner kind={state.step === 'error' ? 'error' : state.step === 'success' ? 'success' : 'info'}>
          {state.step === 'error' ? state.error : stepLabel(state.step)}
          {state.txHash && state.step === 'success' && (
            <span> · tx {state.txHash.slice(0, 12)}…</span>
          )}
        </StatusBanner>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        {mode === 'add' ? (
          <button
            className="veil-btn"
            onClick={handleAdd}
            disabled={busy || !address || !selectedCm0 || !selectedCm1}
          >
            {busy ? 'Working…' : 'Prove & add liquidity'}
          </button>
        ) : (
          <button
            className="veil-btn"
            onClick={handleRemove}
            disabled={busy || !address || !lpCm}
          >
            {busy ? 'Working…' : 'Prove & remove liquidity'}
          </button>
        )}
        {(state.step === 'success' || state.step === 'error') && (
          <button className="veil-btn-ghost" onClick={reset}>Reset</button>
        )}
      </div>

      <p className="veil-muted veil-small" style={{ marginTop: 12 }}>
        Private: LP position size, fee amounts, token balances.
        Public: two nullifiers spent (LP add) or one nullifier (LP remove).
      </p>
    </section>
  );
}
