import { useState, useEffect } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { StatusBanner } from '../../components/StatusBanner';
import { NoteSelector } from '../../components/NoteSelector';
import { getUnspentNotes } from '../../lib/notes';
import { getOrCreateOwnerSk } from '../../lib/identity';
import { getLeaves } from '../../lib/rpc';
import { useWithdraw, type WithdrawStep } from './useWithdraw';
import { checkAmountPrivacy } from '../../lib/privacy';
import type { StoredNote } from '../../types';

function stepLabel(step: WithdrawStep): string {
  switch (step) {
    case 'building_inputs': return 'Building circuit inputs & Merkle path…';
    case 'proving':          return 'Generating ZK withdraw proof (10–30 s)…';
    case 'encrypting':       return 'Encrypting change note for auditor (RULE 4)…';
    case 'submitting':       return 'Submitting withdraw transaction…';
    case 'success':          return 'Withdraw confirmed!';
    case 'error':            return '';
    default:                 return '';
  }
}

export function WithdrawForm() {
  const { address, signXdr } = useWallet();
  const { state, withdraw, reset } = useWithdraw();

  const [notes, setNotes] = useState<StoredNote[]>([]);
  const [selectedCm, setSelectedCm] = useState('');
  const [recipient, setRecipient] = useState('');
  const [amount, setAmount] = useState('');
  const [leaves, setLeaves] = useState<bigint[]>([]);

  useEffect(() => { setNotes(getUnspentNotes()); }, []);

  useEffect(() => {
    if (!address) return;
    getLeaves(address)
      .then((evts) => setLeaves(evts.map((e) => BigInt('0x' + e.commitment))))
      .catch(() => setLeaves([]));
  }, [address]);

  const selectedNote = notes.find((n) => n.commitment === selectedCm);
  const busy = !['idle', 'success', 'error'].includes(state.step);

  // Set amount to full note amount when a note is selected.
  useEffect(() => {
    if (selectedNote) setAmount(selectedNote.amount);
  }, [selectedNote]);

  const amtWarning = amount ? checkAmountPrivacy(BigInt(amount || '0')) : null;

  async function handleSubmit() {
    if (!address || !signXdr || !selectedNote) return;
    if (!recipient.startsWith('G') || recipient.length < 56) {
      alert('Enter a valid Stellar G-address for the recipient.');
      return;
    }
    const amt = BigInt(amount.trim());
    if (amt <= 0n || amt > BigInt(selectedNote.amount)) return;
    const ownerSk = getOrCreateOwnerSk();

    await withdraw({
      address,
      signXdr,
      inputNote: selectedNote,
      ownerSk,
      treeLeaves: leaves,
      withdrawAmount: amt,
      recipientAddress: recipient.trim(),
    });
  }

  return (
    <section className="veil-card">
      <h2>Shielded withdraw</h2>
      <p className="veil-muted">
        Exit to a public Stellar address. A ZK proof shows your note is valid and
        unspent without revealing the amount or your identity. A change note is
        minted if you withdraw less than the full note (RULE 4 — change note has
        auditor ciphertext).
      </p>

      {!address && <StatusBanner kind="warn">Connect Freighter to withdraw.</StatusBanner>}

      <label className="veil-field">
        Note to spend
        <NoteSelector notes={notes} value={selectedCm} onChange={setSelectedCm} />
      </label>

      {selectedNote && (
        <dl className="veil-dl" style={{ marginBottom: 12 }}>
          <dt>Available</dt><dd>{selectedNote.amount} <span className="veil-muted">(private)</span></dd>
        </dl>
      )}

      <label className="veil-field">
        Amount to withdraw
        <input
          type="number"
          min="1"
          max={selectedNote?.amount}
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          disabled={busy}
        />
        {selectedNote && amount && BigInt(amount) < BigInt(selectedNote.amount) && (
          <small className="veil-muted">
            Change ({(BigInt(selectedNote.amount) - BigInt(amount)).toString()} tokens) stays shielded as a new note.
          </small>
        )}
      </label>
      {amtWarning && <StatusBanner kind="warn">{amtWarning.message}</StatusBanner>}

      <label className="veil-field">
        Recipient Stellar address
        <input
          type="text"
          value={recipient}
          onChange={(e) => setRecipient(e.target.value)}
          disabled={busy}
          placeholder="G…"
        />
        <small className="veil-muted">
          Recipient address is <strong>public</strong> (visible on-chain).
        </small>
      </label>

      {state.step !== 'idle' && (
        <StatusBanner kind={state.step === 'error' ? 'error' : state.step === 'success' ? 'success' : 'info'}>
          {state.step === 'error' ? state.error : stepLabel(state.step)}
          {state.step === 'success' && state.txHash && (
            <span> · tx {state.txHash.slice(0, 12)}…</span>
          )}
          {state.step === 'success' && state.changeCommitment && (
            <span> · change note saved</span>
          )}
        </StatusBanner>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button
          className="veil-btn"
          onClick={handleSubmit}
          disabled={busy || !address || !selectedCm || !amount || !recipient}
        >
          {busy ? 'Working…' : 'Prove & withdraw'}
        </button>
        {(state.step === 'success' || state.step === 'error') && (
          <button className="veil-btn-ghost" onClick={reset}>Reset</button>
        )}
      </div>

      <p className="veil-muted veil-small" style={{ marginTop: 12 }}>
        Public: recipient address, commitment + nullifier on-chain.
        Private: amount, asset, your identity.
      </p>
    </section>
  );
}
