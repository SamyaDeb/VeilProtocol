import { useState } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { requestDisclosure } from '../../lib/rpc';
import { StatusBanner } from '../../components/StatusBanner';
import type { DecryptedNote } from '../../types';
// Shared JS crypto core (also used by Node e2e); imported loosely, cast below.
import { decryptNoteAsAuditor } from '../../viewkey/encrypt.js';

type Status = { kind: 'info' | 'success' | 'warn' | 'error'; msg: string } | null;

export function AuditorPanel() {
  const { address, signXdr } = useWallet();
  const [idx, setIdx] = useState('0');
  const [skHex, setSkHex] = useState('');
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<Status>(null);
  const [note, setNote] = useState<DecryptedNote | null>(null);

  async function onRequest() {
    setBusy(true);
    setNote(null);
    setStatus(null);
    try {
      if (!address) {
        throw new Error('Connect a wallet (top right) to authorize the disclosure request.');
      }
      const auditor = address;

      const clean = skHex.replace(/^0x/, '');
      if (clean.length !== 64) throw new Error('Secret key must be 32 bytes (64 hex chars).');
      const auditorSk = BigInt('0x' + clean);

      setStatus({ kind: 'info', msg: 'Fetching ciphertext on-chain (logs the disclosure)…' });
      const ct = await requestDisclosure(auditor, BigInt(idx), signXdr);
      if (!ct) {
        setStatus({ kind: 'warn', msg: `No ciphertext stored at index ${idx}.` });
        return;
      }

      setStatus({ kind: 'info', msg: 'Decrypting off-chain…' });
      const decrypted = (await decryptNoteAsAuditor(ct, auditorSk)) as DecryptedNote;
      setNote(decrypted);
      setStatus({ kind: 'success', msg: `Disclosure complete for index ${idx}.` });
    } catch (e) {
      setStatus({ kind: 'error', msg: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="veil-card">
      <h2>Auditor — selective disclosure</h2>
      <p className="veil-muted">
        Decrypt exactly the in-scope note at a commitment index. The on-chain call
        logs the request for the audit trail; decryption happens locally and the
        secret key never leaves the browser. The key can read — it cannot spend.
      </p>

      <label className="veil-field">
        Commitment index
        <input type="number" min={0} value={idx} onChange={(e) => setIdx(e.target.value)} />
      </label>

      <label className="veil-field">
        Auditor secret key (hex, 32 bytes)
        <input
          type="password"
          placeholder="0x…"
          value={skHex}
          onChange={(e) => setSkHex(e.target.value)}
        />
      </label>

      <button className="veil-btn" onClick={onRequest} disabled={busy}>
        {busy ? 'Working…' : 'Request disclosure'}
      </button>

      {status && <StatusBanner kind={status.kind}>{status.msg}</StatusBanner>}

      {note && (
        <table className="veil-table veil-mt">
          <tbody>
            <tr><td>Amount</td><td>{note.amount.toString()}</td></tr>
            <tr><td>Asset ID</td><td>{note.asset_id.toString(16)}</td></tr>
            <tr><td>Owner PK</td><td>{note.owner_pk.toString(16)}</td></tr>
            <tr><td>Blinding</td><td>{note.blinding.toString(16)}</td></tr>
          </tbody>
        </table>
      )}
    </section>
  );
}
