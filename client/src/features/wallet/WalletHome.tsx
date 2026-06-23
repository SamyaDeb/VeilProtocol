import { useEffect, useMemo, useState } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { balancesByAsset, getUnspentNotes, loadNotes, noteLeafIndex } from '../../lib/notes';
import { getAnonymitySet } from '../../lib/indexer';
import { getCurrentRoot } from '../../lib/rpc';
import type { AnonymitySet, StoredNote } from '../../types';

function shortHex(s: string, n = 10): string {
  const v = BigInt(s).toString(16);
  return v.length > n ? `${v.slice(0, n)}…` : v;
}

export function WalletHome() {
  const { address } = useWallet();
  const [notes, setNotes] = useState<StoredNote[]>([]);
  const [anon, setAnon] = useState<AnonymitySet | null>(null);
  const [root, setRoot] = useState<string | null>(null);
  const [rootErr, setRootErr] = useState<string | null>(null);

  // Local note store — available with or without a wallet connection.
  useEffect(() => {
    setNotes(loadNotes());
  }, []);

  // Pool-level metrics from the indexer (best-effort; null if offline).
  useEffect(() => {
    getAnonymitySet().then(setAnon);
  }, []);

  // On-chain root requires a source account to simulate against.
  useEffect(() => {
    if (!address) return;
    getCurrentRoot(address)
      .then((r) => {
        setRoot(r);
        setRootErr(null);
      })
      .catch((e) => setRootErr(e instanceof Error ? e.message : String(e)));
  }, [address]);

  const balances = useMemo(() => Array.from(balancesByAsset().entries()), [notes]);
  const unspent = useMemo(() => getUnspentNotes(), [notes]);

  return (
    <div className="veil-grid">
      <section className="veil-card">
        <h2>Shielded balances</h2>
        {balances.length === 0 ? (
          <p className="veil-muted">
            No notes yet. Deposit a vetted asset through the ASP gate to mint your
            first shielded note.
          </p>
        ) : (
          <table className="veil-table">
            <thead>
              <tr>
                <th>Asset</th>
                <th>Balance (private)</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {balances.map(([assetId, total]) => (
                <tr key={assetId}>
                  <td>{shortHex(assetId)}</td>
                  <td>{total.toString()}</td>
                  <td>{unspent.filter((n) => n.asset_id === assetId).length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="veil-card">
        <h2>Notes (UTXOs)</h2>
        {notes.length === 0 ? (
          <p className="veil-muted">Your local note store is empty.</p>
        ) : (
          <table className="veil-table">
            <thead>
              <tr>
                <th>Commitment</th>
                <th>Amount</th>
                <th>Leaf</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {notes.map((n) => (
                <tr key={n.commitment}>
                  <td>{shortHex(n.commitment)}</td>
                  <td>{n.amount}</td>
                  <td>{noteLeafIndex(n) ?? '—'}</td>
                  <td>{n.spent ? 'spent' : n.pending ? 'pending' : 'unspent'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section className="veil-card">
        <h2>Pool status</h2>
        <dl className="veil-dl">
          <dt>On-chain root</dt>
          <dd>
            {root ? `${root.slice(0, 16)}…` : rootErr ? <span className="veil-warn">{rootErr}</span> : address ? 'loading…' : 'connect wallet'}
          </dd>
          <dt>Anonymity set</dt>
          <dd>{anon ? `${anon.commitment_count} commitments` : 'indexer offline'}</dd>
          {anon?.de_anon_warning && (
            <>
              <dt>Privacy notice</dt>
              <dd className="veil-warn">{anon.de_anon_warning}</dd>
            </>
          )}
        </dl>
        <p className="veil-muted veil-small">
          Privacy grows with the anonymity set. Avoid unique round-number amounts
          and depositing then immediately withdrawing the same value.
        </p>
      </section>
    </div>
  );
}
