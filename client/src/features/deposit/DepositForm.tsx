import { useState, useEffect } from 'react';
import { useWallet } from '../../providers/WalletProvider';
import { StatusBanner } from '../../components/StatusBanner';
import { getOrCreateOwnerSk } from '../../lib/identity';
import { useDeposit, type DepositStep } from './useDeposit';
import { checkAmountPrivacy, checkAnonSetSize } from '../../lib/privacy';
import { getAnonymitySet } from '../../lib/indexer';
import { config } from '../../config';

// Dev/testnet: well-known credential values.
// Production: credential comes from the KYC provider (M3+).
const DEFAULT_CRED_SECRET = '1'; // Poseidon(1, 456) must be in the approved tree
const DEFAULT_ISSUER_PK = '456';

function stepLabel(step: DepositStep): string {
  switch (step) {
    case 'building_inputs': return 'Building circuit inputs…';
    case 'proving':         return 'Generating ZK proof (may take 10–30 s)…';
    case 'encrypting':      return 'Encrypting note for auditor (RULE 4)…';
    case 'submitting':      return 'Submitting transaction via Freighter…';
    case 'success':         return 'Deposit confirmed!';
    case 'error':           return '';
    default:                return '';
  }
}

export function DepositForm() {
  const { address, signXdr } = useWallet();
  const { state, deposit, reset } = useDeposit();

  const [amount, setAmount] = useState('');
  const [assetId, setAssetId] = useState('');
  const [credSecret, setCredSecret] = useState(DEFAULT_CRED_SECRET);
  const [issuerPk, setIssuerPk] = useState(DEFAULT_ISSUER_PK);
  const [anonCount, setAnonCount] = useState<number | null>(null);

  useEffect(() => {
    getAnonymitySet().then((a) => setAnonCount(a?.commitment_count ?? null));
  }, []);

  const busy = !['idle', 'success', 'error'].includes(state.step);

  async function handleSubmit() {
    if (!address || !signXdr) return;
    const amt = BigInt(amount.trim());
    if (amt <= 0n) return;
    const asset = assetId.trim() || config.tokenContract;

    const ownerSk = getOrCreateOwnerSk();
    const { buildPoseidon } = await import('circomlibjs');
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const ownerPk = BigInt(F.toString(poseidon([ownerSk])));

    // Dev: single-leaf approved tree, empty blocked tree with sentinels.
    const cred = BigInt(credSecret.trim());
    const iss = BigInt(issuerPk.trim());
    const credLeaf = BigInt(F.toString(poseidon([cred, iss])));
    const MAX = (1n << 252n) - 1n;

    // assetId: if it looks like a decimal field element use it directly; otherwise
    // Poseidon-hash the raw bytes of the contract address string into a field element.
    const assetBytes = Buffer.from(asset, 'utf8');
    const assetFieldEl = /^[0-9]+$/.test(asset)
      ? BigInt(asset)
      : BigInt(F.toString(poseidon([BigInt('0x' + assetBytes.toString('hex'))])));

    await deposit({
      address,
      signXdr,
      ownerSk,
      ownerPk,
      amount: amt,
      assetId: assetFieldEl,
      credSecret: cred,
      issuerPk: iss,
      approvedTreeLeaves: [credLeaf],
      blockedTreeLeaves: [1n, MAX],
    });
  }

  const amtWarning = amount ? checkAmountPrivacy(BigInt(amount || '0')) : null;
  const anonWarning = anonCount !== null ? checkAnonSetSize(anonCount) : null;

  return (
    <section className="veil-card">
      <h2>Compliant shielded deposit</h2>
      <p className="veil-muted">
        Your deposit is ASP-gated (RULE 1): a ZK proof attests you are in the
        approved set and not in the blocked set, without revealing your identity.
        The resulting note is privately spendable across all modules.
      </p>

      {!address && (
        <StatusBanner kind="warn">Connect Freighter to deposit.</StatusBanner>
      )}

      {anonWarning && (
        <StatusBanner kind={anonWarning.level === 'high' ? 'warn' : 'info'}>
          {anonWarning.message}
        </StatusBanner>
      )}

      <label className="veil-field">
        Amount (stroops / token units)
        <input
          type="number"
          min="1"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
          disabled={busy}
          placeholder="e.g. 1000000"
        />
      </label>
      {amtWarning && (
        <StatusBanner kind="warn">{amtWarning.message}</StatusBanner>
      )}

      <label className="veil-field">
        Asset ID (field element decimal, or leave blank for TEST-RWA)
        <input
          type="text"
          value={assetId}
          onChange={(e) => setAssetId(e.target.value)}
          disabled={busy}
          placeholder={config.tokenContract || '0'}
        />
        <small className="veil-muted">
          This field is <strong>private</strong> — not revealed on-chain.
        </small>
      </label>

      <details className="veil-field">
        <summary className="veil-muted" style={{ cursor: 'pointer' }}>
          KYC credential (advanced)
        </summary>
        <label className="veil-field" style={{ marginTop: 8 }}>
          Credential secret
          <input
            type="password"
            value={credSecret}
            onChange={(e) => setCredSecret(e.target.value)}
            disabled={busy}
          />
        </label>
        <label className="veil-field">
          Issuer public key (field element)
          <input
            type="text"
            value={issuerPk}
            onChange={(e) => setIssuerPk(e.target.value)}
            disabled={busy}
          />
        </label>
        <p className="veil-muted veil-small">
          Dev defaults match the testnet ASP seeded in the e2e suite. Production
          credentials come from the KYC provider (M3+).
        </p>
      </details>

      {state.step !== 'idle' && state.step !== 'error' && (
        <StatusBanner kind={state.step === 'success' ? 'success' : 'info'}>
          {stepLabel(state.step)}
          {state.step === 'success' && state.txHash && (
            <span> · tx {state.txHash.slice(0, 12)}…</span>
          )}
          {state.step === 'success' && state.leafIdx !== null && (
            <span> · leaf #{state.leafIdx}</span>
          )}
        </StatusBanner>
      )}
      {state.step === 'error' && (
        <StatusBanner kind="error">{state.error}</StatusBanner>
      )}

      <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
        <button
          className="veil-btn"
          onClick={handleSubmit}
          disabled={busy || !address || !amount}
        >
          {busy ? 'Working…' : 'Prove & deposit'}
        </button>
        {(state.step === 'success' || state.step === 'error') && (
          <button className="veil-btn-ghost" onClick={reset}>
            Reset
          </button>
        )}
      </div>

      <p className="veil-muted veil-small" style={{ marginTop: 12 }}>
        Private fields: amount, asset, owner identity.
        Public: commitment inserted into the shared Merkle tree, ASP roots.
      </p>
    </section>
  );
}
