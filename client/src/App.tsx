import { lazy, Suspense, useState } from 'react';
import { Layout } from './components/Layout';
import { WalletHome } from './features/wallet/WalletHome';
import { AuditorPanel } from './features/auditor/AuditorPanel';

// Lazy-load proving screens so snarkjs (~4 MB) is code-split from the initial bundle.
const DepositForm = lazy(() =>
  import('./features/deposit/DepositForm').then((m) => ({ default: m.DepositForm })),
);
const SwapForm = lazy(() =>
  import('./features/swap/SwapForm').then((m) => ({ default: m.SwapForm })),
);
const LendForm = lazy(() =>
  import('./features/lending/LendForm').then((m) => ({ default: m.LendForm })),
);
const LiquidityForm = lazy(() =>
  import('./features/liquidity/LiquidityForm').then((m) => ({ default: m.LiquidityForm })),
);
const WithdrawForm = lazy(() =>
  import('./features/withdraw/WithdrawForm').then((m) => ({ default: m.WithdrawForm })),
);

function ProveLoader() {
  return (
    <div className="veil-card" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <span className="veil-muted">Loading prover…</span>
    </div>
  );
}

const TABS = [
  { id: 'wallet',    label: 'Wallet',    render: () => <WalletHome /> },
  { id: 'deposit',   label: 'Deposit',   render: () => <Suspense fallback={<ProveLoader />}><DepositForm /></Suspense> },
  { id: 'swap',      label: 'Swap',      render: () => <Suspense fallback={<ProveLoader />}><SwapForm /></Suspense> },
  { id: 'lend',      label: 'Borrow',    render: () => <Suspense fallback={<ProveLoader />}><LendForm /></Suspense> },
  { id: 'liquidity', label: 'Liquidity', render: () => <Suspense fallback={<ProveLoader />}><LiquidityForm /></Suspense> },
  { id: 'withdraw',  label: 'Withdraw',  render: () => <Suspense fallback={<ProveLoader />}><WithdrawForm /></Suspense> },
  { id: 'auditor',   label: 'Auditor',   render: () => <AuditorPanel /> },
] as const;

export function App() {
  const [active, setActive] = useState<string>('wallet');
  const current = TABS.find((t) => t.id === active) ?? TABS[0];

  return (
    <Layout
      tabs={TABS.map((t) => ({ id: t.id, label: t.label }))}
      active={active}
      onSelect={setActive}
    >
      {current.render()}
    </Layout>
  );
}
