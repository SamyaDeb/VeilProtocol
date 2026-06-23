import type { ReactNode } from 'react';
import { config, ACTIVE_NETWORK } from '../config';
import { useWallet } from '../providers/WalletProvider';

interface Tab {
  id: string;
  label: string;
}

interface LayoutProps {
  tabs: Tab[];
  active: string;
  onSelect: (id: string) => void;
  children: ReactNode;
}

function shortAddr(a: string): string {
  return `${a.slice(0, 4)}…${a.slice(-4)}`;
}

export function Layout({ tabs, active, onSelect, children }: LayoutProps) {
  const { address, connecting, error, connect, disconnect } = useWallet();

  return (
    <div className="veil-app">
      <header className="veil-header">
        <div className="veil-brand">
          <span className="veil-logo">◈</span> Veil Protocol
          <span className={`veil-net veil-net-${ACTIVE_NETWORK}`}>{config.network}</span>
        </div>
        <div className="veil-wallet">
          {address ? (
            <button className="veil-btn-ghost" onClick={disconnect} title={address}>
              {shortAddr(address)} · disconnect
            </button>
          ) : (
            <button className="veil-btn" onClick={connect} disabled={connecting}>
              {connecting ? 'Connecting…' : 'Connect Freighter'}
            </button>
          )}
        </div>
      </header>

      {error && <div className="veil-banner veil-banner-warn">{error}</div>}

      <nav className="veil-tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`veil-tab ${active === t.id ? 'is-active' : ''}`}
            onClick={() => onSelect(t.id)}
          >
            {t.label}
          </button>
        ))}
      </nav>

      <main className="veil-main">{children}</main>

      <footer className="veil-footer">
        Privacy-preserving DeFi on Stellar · amounts &amp; counterparties hidden ·
        ASP-gated · auditor view keys
      </footer>
    </div>
  );
}
