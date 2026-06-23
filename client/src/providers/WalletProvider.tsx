import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
// Reuse the existing (untouched) Freighter module; allowJs imports it as JS.
import { connectWallet, getNetwork, signAndSubmit } from '../wallet/freighter.js';
import { config } from '../config';

interface WalletState {
  address: string | null;
  connecting: boolean;
  error: string | null;
  connect: () => Promise<void>;
  disconnect: () => void;
  /** Sign a transaction XDR with Freighter; used by state-changing RPC calls. */
  signXdr: (xdr: string, networkPassphrase: string) => Promise<string>;
}

const WalletContext = createContext<WalletState | null>(null);

export function WalletProvider({ children }: { children: ReactNode }) {
  const [address, setAddress] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      const addr = (await connectWallet()) as string;
      // Surface a network mismatch early rather than failing deep in a tx.
      const net = (await getNetwork()) as { passphrase: string };
      if (net.passphrase && net.passphrase !== config.networkPassphrase) {
        setError(
          `Freighter is on a different network than the app (${config.network}). Switch networks in Freighter.`,
        );
      }
      setAddress(addr);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setConnecting(false);
    }
  }, []);

  const disconnect = useCallback(() => setAddress(null), []);

  const signXdr = useCallback(
    (xdr: string, networkPassphrase: string) =>
      signAndSubmit(xdr, networkPassphrase) as Promise<string>,
    [],
  );

  const value = useMemo<WalletState>(
    () => ({ address, connecting, error, connect, disconnect, signXdr }),
    [address, connecting, error, connect, disconnect, signXdr],
  );

  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function useWallet(): WalletState {
  const ctx = useContext(WalletContext);
  if (!ctx) throw new Error('useWallet must be used within <WalletProvider>');
  return ctx;
}
