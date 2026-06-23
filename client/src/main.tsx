import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { WalletProvider } from './providers/WalletProvider';
import { App } from './App';
import './styles.css';

const root = document.getElementById('root');
if (!root) throw new Error('#root element not found');

createRoot(root).render(
  <StrictMode>
    <WalletProvider>
      <App />
    </WalletProvider>
  </StrictMode>,
);
