/**
 * Auditor UI — selective disclosure for M2.
 *
 * Allows an auditor with a view key (secret scalar) to:
 *   1. Enter a commitment index
 *   2. Call veil_core.request_disclosure to retrieve the ciphertext
 *      (logs the disclosure on-chain for audit trail)
 *   3. Decrypt the ciphertext locally with the auditor secret key
 *   4. Display the decrypted note (amount, asset, owner_pk) for the in-scope index
 *
 * Decryption is entirely off-chain. The secret key never leaves the browser.
 */

import { decryptNoteAsAuditor } from '../viewkey/encrypt.js';
import { connectWallet, getNetwork, signAndSubmit } from '../wallet/freighter.js';
import {
    Contract,
    SorobanRpc,
    TransactionBuilder,
    BASE_FEE,
    nativeToScVal,
} from '@stellar/stellar-sdk';

const VEIL_CORE_CONTRACT = import.meta.env.VITE_VEIL_CORE_CONTRACT ?? '';
const RPC_URL            = import.meta.env.VITE_RPC_URL ?? 'https://soroban-testnet.stellar.org';

/**
 * Mount the auditor disclosure UI into `containerEl`.
 * @param {HTMLElement} containerEl
 */
export function mountAuditorUI(containerEl) {
    containerEl.innerHTML = `
      <div class="veil-auditor">
        <h2>Auditor View — Selective Disclosure</h2>

        <label>Commitment index
          <input id="aud-idx" type="number" min="0" placeholder="0" />
        </label>

        <label>Auditor secret key (hex, 32 bytes)
          <input id="aud-sk" type="password" placeholder="0x..." />
        </label>

        <button id="aud-request">Request disclosure</button>
        <div id="aud-status"></div>

        <div id="aud-result" style="display:none">
          <h3>Decrypted note</h3>
          <table>
            <tr><td>Amount</td><td id="aud-amount"></td></tr>
            <tr><td>Asset ID</td><td id="aud-asset"></td></tr>
            <tr><td>Owner PK</td><td id="aud-owner"></td></tr>
            <tr><td>Blinding</td><td id="aud-blinding"></td></tr>
          </table>
        </div>
      </div>
    `;

    const idxEl      = containerEl.querySelector('#aud-idx');
    const skEl       = containerEl.querySelector('#aud-sk');
    const requestBtn = containerEl.querySelector('#aud-request');
    const statusEl   = containerEl.querySelector('#aud-status');
    const resultEl   = containerEl.querySelector('#aud-result');

    requestBtn.addEventListener('click', async () => {
        requestBtn.disabled = true;
        resultEl.style.display = 'none';
        statusEl.textContent = 'Connecting wallet…';

        try {
            const stellarAddress = await connectWallet();
            const { passphrase } = await getNetwork();
            const idx = BigInt(idxEl.value ?? '0');

            const skHex = skEl.value.replace(/^0x/, '');
            if (skHex.length !== 64) throw new Error('Secret key must be 32 bytes (64 hex chars)');
            const auditorSk = BigInt('0x' + skHex);

            // Call request_disclosure on-chain to retrieve ciphertext and log the request
            // VERIFY: exact XDR serialization for u64 argument in soroban-sdk 26.x / stellar-sdk 13.x
            statusEl.textContent = 'Fetching ciphertext from chain…';

            const server   = new SorobanRpc.Server(RPC_URL);
            const account  = await server.getAccount(stellarAddress);
            const contract = new Contract(VEIL_CORE_CONTRACT);

            const txBuilder = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: passphrase })
                .addOperation(contract.call(
                    'request_disclosure',
                    nativeToScVal(stellarAddress, { type: 'address' }),  // auditor = caller
                    nativeToScVal(idx, { type: 'u64' }),
                ))
                .setTimeout(30)
                .build();

            const preparedTx = await server.prepareTransaction(txBuilder);
            const signedXdr   = await signAndSubmit(preparedTx.toXDR(), passphrase);
            const sendResult  = await server.sendTransaction(
                TransactionBuilder.fromXDR(signedXdr, passphrase)
            );

            // Poll for result
            let txResult = null;
            for (let i = 0; i < 15; i++) {
                await new Promise(r => setTimeout(r, 2000));
                const status = await server.getTransaction(sendResult.hash);
                if (status.status === 'SUCCESS') { txResult = status; break; }
                if (status.status === 'FAILED')  throw new Error('Transaction failed');
            }
            if (!txResult) throw new Error('Transaction not confirmed within timeout');

            // Extract the returned Bytes (ciphertext) from the result value
            // VERIFY: result XDR parsing for Bytes return type
            const resultScVal = txResult.returnValue;
            if (!resultScVal || resultScVal.switch().name === 'scvVoid') {
                statusEl.textContent = 'No ciphertext at this index.';
                return;
            }

            const ctBytes = Buffer.from(resultScVal.bytes());
            if (ctBytes.length === 0) {
                statusEl.textContent = 'No ciphertext stored at this index.';
                return;
            }

            // Decrypt off-chain
            statusEl.textContent = 'Decrypting…';
            const decrypted = decryptNoteAsAuditor(ctBytes, auditorSk);

            containerEl.querySelector('#aud-amount').textContent   = decrypted.amount.toString();
            containerEl.querySelector('#aud-asset').textContent    = decrypted.asset_id.toString(16);
            containerEl.querySelector('#aud-owner').textContent    = decrypted.owner_pk.toString(16);
            containerEl.querySelector('#aud-blinding').textContent = decrypted.blinding.toString(16);

            resultEl.style.display = 'block';
            statusEl.textContent   = `Disclosure complete (index ${idx}).`;
        } catch (err) {
            statusEl.textContent = `Error: ${err.message}`;
            console.error(err);
        } finally {
            requestBtn.disabled = false;
        }
    });
}
