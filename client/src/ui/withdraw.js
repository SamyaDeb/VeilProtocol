/**
 * Withdraw UI — shielded withdraw flow.
 *
 * Mounts into a container element. Reads unspent notes from localStorage,
 * generates the withdraw Groth16 proof in WASM, and submits via Freighter.
 *
 * M2 scope: single-note withdraw (input1 is dummy). Multi-note batching
 * is a follow-on UX improvement; the circuit and prover already support it.
 */

import { proveWithdraw, serializeProof, serializePublicInputs } from '../prover/withdraw.js';
import { encryptNoteForAuditor } from '../viewkey/encrypt.js';
import { getUnspentNotes, markSpent, saveNote } from '../store/notes.js';
import { connectWallet, getNetwork, signAndSubmit } from '../wallet/freighter.js';
import {
    Contract,
    SorobanRpc,
    TransactionBuilder,
    BASE_FEE,
    nativeToScVal,
    xdr,
} from '@stellar/stellar-sdk';

// VERIFY: fill in from deployments/testnet.json before running on testnet
const VEIL_CORE_CONTRACT = import.meta.env.VITE_VEIL_CORE_CONTRACT ?? '';
const TOKEN_CONTRACT     = import.meta.env.VITE_TOKEN_CONTRACT ?? '';
const RPC_URL            = import.meta.env.VITE_RPC_URL ?? 'https://soroban-testnet.stellar.org';

/**
 * Mount the withdraw UI into `containerEl`.
 * @param {HTMLElement} containerEl
 * @param {object} opts  { ownerSk: BigInt, ownerPk: BigInt, merkleTree: object }
 */
export function mountWithdrawUI(containerEl, { ownerSk, ownerPk, merkleTree }) {
    containerEl.innerHTML = `
      <div class="veil-withdraw">
        <h2>Shielded Withdraw</h2>

        <label>Select note to spend
          <select id="wd-note-select">
            <option value="">-- loading notes --</option>
          </select>
        </label>

        <label>Recipient address (Stellar)
          <input id="wd-recipient" type="text" placeholder="G..." />
        </label>

        <label>Amount to withdraw
          <input id="wd-amount" type="number" min="1" placeholder="tokens" />
        </label>

        <div id="wd-status"></div>
        <button id="wd-submit">Generate proof &amp; withdraw</button>
      </div>
    `;

    const noteSelect  = containerEl.querySelector('#wd-note-select');
    const recipientEl = containerEl.querySelector('#wd-recipient');
    const amountEl    = containerEl.querySelector('#wd-amount');
    const statusEl    = containerEl.querySelector('#wd-status');
    const submitBtn   = containerEl.querySelector('#wd-submit');

    // Populate note dropdown
    const notes = getUnspentNotes(ownerPk);
    noteSelect.innerHTML = notes.length
        ? notes.map((n, i) =>
            `<option value="${i}">${BigInt(n.amount)} stroop  [idx ${n.leaf_idx}]</option>`
          ).join('')
        : '<option value="">No unspent notes</option>';

    noteSelect.addEventListener('change', () => {
        const n = notes[Number(noteSelect.value)];
        if (n) amountEl.value = BigInt(n.amount).toString();
    });

    submitBtn.addEventListener('click', async () => {
        submitBtn.disabled = true;
        statusEl.textContent = 'Connecting wallet…';
        try {
            const stellarAddress = await connectWallet();
            const { passphrase } = await getNetwork();

            const noteIdx = Number(noteSelect.value);
            const note = notes[noteIdx];
            if (!note) throw new Error('Select a note first');

            const withdrawAmount = BigInt(amountEl.value);
            if (withdrawAmount <= 0n) throw new Error('Amount must be > 0');
            if (withdrawAmount > BigInt(note.amount)) throw new Error('Amount exceeds note');

            const inputNote = {
                amount:    BigInt(note.amount),
                asset_id:  BigInt(note.asset_id),
                blinding:  BigInt(note.blinding),
                owner_sk:  ownerSk,
                leaf_index: BigInt(note.leaf_idx),
                path:      merkleTree.getMerklePath(note.leaf_idx).pathElements,
                idx:       merkleTree.getMerklePath(note.leaf_idx).pathIndices,
            };

            // Change note if withdraw < note amount
            const changeAmount = BigInt(note.amount) - withdrawAmount;
            const { buildPoseidon } = await import('circomlibjs');
            const poseidon = await buildPoseidon();
            const F = poseidon.F;

            const changeBlinding = BigInt('0x' + [...crypto.getRandomValues(new Uint8Array(31))]
                .map(b => b.toString(16).padStart(2, '0')).join(''));

            const changeNote = changeAmount > 0n ? {
                amount:   changeAmount,
                asset_id: BigInt(note.asset_id),
                blinding: changeBlinding,
                owner_pk: ownerPk,
            } : { amount: 0n, asset_id: 0n, blinding: 0n, owner_pk: 0n };

            // Dummy input1
            const dummyNote = { amount: 0n, asset_id: 0n, blinding: 0n, owner_sk: ownerSk, leaf_index: 0n, path: Array(32).fill(0n), idx: Array(32).fill(0) };

            // recipient_hash = Poseidon(recipient_as_field) — computed off-chain
            // VERIFY: canonical field encoding of Stellar address for Poseidon
            const recipientBytes = Buffer.from(recipientEl.value, 'utf8');
            const recipientField = BigInt('0x' + recipientBytes.toString('hex')) % (2n ** 253n);
            const recipientHash = F.toObject(poseidon([recipientField]));

            const root = BigInt('0x' + merkleTree.root.toString('hex'));
            const assetId = BigInt(note.asset_id);

            statusEl.textContent = 'Generating ZK proof (may take ~15 s)…';
            const { proof, nf_in_0, cm_change } = await proveWithdraw(
                inputNote, dummyNote, changeNote, root, withdrawAmount, assetId, recipientHash,
            );

            // Encrypt change note for auditor (RULE 4) — empty bytes if no change
            let changeCtHex = '';
            if (changeAmount > 0n && cm_change !== 0n) {
                const auditorPkHex = import.meta.env.VITE_AUDITOR_PK ?? '00'.repeat(32);
                const auditorPk = BigInt('0x' + auditorPkHex);
                const encBlinding = BigInt('0x' + [...crypto.getRandomValues(new Uint8Array(31))]
                    .map(b => b.toString(16).padStart(2, '0')).join(''));
                const ctBuf = encryptNoteForAuditor(
                    { amount: changeAmount, asset_id: BigInt(note.asset_id), blinding: changeBlinding, owner_pk: ownerPk },
                    auditorPk, encBlinding,
                );
                changeCtHex = ctBuf.toString('hex');
            }

            statusEl.textContent = 'Submitting transaction…';
            const serialized = serializeProof(proof);
            const publicInputs = serializePublicInputs([
                root.toString(), nf_in_0.toString(), '0',
                cm_change.toString(), withdrawAmount.toString(),
                assetId.toString(), recipientHash.toString(),
            ]);

            // Build Soroban transaction
            // VERIFY: Contract.call() / TransactionBuilder API vs @stellar/stellar-sdk 13.x
            const server = new SorobanRpc.Server(RPC_URL);
            const account = await server.getAccount(stellarAddress);
            const contract = new Contract(VEIL_CORE_CONTRACT);

            const txBuilder = new TransactionBuilder(account, { fee: BASE_FEE, networkPassphrase: passphrase })
                .addOperation(contract.call(
                    'withdraw',
                    nativeToScVal(TOKEN_CONTRACT, { type: 'address' }),
                    nativeToScVal(recipientEl.value, { type: 'address' }),
                    // proof, public, change_ct -- VERIFY: exact XDR encoding for custom contracttype
                    // Serialization via XDR helpers is TBD; see e2e-tests/src/withdraw-and-audit.test.js
                ))
                .setTimeout(30)
                .build();

            const preparedTx = await server.prepareTransaction(txBuilder);
            const signedXdr   = await signAndSubmit(preparedTx.toXDR(), passphrase);
            const result       = await server.sendTransaction(
                TransactionBuilder.fromXDR(signedXdr, passphrase)
            );

            statusEl.textContent = `Submitted: ${result.hash}`;
            markSpent(ownerPk, note.leaf_idx);

            if (changeAmount > 0n) {
                const changeCommitment = cm_change;
                // VERIFY: leaf_idx from the result event; using placeholder 0 until indexer lands
                saveNote(ownerPk, {
                    amount: changeAmount,
                    asset_id: BigInt(note.asset_id),
                    blinding: changeBlinding,
                    owner_pk: ownerPk,
                    leaf_idx: 0,  // VERIFY: read from tx result event
                    commitment: changeCommitment,
                });
            }
        } catch (err) {
            statusEl.textContent = `Error: ${err.message}`;
            console.error(err);
        } finally {
            submitBtn.disabled = false;
        }
    });
}
