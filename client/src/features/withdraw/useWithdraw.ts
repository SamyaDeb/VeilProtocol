// Withdraw flow — spends one (or two) shielded notes to a public Stellar address.
// Produces a change note if note.amount > withdraw_amount (RULE 4 for change).
// RULE 3 (spent set): input nullifiers go into the spent set.

import { useState, useCallback } from 'react';
import { prove } from '../../lib/prover';
import { addNoteAsync, markSpentByCommitment } from '../../lib/notes';
import { getCurrentRoot } from '../../lib/rpc';
import { buildMerkleTree } from '../../lib/merkle.js';
import { config } from '../../config';
import {
  buildTx,
  submitAndWait,
  proofToScVal,
  toBytesN,
  toBytes,
  toStruct,
  fieldHex,
  type SerializedProof,
} from '../../lib/soroban';
import { Address } from '@stellar/stellar-sdk';
import type { StoredNote } from '../../types';
import { noteLeafIndex } from '../../lib/notes';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const importProver = () => import('../../prover/withdraw.js') as any;

export type WithdrawStep =
  | 'idle'
  | 'building_inputs'
  | 'proving'
  | 'encrypting'
  | 'submitting'
  | 'success'
  | 'error';

export interface WithdrawState {
  step: WithdrawStep;
  error: string | null;
  txHash: string | null;
  changeCommitment: string | null;
}

const INITIAL: WithdrawState = {
  step: 'idle',
  error: null,
  txHash: null,
  changeCommitment: null,
};

export interface WithdrawParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  inputNote: StoredNote;
  ownerSk: bigint;
  treeLeaves: bigint[];
  withdrawAmount: bigint;
  recipientAddress: string;
}

export function useWithdraw() {
  const [state, setState] = useState<WithdrawState>(INITIAL);

  const withdraw = useCallback(async (params: WithdrawParams) => {
    setState({ ...INITIAL, step: 'building_inputs' });
    try {
      const { buildPoseidon } = await import('circomlibjs');
      const poseidon = await buildPoseidon();
      const F = poseidon.F;

      const leafIdx = noteLeafIndex(params.inputNote);
      if (leafIdx == null) throw new Error('Input note has no leaf index — run recovery first');

      if (params.withdrawAmount > BigInt(params.inputNote.amount)) {
        throw new Error('Withdraw amount exceeds note amount');
      }

      const tree = await buildMerkleTree(params.treeLeaves, 32);
      const { pathElements: path, pathIndices: idx } = tree.getProof(leafIdx);
      const rootHex = await getCurrentRoot(params.address);
      const root = BigInt('0x' + rootHex);
      const ownerPk = BigInt(F.toString(poseidon([params.ownerSk])));

      const changeAmount = BigInt(params.inputNote.amount) - params.withdrawAmount;
      const changeBlinding = randomFieldElem();

      // Dummy note for the unused input1 slot (single-input withdraw).
      const dummySk = params.ownerSk;
      const dummyNote = {
        amount: 0n, asset_id: 0n, blinding: 0n,
        owner_sk: dummySk, leaf_index: 0n,
        path: Array(32).fill(0n), idx: Array(32).fill(0),
      };

      const inputNote0 = {
        amount: BigInt(params.inputNote.amount),
        asset_id: BigInt(params.inputNote.asset_id),
        blinding: BigInt(params.inputNote.blinding),
        owner_sk: params.ownerSk,
        leaf_index: BigInt(leafIdx),
        path,
        idx,
      };

      const changeNote = changeAmount > 0n
        ? { amount: changeAmount, asset_id: BigInt(params.inputNote.asset_id), blinding: changeBlinding, owner_pk: ownerPk }
        : { amount: 0n, asset_id: 0n, blinding: 0n, owner_pk: 0n };

      // recipient_hash = Poseidon(recipient_field)
      // VERIFY: canonical field encoding of Stellar G-address (bytes → field element).
      const recipientBytes = Buffer.from(params.recipientAddress, 'utf8');
      const recipientField = BigInt('0x' + recipientBytes.toString('hex')) % (2n ** 253n);
      const recipientHash = BigInt(F.toString(poseidon([recipientField])));

      const assetId = BigInt(params.inputNote.asset_id);

      setState((s) => ({ ...s, step: 'proving' }));
      const { serializeProof } = await importProver();

      const result = await prove('withdraw', {
        input0: inputNote0,
        input1: dummyNote,
        change: changeNote,
        root,
        publicAmount: params.withdrawAmount,
        assetId,
        recipientHash,
      });

      const proof = result.proof as SerializedProof;
      const publicSignals = result.publicSignals as string[];
      const cm_change = result.cm_change as bigint;
      const serialized = serializeProof(proof) as SerializedProof;

      // RULE 4: encrypt change note for auditor (only if change exists).
      setState((s) => ({ ...s, step: 'encrypting' }));
      let auditorCt = Buffer.alloc(0);
      if (changeAmount > 0n && cm_change !== 0n) {
        const { encryptNoteForAuditor } = await import('../../viewkey/encrypt.js');
        const auditorPk = BigInt('0x' + config.auditorPubkey);
        const encBlinding = randomFieldElem();
        auditorCt = Buffer.from(
          await (encryptNoteForAuditor as Function)(changeNote, auditorPk, encBlinding)
        );
      }

      setState((s) => ({ ...s, step: 'submitting' }));

      // Public signals order (CIRCUITS §2 withdraw): root, nf_in_0, nf_in_1, cm_change,
      // public_amount, asset_id, recipient_hash.
      const [rootSig, nf0Sig, nf1Sig, cmChangeSig, pubAmtSig, assetSig, recipSig] = publicSignals;

      const txXdr = await buildTx(params.address, config.contracts.veil_core, 'withdraw', [
        new Address(params.address).toScVal(),
        new Address(config.tokenContract).toScVal(),
        new Address(params.recipientAddress).toScVal(),
        proofToScVal(serialized),
        toStruct({
          asset_id: toBytesN(fieldHex(BigInt(assetSig))),
          cm_change: toBytesN(fieldHex(BigInt(cmChangeSig))),
          nf_in_0: toBytesN(fieldHex(BigInt(nf0Sig))),
          nf_in_1: toBytesN(fieldHex(BigInt(nf1Sig))),
          public_amount: toBytesN(fieldHex(BigInt(pubAmtSig))),
          recipient_hash: toBytesN(fieldHex(BigInt(recipSig))),
          root: toBytesN(fieldHex(BigInt(rootSig))),
        }),
        toBytes(auditorCt.toString('hex')),
      ]);

      const res = await submitAndWait(txXdr, params.signXdr);

      // Mark input note spent (RULE 3).
      markSpentByCommitment(params.inputNote.commitment);

      // Persist change note if any.
      let changeCommitment: string | null = null;
      if (changeAmount > 0n && cm_change !== 0n) {
        changeCommitment = cm_change.toString();
        await addNoteAsync({
          amount: changeAmount.toString(),
          asset_id: params.inputNote.asset_id,
          blinding: changeBlinding.toString(),
          owner_pk: ownerPk.toString(),
          owner_sk: params.ownerSk.toString(),
          commitment: changeCommitment,
          note_type: 'withdraw_change',
        });
      }

      setState({
        step: 'success',
        error: null,
        txHash: 'hash' in res ? (res as { hash: string }).hash : null,
        changeCommitment,
      });
    } catch (e) {
      setState({
        ...INITIAL,
        step: 'error',
        error: e instanceof Error ? e.message : String(e),
      });
    }
  }, []);

  const reset = useCallback(() => setState(INITIAL), []);
  return { state, withdraw, reset };
}

function randomFieldElem(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
}
