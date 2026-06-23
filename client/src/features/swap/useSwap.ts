// Swap flow — submits a shielded order to amm_pool.submit_order.
// RULE 3 (spent set): the nullifier is spent on-chain at submit time.
// Settlement is async: the committee settles later; the app polls for the
// output note by scanning new commitment events after settlement.

import { useState, useCallback } from 'react';
import { prove } from '../../lib/prover';
import { markSpentByCommitment } from '../../lib/notes';
import { getCurrentRoot } from '../../lib/rpc';
import { buildMerkleTree } from '../../lib/merkle.js';
import { config } from '../../config';
import {
  buildTx,
  submitAndWait,
  proofToScVal,
  toBytesN,
  toBytes,
  fieldHex,
  type SerializedProof,
} from '../../lib/soroban';
import { Address } from '@stellar/stellar-sdk';
import type { StoredNote, PendingSwapOrder } from '../../types';
import { noteLeafIndex } from '../../lib/notes';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const importProver = () => import('../../prover/swap.js') as any;

export type SwapStep =
  | 'idle'
  | 'building_inputs'
  | 'proving'
  | 'submitting'
  | 'awaiting_settlement'
  | 'success'
  | 'error';

export interface SwapState {
  step: SwapStep;
  error: string | null;
  txHash: string | null;
  orderId: string | null;
  outputCommitment: string | null;
}

const INITIAL: SwapState = {
  step: 'idle',
  error: null,
  txHash: null,
  orderId: null,
  outputCommitment: null,
};

const PENDING_ORDERS_KEY = 'veil_pending_orders';

export function loadPendingOrders(): PendingSwapOrder[] {
  try {
    return JSON.parse(localStorage.getItem(PENDING_ORDERS_KEY) ?? '[]') as PendingSwapOrder[];
  } catch {
    return [];
  }
}

function savePendingOrder(order: PendingSwapOrder) {
  const orders = loadPendingOrders();
  orders.push(order);
  localStorage.setItem(PENDING_ORDERS_KEY, JSON.stringify(orders));
}

export interface SwapParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  inputNote: StoredNote;
  ownerSk: bigint;
  /** All tree leaves for building the Merkle path (from getLeaves). */
  treeLeaves: bigint[];
  assetOut: bigint;
  minOut: bigint;
  /** Committee BN254 pubkey (field element). From deployments JSON. */
  committeePk: bigint;
}

export function useSwap() {
  const [state, setState] = useState<SwapState>(INITIAL);

  const submitOrder = useCallback(async (params: SwapParams) => {
    setState({ ...INITIAL, step: 'building_inputs' });
    try {
      const { buildPoseidon } = await import('circomlibjs');
      const poseidon = await buildPoseidon();
      const F = poseidon.F;

      const leafIdx = noteLeafIndex(params.inputNote);
      if (leafIdx == null) throw new Error('Input note has no leaf index — run recovery first');

      const tree = await buildMerkleTree(params.treeLeaves, 32);
      const { pathElements: path, pathIndices: idx } = tree.getProof(leafIdx);

      const rootHex = await getCurrentRoot(params.address);
      const root = BigInt('0x' + rootHex);

      const outBlinding = randomFieldElem();
      const ownerPk = BigInt(F.toString(poseidon([params.ownerSk])));
      const rEnc = randomFieldElem();

      const inputNote = {
        amount: BigInt(params.inputNote.amount),
        asset_id: BigInt(params.inputNote.asset_id),
        blinding: BigInt(params.inputNote.blinding),
        owner_sk: params.ownerSk,
        leaf_index: BigInt(leafIdx),
        path,
        idx,
      };
      const intent = {
        asset_out: params.assetOut,
        min_out: params.minOut,
        out_blinding: outBlinding,
        out_owner_pk: ownerPk,
      };

      setState((s) => ({ ...s, step: 'proving' }));

      const { serializeProof } = await importProver();
      const result = await prove('swap', {
        inputNote,
        intent,
        root,
        committeePk: params.committeePk,
        rEnc,
      });

      const proof = result.proof as SerializedProof;
      const publicSignals = result.publicSignals as string[];
      const nf_in = result.nf_in as bigint;
      const enc_order_hash = result.enc_order_hash as bigint;

      const serialized = serializeProof(proof) as SerializedProof;

      // M3: plaintext JSON enc_order (real ElGamal-on-BN254 G1 for M4+).
      // VERIFY: replace with real flow encryption when G1 scalar-mul confirmed (CAP-0074).
      const encOrderBytes = Buffer.from(
        JSON.stringify({
          amount_in: inputNote.amount.toString(),
          asset_out: intent.asset_out.toString(),
          min_out: intent.min_out.toString(),
          out_blinding: intent.out_blinding.toString(),
          out_owner_pk: intent.out_owner_pk.toString(),
          r_enc: rEnc.toString(),
        }),
      );

      const [rootSig] = publicSignals;

      setState((s) => ({ ...s, step: 'submitting' }));

      const txXdr = await buildTx(params.address, config.contracts.amm_pool, 'submit_order', [
        new Address(params.address).toScVal(),
        proofToScVal(serialized),
        toBytes(encOrderBytes),
        toBytesN(fieldHex(nf_in)),
        toBytesN(fieldHex(enc_order_hash)),
        toBytesN(fieldHex(BigInt(rootSig))),
      ]);

      const res = await submitAndWait(txXdr, params.signXdr);

      // Mark the input note as spent locally (RULE 3 — also enforced on-chain).
      markSpentByCommitment(params.inputNote.commitment);

      // Track the pending order for recovery when the committee settles.
      const orderId = `swap-${Date.now()}`;
      savePendingOrder({
        orderId,
        inputNoteCommitment: params.inputNote.commitment,
        intent: {
          asset_out: params.assetOut.toString(),
          min_out: params.minOut.toString(),
          out_blinding: outBlinding.toString(),
          out_owner_pk: ownerPk.toString(),
        },
        status: 'awaiting_settlement',
        submittedAt: Date.now(),
      });

      setState({
        step: 'awaiting_settlement',
        error: null,
        txHash: 'hash' in res ? (res as { hash: string }).hash : null,
        orderId,
        outputCommitment: null,
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
  return { state, submitOrder, reset };
}

function randomFieldElem(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
}
