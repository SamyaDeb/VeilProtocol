// Liquidity provision — shielded add/remove LP (RULE 2 — universal notes).
// A swap-output note, a deposit note, or any note works as LP input (no conversion).
// LP position size is hidden; fee accrual is provable to the LP locally.

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
  fieldHex,
  type SerializedProof,
} from '../../lib/soroban';
import { Address } from '@stellar/stellar-sdk';
import type { StoredNote } from '../../types';
import { noteLeafIndex } from '../../lib/notes';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const importProver = () => import('../../prover/lp.js') as any;

export type LiquidityStep =
  | 'idle'
  | 'building_inputs'
  | 'proving'
  | 'encrypting'
  | 'submitting'
  | 'success'
  | 'error';

export interface LiquidityState {
  step: LiquidityStep;
  error: string | null;
  txHash: string | null;
  lpCommitment: string | null;
  feeInfo: { fee0: bigint; fee1: bigint } | null;
}

const INITIAL: LiquidityState = {
  step: 'idle',
  error: null,
  txHash: null,
  lpCommitment: null,
  feeInfo: null,
};

export interface AddLiquidityParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  note0: StoredNote;
  note1: StoredNote;
  ownerSk: bigint;
  treeLeaves: bigint[];
  /** Current on-chain reserve amounts [reserve0, reserve1]. */
  preReserves: [bigint, bigint];
  /** Current on-chain total LP shares. */
  preTotalShares: bigint;
  /** Reserve commitment blinding (from AMM pool encrypted_reserves). */
  reserveBlinding: bigint;
}

export interface RemoveLiquidityParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  lpNote: StoredNote;
  ownerSk: bigint;
  treeLeaves: bigint[];
  preReserves: [bigint, bigint];
  preTotalShares: bigint;
  reserveBlinding: bigint;
  /** Asset IDs for the two output notes. */
  asset0: bigint;
  asset1: bigint;
}

export function useLiquidity() {
  const [state, setState] = useState<LiquidityState>(INITIAL);

  const addLiquidity = useCallback(async (params: AddLiquidityParams) => {
    setState({ ...INITIAL, step: 'building_inputs' });
    try {
      const { buildPoseidon } = await import('circomlibjs');
      const poseidon = await buildPoseidon();
      const F = poseidon.F;

      const idx0 = noteLeafIndex(params.note0);
      const idx1 = noteLeafIndex(params.note1);
      if (idx0 == null || idx1 == null) {
        throw new Error('Both LP input notes need leaf indices — run recovery first');
      }

      const tree = await buildMerkleTree(params.treeLeaves, 32);
      const path0 = tree.getProof(idx0);
      const path1 = tree.getProof(idx1);
      const rootHex = await getCurrentRoot(params.address);
      const root = BigInt('0x' + rootHex);
      const ownerSk0 = params.ownerSk;
      const ownerSk1 = params.ownerSk; // same identity

      const inputNote0 = {
        amount: BigInt(params.note0.amount),
        asset_id: BigInt(params.note0.asset_id),
        blinding: BigInt(params.note0.blinding),
        owner_sk: ownerSk0,
        leaf_index: BigInt(idx0),
        path: path0.pathElements,
        idx: path0.pathIndices,
      };
      const inputNote1 = {
        amount: BigInt(params.note1.amount),
        asset_id: BigInt(params.note1.asset_id),
        blinding: BigInt(params.note1.blinding),
        owner_sk: ownerSk1,
        leaf_index: BigInt(idx1),
        path: path1.pathElements,
        idx: path1.pathIndices,
      };

      setState((s) => ({ ...s, step: 'proving' }));
      const { serializeProof } = await importProver();
      const result = await prove('add_liquidity', {
        inputNote0,
        inputNote1,
        preReserves: params.preReserves,
        preTotalShares: params.preTotalShares,
        reserveBlinding: params.reserveBlinding,
        root,
      });

      const proof = result.proof as SerializedProof;
      const lp_commit = result.lp_commit as bigint;
      const nf_in_0 = result.nf_in_0 as bigint;
      const nf_in_1 = result.nf_in_1 as bigint;
      const serialized = serializeProof(proof) as SerializedProof;

      // RULE 4: encrypt LP commitment for auditor.
      setState((s) => ({ ...s, step: 'encrypting' }));
      const { encryptNoteForAuditor } = await import('../../viewkey/encrypt.js');
      const auditorPk = BigInt('0x' + config.auditorPubkey);
      const encBlinding = randomFieldElem();
      const ownerPk = BigInt(F.toString(poseidon([params.ownerSk])));
      const lpNoteForAudit = {
        amount: inputNote0.amount, // LP shares — shares amount
        asset_id: 99999n,          // LP_ASSET sentinel
        blinding: BigInt(params.note0.blinding),
        owner_pk: ownerPk,
      };
      const auditorCt = await (encryptNoteForAuditor as Function)(lpNoteForAudit, auditorPk, encBlinding);

      setState((s) => ({ ...s, step: 'submitting' }));

      const txXdr = await buildTx(params.address, config.contracts.amm_pool, 'add_liquidity', [
        new Address(params.address).toScVal(),
        proofToScVal(serialized),
        toBytesN(fieldHex(nf_in_0)),
        toBytesN(fieldHex(nf_in_1)),
        toBytesN(fieldHex(lp_commit)),
        toBytes(Buffer.from(auditorCt).toString('hex')),
      ]);

      const res = await submitAndWait(txXdr, params.signXdr);

      markSpentByCommitment(params.note0.commitment);
      markSpentByCommitment(params.note1.commitment);

      const lpCommitStr = lp_commit.toString();
      // Persist LP note with deposit-time reserve info for fee display.
      await addNoteAsync({
        amount: inputNote0.amount.toString(), // shares
        asset_id: '99999',                   // LP_ASSET
        blinding: params.note0.blinding,
        owner_pk: ownerPk.toString(),
        owner_sk: params.ownerSk.toString(),
        commitment: lpCommitStr,
        note_type: 'lp',
        deposit_value_0: inputNote0.amount.toString(),
        deposit_value_1: inputNote1.amount.toString(),
      });

      setState({
        step: 'success',
        error: null,
        txHash: 'hash' in res ? (res as { hash: string }).hash : null,
        lpCommitment: lpCommitStr,
        feeInfo: null,
      });
    } catch (e) {
      setState({ ...INITIAL, step: 'error', error: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  const removeLiquidity = useCallback(async (params: RemoveLiquidityParams) => {
    setState({ ...INITIAL, step: 'building_inputs' });
    try {
      const { buildPoseidon } = await import('circomlibjs');
      const poseidon = await buildPoseidon();
      const F = poseidon.F;

      const lpIdx = noteLeafIndex(params.lpNote);
      if (lpIdx == null) throw new Error('LP note has no leaf index — run recovery first');

      const tree = await buildMerkleTree(params.treeLeaves, 32);
      const lpPath = tree.getProof(lpIdx);
      const rootHex = await getCurrentRoot(params.address);
      const root = BigInt('0x' + rootHex);
      const ownerPk = BigInt(F.toString(poseidon([params.ownerSk])));

      const outBlinding0 = randomFieldElem();
      const outBlinding1 = randomFieldElem();

      const lpNoteForProver = {
        amount: BigInt(params.lpNote.amount),
        asset_id: BigInt(params.lpNote.asset_id),
        blinding: BigInt(params.lpNote.blinding),
        owner_sk: params.ownerSk,
        leaf_index: BigInt(lpIdx),
        path: lpPath.pathElements,
        idx: lpPath.pathIndices,
      };
      const intent = {
        asset_0: params.asset0,
        asset_1: params.asset1,
        out_blinding_0: outBlinding0,
        out_blinding_1: outBlinding1,
        out_owner_sk_0: params.ownerSk,
        out_owner_sk_1: params.ownerSk,
      };

      setState((s) => ({ ...s, step: 'proving' }));
      const { serializeProof } = await importProver();
      const result = await prove('remove_liquidity', {
        lpNote: lpNoteForProver,
        intent,
        preReserves: params.preReserves,
        preTotalShares: params.preTotalShares,
        reserveBlinding: params.reserveBlinding,
        root,
      });

      const proof = result.proof as SerializedProof;
      const lp_nf = result.lp_nf as bigint;
      const cm_out_0 = result.cm_out_0 as bigint;
      const cm_out_1 = result.cm_out_1 as bigint;
      const serialized = serializeProof(proof) as SerializedProof;

      // Compute amounts for display.
      const shares = BigInt(params.lpNote.amount);
      const amount_out_0 = (shares * params.preReserves[0]) / params.preTotalShares;
      const amount_out_1 = (shares * params.preReserves[1]) / params.preTotalShares;

      // Fee = current value – deposit_value (stored at LP creation).
      const depositVal0 = BigInt(params.lpNote.deposit_value_0 ?? '0');
      const depositVal1 = BigInt(params.lpNote.deposit_value_1 ?? '0');

      setState((s) => ({ ...s, step: 'submitting' }));

      const txXdr = await buildTx(params.address, config.contracts.amm_pool, 'remove_liquidity', [
        new Address(params.address).toScVal(),
        proofToScVal(serialized),
        toBytesN(fieldHex(lp_nf)),
      ]);

      const res = await submitAndWait(txXdr, params.signXdr);

      markSpentByCommitment(params.lpNote.commitment);

      // Persist output notes.
      await addNoteAsync({
        amount: amount_out_0.toString(),
        asset_id: params.asset0.toString(),
        blinding: outBlinding0.toString(),
        owner_pk: ownerPk.toString(),
        owner_sk: params.ownerSk.toString(),
        commitment: cm_out_0.toString(),
        note_type: 'lp_out',
      });
      await addNoteAsync({
        amount: amount_out_1.toString(),
        asset_id: params.asset1.toString(),
        blinding: outBlinding1.toString(),
        owner_pk: ownerPk.toString(),
        owner_sk: params.ownerSk.toString(),
        commitment: cm_out_1.toString(),
        note_type: 'lp_out',
      });

      setState({
        step: 'success',
        error: null,
        txHash: 'hash' in res ? (res as { hash: string }).hash : null,
        lpCommitment: null,
        feeInfo: {
          fee0: amount_out_0 > depositVal0 ? amount_out_0 - depositVal0 : 0n,
          fee1: amount_out_1 > depositVal1 ? amount_out_1 - depositVal1 : 0n,
        },
      });
    } catch (e) {
      setState({ ...INITIAL, step: 'error', error: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  const reset = useCallback(() => setState(INITIAL), []);
  return { state, addLiquidity, removeLiquidity, reset };
}

function randomFieldElem(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
}
