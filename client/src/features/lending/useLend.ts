// Lending flow — proves LTV range proof and calls lending.open_loan.
// RULE 3 (locked set): collateral nullifier goes into the locked set, not spent.
// RULE 4: borrow note auditor ciphertext is produced and stored on-chain.
// The oracle price is read IMMEDIATELY before proving; the contract re-reads
// on-chain and rejects mismatches (CONTRACTS §4, THREAT_MODEL §5).

import { useState, useCallback } from 'react';
import { prove } from '../../lib/prover';
import { addNoteAsync, markPendingByCommitment } from '../../lib/notes';
import { getCurrentRoot, getOraclePrice } from '../../lib/rpc';
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
import { Address, xdr } from '@stellar/stellar-sdk';
import type { StoredNote } from '../../types';
import { noteLeafIndex } from '../../lib/notes';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const importProver = () => import('../../prover/lend.js') as any;

export type LendStep =
  | 'idle'
  | 'fetching_oracle'
  | 'building_inputs'
  | 'proving'
  | 'encrypting'
  | 'submitting'
  | 'success'
  | 'error';

export interface LendState {
  step: LendStep;
  error: string | null;
  txHash: string | null;
  loanId: string | null;
  borrowCommitment: string | null;
  oraclePrice: bigint | null;
}

const INITIAL: LendState = {
  step: 'idle',
  error: null,
  txHash: null,
  loanId: null,
  borrowCommitment: null,
  oraclePrice: null,
};

export interface LendParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  collatNote: StoredNote;
  ownerSk: bigint;
  treeLeaves: bigint[];
  borrowAmount: bigint;
  borrowAssetId: bigint;
  /** Oracle asset symbol/id string as expected by lending.read_oracle_price. */
  oracleAsset: string;
  /** LTV max in basis points (7500 = 75%). From deployments JSON. */
  ltvMaxBps: bigint;
}

export interface RepayParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  repayNote: StoredNote;
  ownerSk: bigint;
  treeLeaves: bigint[];
  /** Collateral nullifier stored when opening the loan. */
  collatNf: string;
}

export function useLend() {
  const [state, setState] = useState<LendState>(INITIAL);

  const openLoan = useCallback(async (params: LendParams) => {
    setState({ ...INITIAL, step: 'fetching_oracle' });
    try {
      // Step 1: fetch fresh oracle price (CONTRACTS §4 — must match proof public input).
      const priceData = await getOraclePrice(params.address, params.oracleAsset);
      if (!priceData) throw new Error(`Oracle price unavailable for asset: ${params.oracleAsset}`);
      const { price: oraclePrice, decimals: oracleDecimals } = priceData;
      setState((s) => ({ ...s, step: 'building_inputs', oraclePrice }));

      const { buildPoseidon } = await import('circomlibjs');
      const poseidon = await buildPoseidon();
      const F = poseidon.F;

      const leafIdx = noteLeafIndex(params.collatNote);
      if (leafIdx == null) throw new Error('Collateral note has no leaf index — run recovery first');

      const tree = await buildMerkleTree(params.treeLeaves, 32);
      const { pathElements: path, pathIndices: idx } = tree.getProof(leafIdx);
      const rootHex = await getCurrentRoot(params.address);
      const root = BigInt('0x' + rootHex);

      const borrowBlinding = randomFieldElem();
      const ownerPk = BigInt(F.toString(poseidon([params.ownerSk])));

      const collatNote = {
        amount: BigInt(params.collatNote.amount),
        asset_id: BigInt(params.collatNote.asset_id),
        blinding: BigInt(params.collatNote.blinding),
        owner_sk: params.ownerSk,
        leaf_index: BigInt(leafIdx),
        path,
        idx,
      };
      const borrowNote = {
        amount: params.borrowAmount,
        asset_id: params.borrowAssetId,
        blinding: borrowBlinding,
      };

      // Borrow price = oracle price for borrow asset (for now assume same as collat price).
      // VERIFY: use a separate oracle feed for the borrow asset if different.
      const borrowPrice = oraclePrice;

      setState((s) => ({ ...s, step: 'proving' }));

      const { serializeProof } = await importProver();
      const result = await prove('lend', {
        collatNote,
        borrowNote,
        root,
        oraclePrice,
        oracleDecimals,
        ltvMaxBps: params.ltvMaxBps,
        borrowPrice,
      });

      const proof = result.proof as SerializedProof;
      const publicSignals = result.publicSignals as string[];
      const collat_nf = result.collat_nf as bigint;
      const borrow_cm = result.borrow_cm as bigint;

      const serialized = serializeProof(proof) as SerializedProof;

      // RULE 4: encrypt borrow note for auditor.
      setState((s) => ({ ...s, step: 'encrypting' }));
      const { encryptNoteForAuditor } = await import('../../viewkey/encrypt.js');
      const auditorPk = BigInt('0x' + config.auditorPubkey);
      const encBlinding = randomFieldElem();
      const auditorCt = await (encryptNoteForAuditor as Function)(
        { ...borrowNote, owner_pk: ownerPk },
        auditorPk,
        encBlinding,
      );

      // Public signals order (CIRCUITS §4): root, collat_nf, borrow_cm,
      // oracle_price, oracle_decimals, ltv_max_bps, borrow_price.
      // Values used directly from result; publicSignals not needed for contract call.
      void publicSignals;

      setState((s) => ({ ...s, step: 'submitting' }));

      // VERIFY: lending.open_loan arg order against contracts/lending/src/lib.rs
      const txXdr = await buildTx(params.address, config.contracts.lending, 'open_loan', [
        new Address(params.address).toScVal(),
        proofToScVal(serialized),
        toBytesN(fieldHex(collat_nf)),
        toBytesN(fieldHex(borrow_cm)),
        toBytes(Buffer.from(auditorCt).toString('hex')),
        xdr.ScVal.scvString(params.oracleAsset),
        toBytesN(fieldHex(root)),
      ]);

      const res = await submitAndWait(txXdr, params.signXdr);

      // Mark collateral note as pending (locked, not spent).
      markPendingByCommitment(params.collatNote.commitment, true);

      // Persist borrow note.
      await addNoteAsync({
        amount: params.borrowAmount.toString(),
        asset_id: params.borrowAssetId.toString(),
        blinding: borrowBlinding.toString(),
        owner_pk: ownerPk.toString(),
        owner_sk: params.ownerSk.toString(),
        commitment: borrow_cm.toString(),
        note_type: 'borrow',
      });

      setState({
        step: 'success',
        error: null,
        txHash: 'hash' in res ? (res as { hash: string }).hash : null,
        loanId: `loan-${Date.now()}`,
        borrowCommitment: borrow_cm.toString(),
        oraclePrice,
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
  return { state, openLoan, reset };
}

function randomFieldElem(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
}
