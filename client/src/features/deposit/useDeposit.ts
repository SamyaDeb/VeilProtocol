// Deposit flow — proves KYC + ASP membership/non-membership and calls
// veil_core.deposit. Enforces RULE 1 (ASP gate) and RULE 4 (auditor ciphertext).

import { useState, useCallback } from 'react';
import { prove } from '../../lib/prover';
import { addNoteAsync } from '../../lib/notes';
import { buildMerkleTree, buildNonMembershipProof } from '../../lib/merkle.js';
import { config } from '../../config';
import {
  buildTx,
  submitAndWait,
  proofToScVal,
  toBytesN,
  toBytes,
  toVec,
  toStruct,
  fieldHex,
  type SerializedProof,
} from '../../lib/soroban';
import { Address } from '@stellar/stellar-sdk';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const importProver = () => import('../../prover/deposit.js') as any;

export type DepositStep =
  | 'idle'
  | 'building_inputs'
  | 'proving'
  | 'encrypting'
  | 'submitting'
  | 'success'
  | 'error';

export interface DepositState {
  step: DepositStep;
  error: string | null;
  txHash: string | null;
  commitment: string | null;
  leafIdx: number | null;
}

const INITIAL: DepositState = {
  step: 'idle',
  error: null,
  txHash: null,
  commitment: null,
  leafIdx: null,
};

export interface DepositParams {
  address: string;
  signXdr: (xdr: string, passphrase: string) => Promise<string>;
  ownerSk: bigint;
  ownerPk: bigint;
  amount: bigint;
  assetId: bigint;
  /** Credential secret for ASP membership check. */
  credSecret: bigint;
  /** Issuer public key (field element). */
  issuerPk: bigint;
  /**
   * Pre-built ASP approved-set MerkleTree containing the credential leaf.
   * In production this comes from the ASP operator's published tree.
   */
  approvedTreeLeaves: bigint[];
  /**
   * Pre-built ASP blocked-set MerkleTree (sorted leaves).
   */
  blockedTreeLeaves: bigint[];
}

export function useDeposit() {
  const [state, setState] = useState<DepositState>(INITIAL);

  const deposit = useCallback(async (params: DepositParams) => {
    setState({ ...INITIAL, step: 'building_inputs' });

    try {
      const { buildPoseidon } = await import('circomlibjs');
      const poseidon = await buildPoseidon();
      const F = poseidon.F;

      const blinding = randomFieldElem();
      const note = {
        amount: params.amount,
        asset_id: params.assetId,
        blinding,
        owner_pk: params.ownerPk,
      };

      // Derive commitment and credential leaf.
      const cm = BigInt(
        F.toString(poseidon([note.amount, note.asset_id, note.blinding, note.owner_pk])),
      );
      const credLeafHash = poseidon([params.credSecret, params.issuerPk]);
      const credLeaf = BigInt(F.toString(credLeafHash));

      // Build ASP trees (depth 20 per CIRCUITS §1).
      const approvedTree = await buildMerkleTree(params.approvedTreeLeaves, 20);
      const blockedTree = await buildMerkleTree(params.blockedTreeLeaves, 20);

      const credIdx = approvedTree.tree[0].indexOf(credLeaf);
      if (credIdx === -1) throw new Error('Credential not found in approved tree');
      const { pathElements: asp_path, pathIndices: asp_idx } = approvedTree.getProof(credIdx);
      const nmProof = buildNonMembershipProof(blockedTree, credLeaf);

      const aspProof = {
        asp_path,
        asp_idx,
        asp_approved_root: approvedTree.root,
        asp_blocked_root: blockedTree.root,
        blocked_lower_leaf: nmProof.lower_leaf,
        blocked_upper_leaf: nmProof.upper_leaf,
        blocked_lower_path: nmProof.lower_path,
        blocked_lower_idx: nmProof.lower_idx,
        blocked_upper_path: nmProof.upper_path,
        blocked_upper_idx: nmProof.upper_idx,
      };

      setState((s) => ({ ...s, step: 'proving' }));

      const { serializeProof } = await importProver();

      const result = await prove('deposit', {
        note,
        credential: { cred_secret: params.credSecret, issuer_pk: params.issuerPk },
        aspProof,
        publicAmount: params.amount,
      });

      // RULE 4: encrypt output note for auditor.
      setState((s) => ({ ...s, step: 'encrypting' }));
      const { encryptNoteForAuditor } = await import('../../viewkey/encrypt.js');
      const auditorPk = BigInt('0x' + config.auditorPubkey);
      const encBlinding = randomFieldElem();
      const auditorCt = await (encryptNoteForAuditor as Function)(note, auditorPk, encBlinding);

      // Build Soroban call args mirroring e2e-tests/src/deposit.test.js exactly.
      // Arg order: caller, token, asp, proof, public, asp_proof_struct, auditor_ct
      const proof = result.proof as ReturnType<typeof serializeProof>;
      const publicSignals = result.publicSignals as string[];
      const serialized = serializeProof(proof) as SerializedProof;
      const [cmSig, pubAmtSig, approvedRootSig, blockedRootSig] = publicSignals;

      const proofArg = proofToScVal(serialized);

      const publicArg = toStruct({
        asp_approved_root: toBytesN(fieldHex(BigInt(approvedRootSig))),
        asp_blocked_root: toBytesN(fieldHex(BigInt(blockedRootSig))),
        cm: toBytesN(fieldHex(BigInt(cmSig))),
        public_amount: toBytesN(fieldHex(BigInt(pubAmtSig))),
      });

      const aspProofArg = toStruct({
        approved_idx: toVec(asp_idx.map((i) => toBytesN(BigInt(i).toString(16)))),
        approved_path: toVec(asp_path.map((p) => toBytesN(p.toString(16)))),
        approved_root: toBytesN(approvedTree.root.toString(16)),
        blocked_lower_idx: toVec(nmProof.lower_idx.map((i) => toBytesN(BigInt(i).toString(16)))),
        blocked_lower_leaf: toBytesN(nmProof.lower_leaf.toString(16)),
        blocked_lower_path: toVec(nmProof.lower_path.map((p) => toBytesN(p.toString(16)))),
        blocked_root: toBytesN(blockedTree.root.toString(16)),
        blocked_upper_idx: toVec(nmProof.upper_idx.map((i) => toBytesN(BigInt(i).toString(16)))),
        blocked_upper_leaf: toBytesN(nmProof.upper_leaf.toString(16)),
        blocked_upper_path: toVec(nmProof.upper_path.map((p) => toBytesN(p.toString(16)))),
        credential_leaf: toBytesN(credLeaf.toString(16)),
      });

      setState((s) => ({ ...s, step: 'submitting' }));

      const txXdr = await buildTx(params.address, config.contracts.veil_core, 'deposit', [
        new Address(params.address).toScVal(),
        new Address(config.tokenContract).toScVal(),
        new Address(config.contracts.asp).toScVal(),
        proofArg,
        publicArg,
        aspProofArg,
        toBytes(Buffer.from(auditorCt).toString('hex')),
      ]);

      const res = await submitAndWait(txXdr, params.signXdr);

      // Extract leaf index from return value (u64).
      let leafIdx: number | null = null;
      if ('returnValue' in res && res.returnValue) {
        try {
          leafIdx = Number(res.returnValue.u64()?.toBigInt() ?? null);
        } catch {
          leafIdx = null;
        }
      }

      // Persist the note.
      await addNoteAsync({
        amount: params.amount.toString(),
        asset_id: params.assetId.toString(),
        blinding: blinding.toString(),
        owner_pk: params.ownerPk.toString(),
        owner_sk: params.ownerSk.toString(),
        commitment: cm.toString(),
        leaf_idx: leafIdx ?? undefined,
        note_type: 'deposit',
      });

      setState({
        step: 'success',
        error: null,
        txHash: 'hash' in res ? (res as { hash: string }).hash : null,
        commitment: cm.toString(),
        leafIdx,
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
  return { state, deposit, reset };
}

function randomFieldElem(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt('0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''));
}
