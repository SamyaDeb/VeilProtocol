/**
 * Groth16 proving Web Worker.
 *
 * Runs snarkjs.groth16.fullProve off the main thread so proofs (~10–30 s)
 * do not freeze the UI.
 *
 * Shim: browser prover modules check `typeof window === 'undefined'` to detect
 * Node.js and switch to absolute file paths. Workers also lack `window`, so we
 * set it to globalThis here — BEFORE any dynamic import of prover/*.js — so
 * the provers keep using their browser-relative /circuits/… paths.
 */

// Must run before any prover module is imported.
if (typeof window === 'undefined') {
  (globalThis as unknown as Record<string, unknown>).window = globalThis;
}

import type { ProveRequest, ProveResponse } from '../lib/prover';

self.onmessage = async (e: MessageEvent<ProveRequest>) => {
  const { id, circuit, inputs } = e.data;
  try {
    let result: Record<string, unknown>;

    switch (circuit) {
      case 'deposit': {
        const { proveDeposit } = await import('../prover/deposit.js');
        result = await (proveDeposit as Function)(
          inputs.note,
          inputs.credential,
          inputs.aspProof,
          inputs.publicAmount,
        );
        break;
      }
      case 'swap': {
        const { proveSwap } = await import('../prover/swap.js');
        result = await (proveSwap as Function)(
          inputs.inputNote,
          inputs.intent,
          inputs.root,
          inputs.committeePk,
          inputs.rEnc,
        );
        break;
      }
      case 'lend': {
        const { proveLend } = await import('../prover/lend.js');
        result = await (proveLend as Function)(
          inputs.collatNote,
          inputs.borrowNote,
          inputs.root,
          inputs.oraclePrice,
          inputs.oracleDecimals,
          inputs.ltvMaxBps,
          inputs.borrowPrice,
        );
        break;
      }
      case 'withdraw': {
        const { proveWithdraw } = await import('../prover/withdraw.js');
        result = await (proveWithdraw as Function)(
          inputs.input0,
          inputs.input1,
          inputs.change,
          inputs.root,
          inputs.publicAmount,
          inputs.assetId,
          inputs.recipientHash,
        );
        break;
      }
      case 'transfer': {
        const { proveTransfer } = await import('../prover/transfer.js');
        result = await (proveTransfer as Function)(
          inputs.input0,
          inputs.input1,
          inputs.output0,
          inputs.output1,
          inputs.root,
          inputs.publicAmount,
        );
        break;
      }
      case 'add_liquidity': {
        const { proveAddLiquidity } = await import('../prover/lp.js');
        result = await (proveAddLiquidity as Function)(
          inputs.inputNote0,
          inputs.inputNote1,
          inputs.preReserves,
          inputs.preTotalShares,
          inputs.reserveBlinding,
          inputs.root,
        );
        break;
      }
      case 'remove_liquidity': {
        const { proveRemoveLiquidity } = await import('../prover/lp.js');
        result = await (proveRemoveLiquidity as Function)(
          inputs.lpNote,
          inputs.intent,
          inputs.preReserves,
          inputs.preTotalShares,
          inputs.reserveBlinding,
          inputs.root,
        );
        break;
      }
      default:
        throw new Error(`Unknown circuit: ${circuit}`);
    }

    const response: ProveResponse = { id, ok: true, result };
    self.postMessage(response);
  } catch (err) {
    const response: ProveResponse = {
      id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    };
    self.postMessage(response);
  }
};
