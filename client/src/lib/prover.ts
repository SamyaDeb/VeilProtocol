// Typed client for the Groth16 proving Web Worker.
//
// Lazy-loads the worker on first use (code-splits snarkjs ~4 MB out of the
// main bundle). Uses a per-request `id` correlator so concurrent prove calls
// from different tabs/components don't cross-wire.

export type CircuitName =
  | 'deposit'
  | 'swap'
  | 'lend'
  | 'withdraw'
  | 'transfer'
  | 'add_liquidity'
  | 'remove_liquidity';

export interface ProveRequest {
  id: string;
  circuit: CircuitName;
  inputs: Record<string, unknown>;
}

export interface ProveResponse {
  id: string;
  ok: boolean;
  result?: Record<string, unknown>;
  error?: string;
}

// Single shared worker instance (re-created only if it crashes).
let _worker: Worker | null = null;

function getWorker(): Worker {
  if (!_worker) {
    _worker = new Worker(
      new URL('../workers/prover.worker.ts', import.meta.url),
      { type: 'module' },
    );
    _worker.onerror = () => {
      _worker = null; // allow re-creation on next call
    };
  }
  return _worker;
}

/**
 * Run a ZK proof in the Web Worker.
 * `inputs` values may contain BigInt (transferred via structured clone).
 */
export function prove(circuit: CircuitName, inputs: Record<string, unknown>): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const id = crypto.randomUUID();
    const worker = getWorker();

    const handler = (e: MessageEvent<ProveResponse>) => {
      if (e.data.id !== id) return;
      worker.removeEventListener('message', handler);
      if (e.data.ok && e.data.result) {
        resolve(e.data.result);
      } else {
        reject(new Error(e.data.error ?? 'Prover worker returned no result'));
      }
    };

    worker.addEventListener('message', handler);
    worker.postMessage({ id, circuit, inputs } satisfies ProveRequest);
  });
}

/** Terminate the shared worker (e.g., on unmount or session end). */
export function terminateWorker(): void {
  _worker?.terminate();
  _worker = null;
}
