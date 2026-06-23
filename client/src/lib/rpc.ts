// Soroban RPC helpers.
//
// Uses the stellar-sdk v16 `rpc` namespace (same as the e2e suites). Read-only
// calls go through simulation; the auditor disclosure is a real signed tx
// because it also writes an on-chain audit-trail event.

import {
  Contract,
  rpc,
  TransactionBuilder,
  BASE_FEE,
  nativeToScVal,
  xdr,
} from '@stellar/stellar-sdk';
import { config } from '../config';
import { simulateCall, toBytesN, toU64 } from './soroban';

export type SignXdr = (xdr: string, networkPassphrase: string) => Promise<string>;

function server(): rpc.Server {
  return new rpc.Server(config.rpcUrl);
}

/** Read the current Merkle root from veil_core via simulation. Returns hex (no 0x). */
export async function getCurrentRoot(sourceAddress: string): Promise<string> {
  const srv = server();
  const account = await srv.getAccount(sourceAddress);
  const contract = new Contract(config.contracts.veil_core);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: config.networkPassphrase,
  })
    .addOperation(contract.call('current_root'))
    .setTimeout(30)
    .build();

  const sim = await srv.simulateTransaction(tx);
  if (!rpc.Api.isSimulationSuccess(sim) || !sim.result) {
    throw new Error('current_root simulation failed');
  }
  return Buffer.from(sim.result.retval.bytes()).toString('hex');
}

/**
 * Fetch the auditor ciphertext stored at commitment index `idx`.
 * Uses a read simulation of `ciphertext_at(idx)` on veil_core.
 * Returns null if nothing is stored at that index.
 */
export async function getCiphertextAt(
  sourceAddress: string,
  idx: bigint,
): Promise<Buffer | null> {
  try {
    const retval = await simulateCall(
      sourceAddress,
      config.contracts.veil_core,
      'ciphertext_at',
      [toU64(idx)],
    );
    if (retval.switch().name === 'scvVoid') return null;
    const bytes = Buffer.from(retval.bytes());
    return bytes.length === 0 ? null : bytes;
  } catch {
    return null;
  }
}

/**
 * Fetch all commitment-insertion events from veil_core using the Soroban RPC
 * event stream. Returns leaves in ascending insertion order.
 *
 * VERIFY: exact topic format against the emitted events in veil_core's
 * insert_commitment function before mainnet — the event key name must match.
 * Current assumption: topic[0] = Symbol("insert_commitment"), topic[1] = leaf bytes.
 */
export interface LeafEvent {
  idx: number;
  commitment: string; // hex, 32 bytes
  auditorCt: string;  // hex, 160 bytes (dev XOR scheme)
  ledger: number;
}

export async function getLeaves(
  _sourceAddress: string,
  fromLedger = 0,
): Promise<LeafEvent[]> {
  const srv = server();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let events: any[] = [];
  try {
    // VERIFY: getEvents filter format against stellar-sdk v16 docs.
    // Topic filter: first element = scvSymbol("insert_commitment").
    const resp = await srv.getEvents({
      startLedger: fromLedger,
      filters: [
        {
          type: 'contract',
          contractIds: [config.contracts.veil_core],
          topics: [
            [
              xdr.ScVal.scvSymbol('insert_commitment').toXDR('base64'),
            ],
          ],
        },
      ],
      limit: 10000,
    });
    events = resp.events ?? [];
  } catch {
    // Indexer offline or no events — return empty; caller degrades gracefully.
    return [];
  }

  return events
    .filter((e) => Array.isArray(e.topic) && e.topic.length >= 2)
    .map((e, i) => {
      // VERIFY: exact ScVal encoding of the event data fields.
      // Assumption: event data = scvMap { leaf: BytesN<32>, idx: u64, auditor_ct: Bytes }
      let commitment = '';
      let auditorCt = '';
      let idx = i;
      try {
        const data = e.value;
        if (data.switch().name === 'scvMap') {
          const map = data.map() ?? [];
          for (const entry of map) {
            const key = entry.key().sym()?.toString();
            if (key === 'leaf') commitment = Buffer.from(entry.val().bytes()).toString('hex');
            if (key === 'auditor_ct') auditorCt = Buffer.from(entry.val().bytes()).toString('hex');
            // XDR Uint64 (long.js) → string → number.
            if (key === 'idx') idx = Number(entry.val().u64()?.toString() ?? i);
          }
        }
      } catch {
        // Malformed event — skip; we'll surface only valid leaves.
      }
      return { idx, commitment, auditorCt, ledger: e.ledger ?? 0 };
    })
    .filter((e) => e.commitment !== '');
}

/** Check whether `root` is a known recent root on veil_core. */
export async function rootIsKnown(sourceAddress: string, root: bigint): Promise<boolean> {
  try {
    const retval = await simulateCall(
      sourceAddress,
      config.contracts.veil_core,
      'root_is_known',
      [toBytesN(root.toString(16))],
    );
    return retval.switch().name === 'scvBool' && (retval.b() ?? false);
  } catch {
    return false;
  }
}

/**
 * Read the oracle price from Reflector for `asset` (SEP-40 format).
 * Returns { price: bigint, decimals: bigint } or null if unavailable.
 *
 * VERIFY: Reflector contract ID comes from deployments/mainnet.json oracle field.
 * Lending contract wraps this; client reads it directly to pass as a public input.
 */
export async function getOraclePrice(
  sourceAddress: string,
  asset: string,
): Promise<{ price: bigint; decimals: bigint } | null> {
  try {
    // VERIFY: exact lending.read_oracle_price argument encoding for the Asset enum.
    // Using lending contract's read_oracle_price(asset) helper.
    const retval = await simulateCall(
      sourceAddress,
      config.contracts.lending,
      'read_oracle_price',
      [xdr.ScVal.scvString(asset)],
    );
    if (retval.switch().name === 'scvVoid') return null;
    const map = retval.map() ?? [];
    let price = 0n;
    let decimals = 7n;
    for (const entry of map) {
      const k = entry.key().sym()?.toString();
      // i128().lo() returns XDR Uint64 (long.js) → use .toString() for BigInt.
      if (k === 'price') { const lo = entry.val().i128()?.lo(); price = lo ? BigInt(lo.toString()) : 0n; }
      if (k === 'decimals') decimals = BigInt(entry.val().u32() ?? 7);
    }
    return { price, decimals };
  } catch {
    return null;
  }
}

/**
 * Request selective disclosure of the ciphertext at `idx`. This is a state-
 * changing call (it logs the disclosure on-chain), so it must be signed.
 * Returns the raw ciphertext bytes, or null if nothing is stored at `idx`.
 */
export async function requestDisclosure(
  auditorAddress: string,
  idx: bigint,
  signXdrFn: SignXdr,
): Promise<Buffer | null> {
  const srv = server();
  const account = await srv.getAccount(auditorAddress);
  const contract = new Contract(config.contracts.veil_core);

  const built = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: config.networkPassphrase,
  })
    .addOperation(
      contract.call(
        'request_disclosure',
        nativeToScVal(auditorAddress, { type: 'address' }),
        nativeToScVal(idx, { type: 'u64' }),
      ),
    )
    .setTimeout(30)
    .build();

  const prepared = await srv.prepareTransaction(built);
  const signedXdr = await signXdrFn(prepared.toXDR(), config.networkPassphrase);
  const sent = await srv.sendTransaction(
    TransactionBuilder.fromXDR(signedXdr, config.networkPassphrase),
  );

  let result: rpc.Api.GetTransactionResponse | null = null;
  for (let i = 0; i < 15; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const status = await srv.getTransaction(sent.hash);
    if (status.status === rpc.Api.GetTransactionStatus.SUCCESS) {
      result = status;
      break;
    }
    if (status.status === rpc.Api.GetTransactionStatus.FAILED) {
      throw new Error('request_disclosure transaction failed');
    }
  }
  if (!result || !('returnValue' in result) || !result.returnValue) {
    throw new Error('Transaction not confirmed within timeout');
  }

  const retval = result.returnValue;
  if (retval.switch().name === 'scvVoid') return null;
  const bytes = Buffer.from(retval.bytes());
  return bytes.length === 0 ? null : bytes;
}
