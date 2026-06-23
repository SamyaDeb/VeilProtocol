// XDR encoding helpers for Soroban contract calls.
//
// These match the patterns in e2e-tests/src/*.test.js exactly so contract arg
// encoding is consistent between the React app and the Node test suites.
// Every ScVal helper mirrors the corresponding test helper: toBytesN/toBytesN64/
// toBytesN128/toBytes/toVec/toStruct.

import {
  Contract,
  rpc,
  TransactionBuilder,
  xdr,
  Address,
  BASE_FEE,
} from '@stellar/stellar-sdk';
import { config } from '../config';

// ─── primitive ScVal encoders ─────────────────────────────────────────────────

/** BytesN<32> — a 32-byte field element (big-endian, mod BN254 scalar field). */
export function toBytesN(hex: string): xdr.ScVal {
  return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0').slice(0, 64), 'hex'));
}

/** BytesN<64> — a G1 curve point (2 × 32 bytes). */
export function toBytesN64(hex: string): xdr.ScVal {
  return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(128, '0').slice(0, 128), 'hex'));
}

/** BytesN<128> — a G2 curve point (4 × 32 bytes). */
export function toBytesN128(hex: string): xdr.ScVal {
  return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(256, '0').slice(0, 256), 'hex'));
}

/** Variable-length Bytes. Accepts hex string or Buffer. */
export function toBytes(data: string | Buffer | Uint8Array): xdr.ScVal {
  const buf = typeof data === 'string' ? Buffer.from(data, 'hex') : Buffer.from(data);
  return xdr.ScVal.scvBytes(buf);
}

export function toU32(val: number): xdr.ScVal {
  return xdr.ScVal.scvU32(val);
}

export function toU64(val: bigint): xdr.ScVal {
  return xdr.ScVal.scvU64(xdr.Uint64.fromString(val.toString()));
}

export function toVec(vals: xdr.ScVal[]): xdr.ScVal {
  return xdr.ScVal.scvVec(vals);
}

/** Struct (sorted ScMap). Key order must match the Rust contract's field order. */
export function toStruct(obj: Record<string, xdr.ScVal>): xdr.ScVal {
  const entries = Object.keys(obj)
    .sort()
    .map(
      (key) =>
        new xdr.ScMapEntry({
          key: xdr.ScVal.scvSymbol(key),
          val: obj[key],
        }),
    );
  return xdr.ScVal.scvMap(entries);
}

export function toAddress(addr: string): xdr.ScVal {
  return new Address(addr).toScVal();
}

// ─── proof / public-input encoders ────────────────────────────────────────────

export interface SerializedProof {
  a: string; // hex, 64 bytes (G1)
  b: string; // hex, 128 bytes (G2)
  c: string; // hex, 64 bytes (G1)
}

export function proofToScVal(proof: SerializedProof): xdr.ScVal {
  return toStruct({
    a: toBytesN64(proof.a),
    b: toBytesN128(proof.b),
    c: toBytesN64(proof.c),
  });
}

export function publicInputsToScVal(signals: string[]): xdr.ScVal {
  return toVec(signals.map((s) => toBytesN(BigInt(s).toString(16))));
}

// ─── transaction helpers ──────────────────────────────────────────────────────

export type SignXdr = (xdr: string, passphrase: string) => Promise<string>;

/** Submit a signed Soroban transaction and poll until SUCCESS or FAILED. */
export async function submitAndWait(
  txXdr: string,
  signXdrFn: SignXdr,
): Promise<rpc.Api.GetTransactionResponse> {
  const srv = new rpc.Server(config.rpcUrl);
  const signedXdr = await signXdrFn(txXdr, config.networkPassphrase);
  const sent = await srv.sendTransaction(
    TransactionBuilder.fromXDR(signedXdr, config.networkPassphrase),
  );

  if (sent.status === 'ERROR') {
    // VERIFY: stellar-sdk v16 uses errorResult (XDR object), not errorResultXdr.
    throw new Error(`Submission failed: ${String((sent as unknown as Record<string, unknown>).errorResult ?? 'unknown error')}`);
  }

  for (let i = 0; i < 30; i++) {
    await new Promise((r) => setTimeout(r, 2000));
    const res = await srv.getTransaction(sent.hash);
    if (res.status === rpc.Api.GetTransactionStatus.SUCCESS) return res;
    if (res.status === rpc.Api.GetTransactionStatus.FAILED) {
      throw new Error(`Transaction failed: ${res.status}`);
    }
  }
  throw new Error('Transaction not confirmed within 60 s');
}

/** Build, prepare, and return a transaction XDR ready to sign. */
export async function buildTx(
  address: string,
  contractId: string,
  method: string,
  args: xdr.ScVal[],
): Promise<string> {
  const srv = new rpc.Server(config.rpcUrl);
  const account = await srv.getAccount(address);
  const contract = new Contract(contractId);

  const tx = new TransactionBuilder(account, {
    fee: '1000000',
    networkPassphrase: config.networkPassphrase,
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(30)
    .build();

  const prepared = await srv.prepareTransaction(tx);
  return prepared.toXDR();
}

/** Read-only: simulate a contract call and return the raw return value. */
export async function simulateCall(
  address: string,
  contractId: string,
  method: string,
  args: xdr.ScVal[] = [],
): Promise<xdr.ScVal> {
  const srv = new rpc.Server(config.rpcUrl);
  const account = await srv.getAccount(address);
  const contract = new Contract(contractId);

  const tx = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: config.networkPassphrase,
  })
    .addOperation(contract.call(method, ...args))
    .setTimeout(30)
    .build();

  const sim = await srv.simulateTransaction(tx);
  if (!rpc.Api.isSimulationSuccess(sim) || !sim.result) {
    throw new Error(`Simulation of ${method} failed`);
  }
  return sim.result.retval;
}

/** Bigint field element → 64-char hex (no 0x). */
export function fieldHex(n: bigint): string {
  return n.toString(16).padStart(64, '0');
}
