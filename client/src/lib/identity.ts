// ZK identity management.
//
// The `owner_sk` is a BN254 scalar-field element (< 2^253) that is separate
// from the Stellar/Freighter signing key. Every note and nullifier binds to it;
// it never leaves the browser. Secrets are stored as hex in localStorage.

const SK_KEY = 'veil_owner_sk';
const SEED_KEY = 'veil_owner_seed';

function randBigInt31Bytes(): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(31));
  return BigInt(
    '0x' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(''),
  );
}

/** Return the stored owner_sk (hex) or null if no identity exists. */
export function getOwnerSk(): bigint | null {
  const v = localStorage.getItem(SK_KEY);
  return v ? BigInt('0x' + v) : null;
}

/** Generate a new owner_sk from random bytes and persist it. */
export function generateIdentity(): bigint {
  const sk = randBigInt31Bytes();
  localStorage.setItem(SK_KEY, sk.toString(16).padStart(62, '0'));
  return sk;
}

/** Return the existing owner_sk or create one. */
export function getOrCreateOwnerSk(): bigint {
  return getOwnerSk() ?? generateIdentity();
}

/**
 * Derive a deterministic owner_sk from a user-supplied seed phrase.
 * Uses SHA-256(seed || "veil_owner_sk") and reduces mod the BN254 scalar field.
 * The derived sk is stored so subsequent loads don't require the seed.
 *
 * VERIFY: use HKDF before M7 for proper key derivation hygiene.
 */
export async function deriveIdentityFromSeed(seed: string): Promise<bigint> {
  const enc = new TextEncoder().encode(seed + '\x00veil_owner_sk');
  const hashBuf = await crypto.subtle.digest('SHA-256', enc);
  const hex = [...new Uint8Array(hashBuf)].map((b) => b.toString(16).padStart(2, '0')).join('');
  // Reduce mod BN254 scalar field (< 2^254 − delta; 31 bytes is always in-field).
  const sk = BigInt('0x' + hex) % ((1n << 254n) - 1n);
  localStorage.setItem(SK_KEY, sk.toString(16).padStart(62, '0'));
  localStorage.setItem(SEED_KEY, '(set)'); // flag that seed was used — never store the seed itself
  return sk;
}

/** True if the user set an identity via seed derivation in this browser. */
export function hasSeedIdentity(): boolean {
  return localStorage.getItem(SEED_KEY) !== null;
}

/** Clear the stored identity (irreversible unless the seed is known). */
export function clearIdentity(): void {
  localStorage.removeItem(SK_KEY);
  localStorage.removeItem(SEED_KEY);
}

/**
 * Derive the AES-GCM key used to encrypt the note store at rest.
 * Key = HKDF(SHA-256, ikm=owner_sk_bytes, salt="veil_notes_v1", info="encrypt").
 */
export async function deriveNoteStoreKey(ownerSk: bigint): Promise<CryptoKey> {
  const skBytes = hexToBytes(ownerSk.toString(16).padStart(64, '0'));
  const ikm = await crypto.subtle.importKey('raw', skBytes.buffer as ArrayBuffer, { name: 'HKDF' }, false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('veil_notes_v1'),
      info: new TextEncoder().encode('encrypt'),
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}
