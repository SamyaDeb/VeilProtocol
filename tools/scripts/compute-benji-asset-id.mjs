/**
 * compute-benji-asset-id.mjs — M7 Phase 4B
 *
 * Computes the Veil Protocol `asset_id` field element for BENJI (and any other
 * Stellar asset) using the canonical formula:
 *
 *   asset_id = Poseidon(issuer_field, code_field)
 *
 * where:
 *   issuer_field = BigInt("0x" + base32-decoded 32-byte Stellar account key)
 *                  (G_BENJI's raw ed25519 public key, stripped of the 1-byte
 *                   version prefix and 2-byte checksum in the strkey encoding)
 *   code_field   = BigInt of the asset code bytes, big-endian, zero-padded to
 *                  4 bytes (for codes ≤ 4 chars) or 12 bytes (for codes ≤ 12 chars)
 *
 * This matches the commitment hasher in circuits/lib/commitment_hasher.circom:
 * `asset_id` is a Poseidon preimage, not an opaque integer.
 *
 * Usage:
 *   node tools/scripts/compute-benji-asset-id.mjs [--issuer <G...>] [--code <BENJI>]
 *
 * Defaults to the BENJI config from deployments/mainnet.json.
 *
 * Output: prints the asset_id as a decimal string (field element) suitable for
 * use as a circuit public/private input and for storage in the note.
 */

import { buildPoseidon } from 'circomlibjs';
import { readFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const ROOT = path.resolve(fileURLToPath(import.meta.url), '../../..');

// ── Argument parsing ──────────────────────────────────────────────────────────
const args = process.argv.slice(2);
let issuerOverride = null, codeOverride = null;
for (let i = 0; i < args.length; i++) {
    if (args[i] === '--issuer') issuerOverride = args[++i];
    if (args[i] === '--code')   codeOverride   = args[++i];
}

// Defaults from mainnet config
const config = JSON.parse(readFileSync(path.join(ROOT, 'deployments/mainnet.json'), 'utf8'));
const issuer = issuerOverride ?? config.assets.BENJI.issuer;
const code   = codeOverride   ?? config.assets.BENJI.code;

if (!issuer) {
    console.error('Error: issuer address not set. Provide --issuer <G...> or fill in deployments/mainnet.json.');
    process.exit(1);
}

// ── Stellar strkey → raw 32-byte pubkey ──────────────────────────────────────
// Stellar strkeys are base32(version_byte || payload || checksum).
// For an account (G...) the version byte is 6<<3 = 0x30, payload is 32 bytes ed25519 pubkey.
// We decode, strip the 1-byte version prefix and 2-byte CRC16 suffix → 32 raw bytes.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Decode(str) {
    let bits = 0n, bitsCount = 0;
    const bytes = [];
    for (const ch of str.toUpperCase()) {
        const val = BASE32_ALPHABET.indexOf(ch);
        if (val < 0) continue; // padding '='
        bits = (bits << 5n) | BigInt(val);
        bitsCount += 5;
        if (bitsCount >= 8) {
            bitsCount -= 8;
            bytes.push(Number((bits >> BigInt(bitsCount)) & 0xffn));
        }
    }
    return Uint8Array.from(bytes);
}

const decoded  = base32Decode(issuer); // version(1) + pubkey(32) + checksum(2) = 35 bytes
if (decoded.length !== 35) {
    console.error(`Error: expected 35 decoded bytes for a Stellar account strkey, got ${decoded.length}`);
    process.exit(1);
}
const rawPubkey = decoded.slice(1, 33); // 32 bytes

// ── Asset code → field element ────────────────────────────────────────────────
// Zero-pad right to 4 bytes if code ≤ 4 chars (credit asset4), else 12 bytes (asset12).
const codeBytes = new TextEncoder().encode(code);
const padLen    = codeBytes.length <= 4 ? 4 : 12;
const codePadded = new Uint8Array(padLen);
codePadded.set(codeBytes.slice(0, padLen));

function bytesToBigInt(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    return n;
}

const issuerField = bytesToBigInt(rawPubkey);
const codeField   = bytesToBigInt(codePadded);

// ── Poseidon(issuer_field, code_field) ───────────────────────────────────────
const poseidon = await buildPoseidon();
const asset_id = BigInt(poseidon.F.toString(poseidon([issuerField, codeField])));

console.log(`Asset:     ${code} / ${issuer}`);
console.log(`issuer_field (decimal): ${issuerField}`);
console.log(`code_field   (decimal): ${codeField}`);
console.log(`\nasset_id = Poseidon(issuer_field, code_field)`);
console.log(`        = ${asset_id}`);
console.log(`\nPaste this value as asset_id in note construction and circuit inputs.`);
