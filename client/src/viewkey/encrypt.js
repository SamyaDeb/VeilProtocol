/**
 * Auditor view-key encryption (RULE 4).
 *
 * Every commitment insertion MUST store a note ciphertext encrypted to the
 * auditor's public key. This module provides the canonical encrypt/serialize
 * routine shared by every module.
 *
 * Encryption scheme: ECIES-like using BN254 scalar field arithmetic + AES-256-GCM.
 * For the dev/testnet phase, we use a simpler XOR-with-shared-secret approach
 * that is adequate for functional testing. Production will use proper ECIES.
 *
 * VERIFY: move to proper ECIES before M7 ceremony.
 */

import { buildPoseidon } from 'circomlibjs';

/**
 * Encrypt a note plaintext to the auditor's public key.
 *
 * Dev-mode: Poseidon(auditor_pk, blinding) XOR plaintext.
 * The blinding is prepended to the ciphertext so the auditor can recover the key.
 *
 * @param {{ amount: BigInt, asset_id: BigInt, blinding: BigInt, owner_pk: BigInt }} note
 * @param {BigInt} auditorPk - the auditor's public key (field element)
 * @param {BigInt} encBlinding - random blinding for encryption
 * @returns {Buffer} ciphertext
 */
export async function encryptNoteForAuditor(note, auditorPk, encBlinding) {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Shared secret = Poseidon(auditor_pk, encBlinding)
    const sharedSecret = F.toObject(poseidon([auditorPk, encBlinding]));

    // Plaintext = amount || asset_id || blinding || owner_pk (4 x 32 bytes = 128 bytes)
    const plaintext = Buffer.concat([
        bigintToBe32(note.amount),
        bigintToBe32(note.asset_id),
        bigintToBe32(note.blinding),
        bigintToBe32(note.owner_pk),
    ]);

    // Key stream = Poseidon(sharedSecret, 0) || Poseidon(sharedSecret, 1) || ...
    const keyStream = Buffer.alloc(128);
    for (let i = 0; i < 4; i++) {
        const block = F.toObject(poseidon([sharedSecret, BigInt(i)]));
        const blockBytes = bigintToBe32(block);
        blockBytes.copy(keyStream, i * 32);
    }

    // XOR
    const encrypted = Buffer.alloc(128);
    for (let i = 0; i < 128; i++) {
        encrypted[i] = plaintext[i] ^ keyStream[i];
    }

    // Ciphertext = encBlinding (32 bytes) || encrypted (128 bytes) = 160 bytes
    return Buffer.concat([bigintToBe32(encBlinding), encrypted]);
}

/**
 * Decrypt a note ciphertext with the auditor's secret key.
 *
 * @param {Buffer} ciphertext - 160 bytes (32 blinding + 128 encrypted)
 * @param {BigInt} auditorSk - the auditor's secret key
 * @returns {{ amount: BigInt, asset_id: BigInt, blinding: BigInt, owner_pk: BigInt }}
 */
export async function decryptNoteAsAuditor(ciphertext, auditorSk) {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    // Derive auditor_pk from sk
    const auditorPk = F.toObject(poseidon([auditorSk]));

    // Extract encBlinding from first 32 bytes
    const encBlinding = be32ToBigint(ciphertext.subarray(0, 32));
    const encrypted = ciphertext.subarray(32);

    // Reconstruct shared secret
    const sharedSecret = F.toObject(poseidon([auditorPk, encBlinding]));

    // Reconstruct key stream
    const keyStream = Buffer.alloc(128);
    for (let i = 0; i < 4; i++) {
        const block = F.toObject(poseidon([sharedSecret, BigInt(i)]));
        bigintToBe32(block).copy(keyStream, i * 32);
    }

    // XOR to decrypt
    const plaintext = Buffer.alloc(128);
    for (let i = 0; i < 128; i++) {
        plaintext[i] = encrypted[i] ^ keyStream[i];
    }

    return {
        amount:   be32ToBigint(plaintext.subarray(0, 32)),
        asset_id: be32ToBigint(plaintext.subarray(32, 64)),
        blinding: be32ToBigint(plaintext.subarray(64, 96)),
        owner_pk: be32ToBigint(plaintext.subarray(96, 128)),
    };
}

function bigintToBe32(n) {
    const hex = n.toString(16).padStart(64, '0');
    return Buffer.from(hex, 'hex');
}

function be32ToBigint(buf) {
    return BigInt('0x' + buf.toString('hex'));
}
