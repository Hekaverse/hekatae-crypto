/**
 * Per-recording encryption/decryption.
 *
 * Key hierarchy for recordings:
 *   Password → Argon2id → PDK → decrypts UMK
 *   UMK → decrypts REK (per-recording key)
 *   REK → decrypts recording blob (AES-256-GCM)
 *
 * Server stores: ciphertext blob + iv + authTag + encryptedREK
 * Server never sees: UMK, PDK, REK, or plaintext blob
 */

import {
  generateDataKey,
  encryptData,
  wrapKey,
  unwrapKey,
  base64ToArrayBuffer,
} from "./browser-crypto.js";
import { decryptCiphertextBlob } from "./blob-decryption.js";

export interface EncryptedRecording {
  ciphertextBlob: Blob; // The encrypted media blob
  iv: string; // base64
  authTag: string; // base64
  encryptedREK: string; // base64: AES-GCM(REK, UMK)
}

/**
 * Encrypt a media blob for storage.
 * 1. Generate a random REK (Recording Encryption Key)
 * 2. Encrypt the blob with REK via AES-256-GCM
 * 3. Encrypt REK with the user's UMK
 *
 * Returns the ciphertext blob + metadata needed for decryption.
 */
export async function encryptRecording(
  plaintextBlob: Blob,
  umkKey: CryptoKey
): Promise<EncryptedRecording> {
  // 1. Generate per-recording key
  const rek = await generateDataKey();

  // 2. Encrypt blob with REK
  const plaintextArray = new Uint8Array(await plaintextBlob.arrayBuffer());
  const encrypted = await encryptData(plaintextArray, rek);

  // 3. Wrap REK with UMK
  const encryptedREK = await wrapKey(rek, umkKey);

  // 4. Reconstruct the ciphertext blob (data + authTag for storage)
  const cipherBytes = new Uint8Array(
    await Promise.all([
      base64ToArrayBuffer(encrypted.ciphertext),
      base64ToArrayBuffer(encrypted.authTag),
    ]).then(([c, a]) => {
      const combined = new Uint8Array(c.byteLength + a.byteLength);
      combined.set(new Uint8Array(c), 0);
      combined.set(new Uint8Array(a), c.byteLength);
      return combined;
    })
  );

  const ciphertextBlob = new Blob([cipherBytes], {
    type: plaintextBlob.type || "application/octet-stream",
  });

  return {
    ciphertextBlob,
    iv: encrypted.iv,
    authTag: encrypted.authTag,
    encryptedREK,
  };
}

/**
 * Decrypt a recording blob for playback.
 * 1. Decrypt REK with UMK
 * 2. Decrypt blob with REK
 * 3. Return plaintext Blob
 */
export async function decryptRecording(
  ciphertextBlob: Blob,
  iv: string,
  authTag: string,
  encryptedREK: string,
  umkKey: CryptoKey
): Promise<Blob> {
  // 1. Unwrap REK with UMK
  const rek = await unwrapKey(encryptedREK, umkKey);

  // 2. Decrypt blob with REK using shared utility
  return decryptCiphertextBlob(ciphertextBlob, iv, authTag, rek);
}


