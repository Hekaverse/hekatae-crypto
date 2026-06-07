/**
 * Shared Ciphertext Blob Decryption Utilities
 *
 * Both Trust Lattice and legacy encryption use the same ciphertext blob format:
 *   ciphertext (N bytes) || authTag (16 bytes)
 *
 * This module extracts that shared logic so it's not duplicated across
 * RecordingPlayer, TrustLatticePlayer, and MixedMediaItem.
 */

import { decryptData, type EncryptionResult, arrayBufferToBase64 } from "./browser-crypto.js";

/**
 * Extract the auth tag from the end of a concatenated ciphertext blob.
 *
 * The stored blob format is:
 *   [ciphertext bytes...][auth tag (16 bytes)]
 *
 * Returns both the data cipher (without auth tag) and the stored auth tag.
 */
export function extractAuthTagFromBlob(cipherArray: Uint8Array): {
  dataCipher: Uint8Array;
  storedAuthTag: Uint8Array;
} {
  const authTagLength = 16;
  if (cipherArray.length < authTagLength) {
    throw new Error("Ciphertext blob is too short to contain an auth tag");
  }

  const dataCipher = cipherArray.slice(0, cipherArray.length - authTagLength);
  const storedAuthTag = cipherArray.slice(cipherArray.length - authTagLength);

  return { dataCipher, storedAuthTag };
}

/**
 * Verify that the stored auth tag matches the metadata auth tag.
 *
 * Returns true if they match. If they don't match, the blob might be:
 *   - An older format without appended auth tag
 *   - Corrupted
 *   - Tampered
 */
export function verifyAuthTag(
  storedAuthTag: Uint8Array,
  metadataAuthTag: string
): boolean {
  const storedAuthTagB64 = arrayBufferToBase64(storedAuthTag);
  return storedAuthTagB64 === metadataAuthTag;
}

/**
 * Decrypt a Trust Lattice or legacy ciphertext blob.
 *
 * 1. Extract auth tag from the end of the blob
 * 2. Verify it matches the metadata auth tag (if present)
 * 3. Decrypt with the provided key
 *
 * @param ciphertextBlob - The encrypted blob (ciphertext || authTag)
 * @param iv - Base64-encoded IV from metadata
 * @param authTag - Base64-encoded auth tag from metadata
 * @param key - The decryption key (CK for Trust Lattice, REK for legacy)
 * @param blobType - MIME type for the resulting Blob
 */
export async function decryptCiphertextBlob(
  ciphertextBlob: Blob,
  iv: string,
  authTag: string,
  key: CryptoKey,
  blobType?: string
): Promise<Blob> {
  const cipherArray = new Uint8Array(await ciphertextBlob.arrayBuffer());

  const { dataCipher, storedAuthTag } = extractAuthTagFromBlob(cipherArray);

  // Integrity check: the auth tag appended to the blob must match the metadata
  // auth tag. If they differ, the blob is corrupted, tampered with, or stored
  // in an unsupported legacy format (e.g., without appended auth tag).
  if (!verifyAuthTag(storedAuthTag, authTag)) {
    throw new Error(
      "Cryptographic integrity check failed: auth tag mismatch between metadata and payload. " +
        "The recording blob may be corrupted, tampered with, or stored in an unsupported format."
    );
  }

  // Build the EncryptionResult for decryptData
  const encrypted: EncryptionResult = {
    ciphertext: arrayBufferToBase64(dataCipher),
    iv,
    authTag,
  };

  const plaintext = await decryptData(encrypted, key);

  return new Blob([plaintext as unknown as BlobPart], {
    type: blobType || ciphertextBlob.type || "application/octet-stream",
  });
}


