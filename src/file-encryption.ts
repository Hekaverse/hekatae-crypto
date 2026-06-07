/**
 * File Encryption Helpers
 *
 * App-side AES-256-GCM encryption/decryption for storageVersion=2 recordings.
 * Uses the exact same algorithm as the vault service to ensure compatibility.
 */

import { randomBytes, createCipheriv, createDecipheriv } from "crypto";

export interface FileEncryptionResult {
  ciphertext: Buffer;
  iv: string; // hex
  authTag: string; // hex
}

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12; // NIST SP 800-38D recommended length for AES-GCM

/**
 * Encrypt a file buffer with a 32-byte AES-256 key.
 */
export function encryptFile(plaintext: Buffer, key: Buffer): FileEncryptionResult {
  if (key.length !== 32) {
    throw new Error("Encryption key must be 32 bytes (256 bits)");
  }
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    ciphertext: encrypted,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex"),
  };
}

/**
 * Decrypt a ciphertext buffer with a 32-byte AES-256 key.
 */
export function decryptFile(ciphertext: Buffer, iv: string, authTag: string, key: Buffer): Buffer {
  if (key.length !== 32) {
    throw new Error("Encryption key must be 32 bytes (256 bits)");
  }
  const decipher = createDecipheriv(ALGORITHM, key, Buffer.from(iv, "hex"));
  decipher.setAuthTag(Buffer.from(authTag, "hex"));
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
