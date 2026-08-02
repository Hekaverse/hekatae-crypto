/**
 * WebCrypto API wrapper for AES-256-GCM encryption/decryption in the browser.
 * All operations run client-side. No keys or plaintext leave this module.
 */

const ALGORITHM = "AES-GCM";
const KEY_LENGTH = 256;
const IV_LENGTH = 12; // 96 bits recommended for GCM

/**
 * Convert an ArrayBuffer or Uint8Array to a base64 string.
 * Uses chunked processing to avoid O(n²) string concatenation and
 * call-stack overflow on large buffers (e.g., media recordings).
 */
export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const chunks: string[] = [];
  const chunkSize = 0x8000; // 32k chunks stay well under apply() limits
  for (let i = 0; i < bytes.length; i += chunkSize) {
    chunks.push(
      String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize) as unknown as number[])
    );
  }
  return btoa(chunks.join(""));
}

/**
 * Convert a base64 string to an ArrayBuffer.
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

export interface EncryptionResult {
  ciphertext: string; // base64
  iv: string; // base64
  authTag: string; // base64 (included in ciphertext for GCM, but we separate for clarity)
}

/**
 * Generate a random 256-bit AES key.
 *
 * @param usages - Key usages. Default: ["encrypt", "decrypt"] for data keys.
 *   Use ["wrapKey", "unwrapKey"] for wrapping keys (e.g., UMK).
 *   Use ["encrypt", "wrapKey", "unwrapKey"] for PDK.
 */
export async function generateAESKey(
  usages: KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH },
    true, // extractable
    usages
  );
}

/**
 * Generate a data encryption key (REK, CK).
 * Only encrypt/decrypt — never wraps other keys.
 */
export async function generateDataKey(): Promise<CryptoKey> {
  return generateAESKey(["encrypt", "decrypt"]);
}

/**
 * Generate a wrapping key (UMK).
 * Only wrap/unwrap — never encrypts data directly.
 */
export async function generateWrappingKey(): Promise<CryptoKey> {
  return generateAESKey(["wrapKey", "unwrapKey"]);
}

/**
 * Export a CryptoKey to a base64 string.
 */
export async function exportKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64(raw);
}

/**
 * Import a base64 key string into a CryptoKey.
 *
 * @param base64Key - The base64-encoded raw key bytes.
 * @param extractable - Whether the imported key can be exported. Default false.
 *   Keys that will be wrapped (e.g., UMK, CK) must be extractable.
 * @param usages - Key usages. Default: ["encrypt", "decrypt"].
 */
export async function importKey(
  base64Key: string,
  extractable = false,
  usages: KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  const binary = atob(base64Key);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return crypto.subtle.importKey(
    "raw",
    bytes,
    { name: ALGORITHM },
    extractable,
    usages
  );
}

/**
 * Import a data encryption key (REK, CK).
 */
export async function importDataKey(base64Key: string): Promise<CryptoKey> {
  return importKey(base64Key, true, ["encrypt", "decrypt"]);
}

/**
 * Import a wrapping key (UMK).
 */
export async function importWrappingKey(base64Key: string): Promise<CryptoKey> {
  return importKey(base64Key, true, ["wrapKey", "unwrapKey"]);
}

/**
 * Import a password-derived key (PDK).
 */
export async function importPDK(base64Key: string): Promise<CryptoKey> {
  return importKey(base64Key, false, ["encrypt", "wrapKey", "unwrapKey"]);
}

/**
 * Generate a random 256-bit key as a base64 string.
 *
 * @param usages - Key usages for the generated key.
 */
export async function generateKeyBase64(
  usages: KeyUsage[] = ["encrypt", "decrypt"]
): Promise<string> {
  const key = await generateAESKey(usages);
  return exportKey(key);
}

/**
 * Encrypt data with AES-256-GCM.
 * Returns ciphertext, iv, and authTag as base64 strings.
 *
 * @param additionalData - Optional AAD (Additional Authenticated Data) to bind
 *   the ciphertext to a context (e.g. recording id + contract). Must be supplied
 *   again at decryption time.
 */
export async function encryptData(
  plaintext: Uint8Array,
  key: CryptoKey,
  additionalData?: Uint8Array
): Promise<EncryptionResult> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv, additionalData: additionalData as BufferSource },
    key,
    plaintext as BufferSource
  );

  // For AES-GCM, the auth tag is appended to the ciphertext by WebCrypto.
  // It is the last 16 bytes.
  const fullCipher = new Uint8Array(ciphertextBuffer);
  const authTagLength = 16;
  const dataCipher = fullCipher.slice(0, fullCipher.length - authTagLength);
  const authTag = fullCipher.slice(fullCipher.length - authTagLength);

  return {
    ciphertext: arrayBufferToBase64(dataCipher.buffer),
    iv: arrayBufferToBase64(iv.buffer),
    authTag: arrayBufferToBase64(authTag.buffer),
  };
}

/**
 * Decrypt data with AES-256-GCM.
 *
 * @param additionalData - Optional AAD that was provided during encryption.
 *   Omitting or supplying the wrong AAD will cause decryption to fail.
 */
export async function decryptData(
  result: EncryptionResult,
  key: CryptoKey,
  additionalData?: Uint8Array
): Promise<Uint8Array> {
  const iv = new Uint8Array(base64ToArrayBuffer(result.iv));
  const dataCipher = new Uint8Array(base64ToArrayBuffer(result.ciphertext));
  const authTag = new Uint8Array(base64ToArrayBuffer(result.authTag));

  // Reconstruct the ciphertext + auth tag buffer that WebCrypto expects
  const fullCipher = new Uint8Array(dataCipher.length + authTag.length);
  fullCipher.set(dataCipher, 0);
  fullCipher.set(authTag, dataCipher.length);

  const plaintextBuffer = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv, additionalData: additionalData as BufferSource },
    key,
    fullCipher as BufferSource
  );

  return new Uint8Array(plaintextBuffer);
}

/**
 * Encrypt a string (e.g., text recording) to base64 ciphertext.
 */
export async function encryptString(
  text: string,
  key: CryptoKey,
  additionalData?: Uint8Array
): Promise<EncryptionResult> {
  const encoder = new TextEncoder();
  return encryptData(encoder.encode(text), key, additionalData);
}

/**
 * Decrypt to a string.
 */
export async function decryptToString(
  result: EncryptionResult,
  key: CryptoKey,
  additionalData?: Uint8Array
): Promise<string> {
  const plaintext = await decryptData(result, key, additionalData);
  return new TextDecoder().decode(plaintext);
}

/**
 * Wrap (encrypt) a key with another key.
 * Returns base64 wrapped key.
 */
export async function wrapKey(
  keyToWrap: CryptoKey,
  wrappingKey: CryptoKey
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const wrapped = await crypto.subtle.wrapKey("raw", keyToWrap, wrappingKey, {
    name: ALGORITHM,
    iv,
  });
  // Prepend IV to wrapped key for storage
  const full = new Uint8Array(iv.length + wrapped.byteLength);
  full.set(iv, 0);
  full.set(new Uint8Array(wrapped), iv.length);
  return arrayBufferToBase64(full.buffer);
}

/**
 * Unwrap (decrypt) a key with another key.
 *
 * @param usages - Usages for the unwrapped key. Default ["encrypt", "decrypt"]
 *   for data keys. Use ["wrapKey", "unwrapKey"] when unwrapping a UMK.
 */
export async function unwrapKey(
  wrappedBase64: string,
  unwrappingKey: CryptoKey,
  usages: KeyUsage[] = ["encrypt", "decrypt"]
): Promise<CryptoKey> {
  const full = new Uint8Array(base64ToArrayBuffer(wrappedBase64));
  const iv = full.slice(0, IV_LENGTH);
  const wrapped = full.slice(IV_LENGTH);

  return crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    unwrappingKey,
    { name: ALGORITHM, iv },
    { name: ALGORITHM, length: KEY_LENGTH },
    true,
    usages
  );
}

/**
 * Generate a cryptographically secure random salt.
 */
export function generateSalt(length = 32): string {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return arrayBufferToBase64(bytes.buffer);
}

/**
 * Derive an AES key from a passphrase using PBKDF2.
 * Used for encrypting shares with a user-provided passphrase.
 */
export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const passBuffer = encoder.encode(passphrase);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passBuffer,
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: 600000,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );

  return crypto.subtle.importKey(
    "raw",
    derivedBits,
    { name: ALGORITHM },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Encrypt data with a passphrase-derived key.
 * Returns { ciphertext, iv, salt } where salt is base64.
 */
export async function encryptWithPassphrase(
  data: Uint8Array,
  passphrase: string
): Promise<{ ciphertext: string; iv: string; salt: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKeyFromPassphrase(passphrase, salt);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const encrypted = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv },
    key,
    data as unknown as BufferSource
  );

  return {
    ciphertext: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer),
    salt: arrayBufferToBase64(salt.buffer),
  };
}

/**
 * Decrypt data that was encrypted with a passphrase-derived key.
 */
export async function decryptWithPassphrase(
  ciphertext: string,
  iv: string,
  salt: string,
  passphrase: string
): Promise<Uint8Array> {
  const saltBytes = new Uint8Array(base64ToArrayBuffer(salt));
  const key = await deriveKeyFromPassphrase(passphrase, saltBytes);
  const ivBytes = new Uint8Array(base64ToArrayBuffer(iv));
  const cipherBytes = new Uint8Array(base64ToArrayBuffer(ciphertext));

  const decrypted = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: ivBytes },
    key,
    cipherBytes
  );

  return new Uint8Array(decrypted);
}
