/**
 * User Master Key (UMK) generation and management.
 * UMK is a random 256-bit key generated in the browser.
 * It is never stored in plaintext; only encrypted with PDK or split into shares.
 */

import { deriveKeyPDK, deriveKeyPBKDF2 } from "./argon2.js";
import {
  generateKeyBase64,
  generateDataKey,
  importWrappingKey,
  importPDK,
  wrapKey,
  unwrapKey,
  generateSalt,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./browser-crypto.js";
import { splitSecret, combineShares } from "./shamir.js";

export interface KeySetupPayload {
  encryptedMasterKey: string; // base64: encPDK(UMK)
  recoveryShareB: string; // base64: encServerKey(Share B)
  masterKeySalt: string; // base64 salt for Argon2id
}

export interface KeySetupResult {
  umkBase64: string;
  pdkBase64: string;
  encryptedUMK: string;
  shareA: string; // encrypted with PDK
  shareB: string; // raw share for server
  shareC: string; // raw share for recovery contact
  salt: string;
  sentinel: string; // base64: UMK-wrapped dummy key for share integrity verification
}

export interface RecoverySharesResult {
  shareA: string; // encrypted with PDK
  shareB: string; // raw share for server
  shareC: string; // raw share for recovery contact encryption
}

/**
 * Generate a new User Master Key and derive PDK from password.
 * Returns the UMK, PDK, encrypted UMK, and 3 SSS shares.
 */
export async function setupUserKeys(
  password: string,
  userId?: string
): Promise<KeySetupResult> {
  // 1. Generate random UMK (wrapping key)
  const umkBase64 = await generateKeyBase64(["wrapKey", "unwrapKey"]);
  const umkKey = await importWrappingKey(umkBase64);

  // 2. Generate salt
  const salt = generateSalt(32);

  // 3. Derive PDK from password + salt
  let pdkBase64: string;
  try {
    pdkBase64 = await deriveKeyPDK({
      pass: password,
      salt: userId ? salt + userId : salt, // salt + userId as unique per-user salt
    });
  } catch {
    // Fallback to PBKDF2 if Argon2 WASM fails
    pdkBase64 = await deriveKeyPBKDF2(password, userId ? salt + userId : salt);
  }

  const pdkKey = await importPDK(pdkBase64);

  // 4. Encrypt UMK with PDK
  const encryptedUMK = await wrapKey(umkKey, pdkKey);

  // 5. Generate sentinel: a dummy key wrapped with the UMK.
  // During recovery, unwrapping this sentinel verifies that the reconstructed
  // UMK is correct. If shares are corrupted, the unwrap will fail.
  const dummyKey = await generateDataKey();
  const sentinel = await wrapKey(dummyKey, umkKey);

  // 6. Split UMK into 3 shares (2-of-3 threshold)
  const umkBytes = new Uint8Array(base64ToArrayBuffer(umkBase64));
  const [share1, share2, share3] = await splitSecret(umkBytes, 3, 2);

  // 7. Encrypt shares
  // Share A: encrypted with PDK (user keeps this)
  const shareA = await encryptShare(share1, pdkKey);

  // Share B: will be encrypted with server public key (done server-side)
  const shareB = share2;

  // Share C: will be encrypted with recovery contact passphrase (done server-side)
  const shareC = share3;

  return {
    umkBase64,
    pdkBase64,
    encryptedUMK,
    shareA,
    shareB,
    shareC,
    salt,
    sentinel,
  };
}

/**
 * Decrypt UMK using password.
 * Returns the UMK as a base64 string.
 */
export async function decryptUMK(
  encryptedUMK: string,
  password: string,
  salt: string,
  userId?: string
): Promise<string> {
  const saltInput = userId ? salt + userId : salt;
  let pdkBase64: string;
  try {
    pdkBase64 = await deriveKeyPDK({
      pass: password,
      salt: saltInput,
    });
  } catch {
    pdkBase64 = await deriveKeyPBKDF2(password, saltInput);
  }

  const pdkKey = await importPDK(pdkBase64);
  const umkKey = await unwrapKey(encryptedUMK, pdkKey);

  // Export UMK back to base64
  const raw = await crypto.subtle.exportKey("raw", umkKey);
  return arrayBufferToBase64(raw);
}

/**
 * Reconstruct UMK from two shares and optionally verify integrity.
 * Returns the UMK as a base64 string.
 *
 * @param sentinel - Optional UMK-wrapped sentinel. If provided, the
 *   reconstructed UMK must successfully unwrap it. This detects corrupted
 *   or malicious shares that would otherwise produce a silent wrong UMK.
 */
export async function reconstructUMKFromShares(
  shareA: string,
  shareB: string,
  sentinel?: string
): Promise<string> {
  const umkBytes = await combineShares([shareA, shareB]);

  if (sentinel) {
    const umkKey = await importWrappingKey(arrayBufferToBase64(umkBytes));
    try {
      await unwrapKey(sentinel, umkKey, ["encrypt", "decrypt"]);
    } catch {
      throw new Error(
        "Share verification failed: one or more shares are corrupted or invalid."
      );
    }
  }

  return arrayBufferToBase64(umkBytes);
}

/**
 * Generate fresh recovery shares from an existing UMK.
 * Called when adding/updating recovery contacts.
 * Returns new shares (2-of-3 threshold) for the same UMK.
 */
export async function generateRecoveryShares(
  umkBase64: string,
  pdkKey: CryptoKey
): Promise<RecoverySharesResult> {
  // Split UMK into 3 shares (2-of-3 threshold)
  const umkBytes = new Uint8Array(base64ToArrayBuffer(umkBase64));
  const [share1, share2, share3] = await splitSecret(umkBytes, 3, 2);

  // Encrypt Share A with PDK
  const shareA = await encryptShare(share1, pdkKey);

  // Share B and Share C are returned raw for further encryption
  return {
    shareA,
    shareB: share2,
    shareC: share3,
  };
}

/**
 * Encrypt a single share with a key.
 */
async function encryptShare(
  shareBase64: string,
  key: CryptoKey
): Promise<string> {
  const bytes = new Uint8Array(base64ToArrayBuffer(shareBase64));

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    bytes
  );

  const full = new Uint8Array(iv.length + encrypted.byteLength);
  full.set(iv, 0);
  full.set(new Uint8Array(encrypted), iv.length);

  return arrayBufferToBase64(full);
}

/**
 * Decrypt a single share with a key.
 */
export async function decryptShare(
  encryptedShareBase64: string,
  key: CryptoKey
): Promise<string> {
  const full = new Uint8Array(base64ToArrayBuffer(encryptedShareBase64));

  const iv = full.slice(0, 12);
  const ciphertext = full.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    ciphertext
  );

  return arrayBufferToBase64(decrypted);
}
