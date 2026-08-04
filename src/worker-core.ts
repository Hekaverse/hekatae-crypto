/**
 * WorkerCryptoCore — the key-holding heart of the worker-based isolation path.
 *
 * This class is intentionally free of any Web Worker API usage so it can be
 * unit-tested directly in Node/jsdom. `worker.ts` merely wires an instance of
 * this class to postMessage; `worker-client.ts` is the main-thread counterpart.
 *
 * Security model
 * ──────────────
 * The core HOLDS the User Master Key (UMK) inside the worker realm. The main
 * thread sends operations and receives only results that must leave the
 * enclave: ciphertexts, wrapped keys, and recovery shares. Raw UMK/PDK bytes
 * never cross the boundary in the normal flows:
 *
 *   - setupUserKeys: UMK is generated from raw random bytes, split for Shamir,
 *     and re-imported as a NON-EXTRACTABLE session key. The raw bytes live
 *     only for the duration of the call and are zeroed in a `finally` block.
 *     (Shamir splitting is the one flow that fundamentally needs raw bytes —
 *     the extractable lifetime is minimized to that single operation.)
 *   - unlock ("decryptUMK"): the UMK is unwrapped as a NON-EXTRACTABLE
 *     CryptoKey and held. Nothing key-like is returned — only success.
 *   - encryptBlob / decryptBlob: the per-blob REK is generated, used, and
 *     wrapped entirely inside the worker. Only ciphertext (+ wrapped REK)
 *     leaves on encrypt; only plaintext leaves on decrypt (plaintext must
 *     leave by definition — it is what the user asked to see).
 *   - wrapREK / unwrapREK: compatibility operations for flows where the main
 *     thread already holds a per-item key (e.g. Trust Lattice content keys).
 *     Prefer encryptBlob/decryptBlob, which keep REKs out of the page entirely.
 *   - exportUMK: ESCAPE HATCH for legacy flows that still need the raw UMK
 *     base64 on the main thread (see README "Production hardening"). It
 *     re-derives the PDK from the password, unwraps the UMK extractably for
 *     the duration of that one call, exports, and zeroes. Avoid in new code.
 *
 * All intermediate raw key bytes are kept in Uint8Arrays and scrubbed with
 * zeroize() immediately after use. Base64 is used only where values cross the
 * worker boundary (the existing wire/storage formats demand it). JS strings
 * cannot be reliably zeroed — see zeroize.ts — which is why raw key material
 * is never base64-encoded inside this module except at that boundary.
 */

import { deriveKeyPDK, deriveKeyPBKDF2 } from "./argon2.js";
import {
  generateDataKey,
  importPDK,
  importDataKey,
  wrapKey,
  encryptData,
  decryptData,
  generateSalt,
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./browser-crypto.js";
import { splitSecret } from "./shamir.js";
import { zeroize } from "./zeroize.js";

const AES_GCM: AesKeyAlgorithm = { name: "AES-GCM", length: 256 };
const IV_LENGTH = 12;

/** Result of setupUserKeys. Deliberately has NO umkBase64 field. */
export interface WorkerKeySetupResult {
  encryptedUMK: string; // base64: encPDK(UMK)
  shareA: string; // encrypted with PDK
  shareB: string; // raw share for server
  shareC: string; // raw share for recovery contact
  salt: string; // base64 salt for Argon2id
  sentinel: string; // base64: UMK-wrapped dummy key for share verification
}

export interface WorkerEncryptedBlob {
  ciphertext: ArrayBuffer; // raw bytes, data only (auth tag separate)
  iv: string; // base64
  authTag: string; // base64
  encryptedREK: string; // base64: AES-GCM(REK, UMK)
}

export interface WorkerRecoveryShares {
  shareA: string; // encrypted with PDK
  shareB: string;
  shareC: string;
}

/** Unwrap a key with explicit control over extractability and usages. */
async function unwrapKeyLocal(
  wrappedBase64: string,
  unwrappingKey: CryptoKey,
  extractable: boolean,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  const full = new Uint8Array(base64ToArrayBuffer(wrappedBase64));
  const iv = full.slice(0, IV_LENGTH);
  const wrapped = full.slice(IV_LENGTH);
  return crypto.subtle.unwrapKey(
    "raw",
    wrapped,
    unwrappingKey,
    { name: "AES-GCM", iv },
    AES_GCM,
    extractable,
    usages
  );
}

async function derivePdkKey(
  password: string,
  salt: string,
  userId?: string
): Promise<CryptoKey> {
  const saltInput = userId ? salt + userId : salt;
  let pdkBase64: string;
  try {
    pdkBase64 = await deriveKeyPDK({ pass: password, salt: saltInput });
  } catch {
    pdkBase64 = await deriveKeyPBKDF2(password, saltInput);
  }
  return importPDK(pdkBase64);
}

/** Encrypt a single Shamir share with a key (IV prepended). */
async function encryptShareLocal(
  shareBase64: string,
  key: CryptoKey
): Promise<string> {
  const bytes = new Uint8Array(base64ToArrayBuffer(shareBase64));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  let encrypted: ArrayBuffer;
  try {
    encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  } finally {
    zeroize(bytes);
  }
  const full = new Uint8Array(iv.length + encrypted.byteLength);
  full.set(iv, 0);
  full.set(new Uint8Array(encrypted), iv.length);
  return arrayBufferToBase64(full);
}

export class WorkerCryptoCore {
  /**
   * Session UMK, held as a NON-EXTRACTABLE CryptoKey. It never leaves this
   * object; there is intentionally no getter. Note the key bytes live inside
   * the WebCrypto implementation and cannot be zeroed on destroy() — realm
   * isolation (not extractability) is what protects them from page XSS.
   */
  private umk: CryptoKey | null = null;

  /** Whether the core currently holds an unlocked UMK. */
  hasUMK(): boolean {
    return this.umk !== null;
  }

  /**
   * Generate a fresh UMK, derive the PDK from `password`, and produce all
   * setup artifacts. The UMK is retained (non-extractable) for subsequent
   * operations; only encrypted/wrapped material and shares are returned.
   */
  async setupUserKeys(
    password: string,
    userId?: string
  ): Promise<WorkerKeySetupResult> {
    // Raw UMK bytes. Shamir splitting needs the bytes, so the key exists in
    // extractable form only for the remainder of this call — then the raw
    // buffer is zeroed and the session key is re-imported non-extractable.
    const umkBytes = crypto.getRandomValues(new Uint8Array(32));
    try {
      const salt = generateSalt(32);
      const pdkKey = await derivePdkKey(password, salt, userId);

      const umkExtractable = await crypto.subtle.importKey(
        "raw",
        umkBytes,
        AES_GCM,
        true,
        ["wrapKey", "unwrapKey"]
      );

      // Encrypt UMK with PDK for server-side storage
      const encryptedUMK = await wrapKey(umkExtractable, pdkKey);

      // Sentinel: dummy key wrapped with the UMK, for share integrity checks
      const dummyKey = await generateDataKey();
      const sentinel = await wrapKey(dummyKey, umkExtractable);

      // Split UMK into 3 shares (2-of-3 threshold)
      const [share1, share2, share3] = await splitSecret(umkBytes, 3, 2);

      // Share A: encrypted with PDK (user keeps). B/C returned raw for
      // server-side / recovery-contact encryption respectively.
      const shareA = await encryptShareLocal(share1, pdkKey);

      // Retain the session UMK as NON-EXTRACTABLE.
      this.umk = await crypto.subtle.importKey(
        "raw",
        umkBytes,
        AES_GCM,
        false,
        ["wrapKey", "unwrapKey"]
      );

      return {
        encryptedUMK,
        shareA,
        shareB: share2,
        shareC: share3,
        salt,
        sentinel,
      };
    } finally {
      zeroize(umkBytes);
    }
  }

  /**
   * Worker equivalent of decryptUMK: derive the PDK and unwrap the UMK into
   * the enclave (non-extractable). Resolves to nothing — the UMK itself is
   * NOT returned to the caller. Rejects on wrong password / corrupt input.
   */
  async unlock(
    encryptedUMK: string,
    password: string,
    salt: string,
    userId?: string
  ): Promise<void> {
    const pdkKey = await derivePdkKey(password, salt, userId);
    this.umk = await unwrapKeyLocal(encryptedUMK, pdkKey, false, [
      "wrapKey",
      "unwrapKey",
    ]);
  }

  /** Drop the held UMK. Subsequent key operations will reject until unlock. */
  lock(): void {
    this.umk = null;
  }

  /**
   * Generate a fresh REK, encrypt `plaintext` with it, wrap the REK with the
   * held UMK. Only ciphertext + metadata cross the boundary; the raw REK
   * never does. The worker-side plaintext copy is zeroed after encryption.
   */
  async encryptBlob(
    plaintext: ArrayBuffer,
    aad?: Uint8Array
  ): Promise<WorkerEncryptedBlob> {
    const umk = this.requireUMK();
    const rek = await generateDataKey();

    const plaintextBytes = new Uint8Array(plaintext);
    let encrypted;
    try {
      encrypted = await encryptData(plaintextBytes, rek, aad);
    } finally {
      zeroize(plaintextBytes);
    }

    const encryptedREK = await wrapKey(rek, umk);

    return {
      ciphertext: base64ToArrayBuffer(encrypted.ciphertext),
      iv: encrypted.iv,
      authTag: encrypted.authTag,
      encryptedREK,
    };
  }

  /**
   * Unwrap the REK with the held UMK and decrypt the blob, all inside the
   * worker. Returns the plaintext (which must leave the enclave by
   * definition). Rejects on tampered ciphertext, wrong AAD, or wrong REK.
   */
  async decryptBlob(
    ciphertext: ArrayBuffer,
    iv: string,
    authTag: string,
    encryptedREK: string,
    aad?: Uint8Array
  ): Promise<ArrayBuffer> {
    const umk = this.requireUMK();
    const rek = await unwrapKeyLocal(encryptedREK, umk, false, [
      "encrypt",
      "decrypt",
    ]);
    const plaintext = await decryptData(
      {
        ciphertext: arrayBufferToBase64(ciphertext),
        iv,
        authTag,
      },
      rek,
      aad
    );
    return plaintext.buffer as ArrayBuffer;
  }

  /**
   * Wrap a main-thread-provided REK/content key with the held UMK.
   * Compatibility op for flows where the page legitimately holds a per-item
   * key (e.g. Trust Lattice content keys that must be split client-side).
   */
  async wrapREK(rekBase64: string): Promise<string> {
    const umk = this.requireUMK();
    const rek = await importDataKey(rekBase64);
    return wrapKey(rek, umk);
  }

  /**
   * Unwrap a REK and return it as base64. The raw REK crosses the boundary
   * here — provided for compatibility; prefer decryptBlob in new code so the
   * REK stays inside the worker.
   */
  async unwrapREK(encryptedREK: string): Promise<string> {
    const umk = this.requireUMK();
    const rek = await unwrapKeyLocal(encryptedREK, umk, true, [
      "encrypt",
      "decrypt",
    ]);
    const raw = await crypto.subtle.exportKey("raw", rek);
    try {
      return arrayBufferToBase64(raw);
    } finally {
      zeroize(raw);
    }
  }

  /**
   * Generate fresh 2-of-3 recovery shares for the account's UMK. Because the
   * session UMK is non-extractable, this re-derives the PDK from the password
   * and unwraps `encryptedUMK` extractably for the duration of this call
   * only; the exported bytes are zeroed immediately after splitting.
   */
  async generateRecoveryShares(
    encryptedUMK: string,
    password: string,
    salt: string,
    userId?: string
  ): Promise<WorkerRecoveryShares> {
    const pdkKey = await derivePdkKey(password, salt, userId);
    const umkExtractable = await unwrapKeyLocal(encryptedUMK, pdkKey, true, [
      "wrapKey",
      "unwrapKey",
    ]);
    const raw = await crypto.subtle.exportKey("raw", umkExtractable);
    const umkBytes = new Uint8Array(raw);
    try {
      const [share1, share2, share3] = await splitSecret(umkBytes, 3, 2);
      const shareA = await encryptShareLocal(share1, pdkKey);
      return { shareA, shareB: share2, shareC: share3 };
    } finally {
      zeroize(umkBytes);
    }
  }

  /**
   * ESCAPE HATCH — export the raw UMK as base64 for legacy main-thread flows
   * that cannot yet run inside the worker. Re-derives the PDK from the
   * password (the session UMK is non-extractable by design), exports, and
   * zeroes the raw bytes immediately. Do not use in new code.
   */
  async exportUMK(
    encryptedUMK: string,
    password: string,
    salt: string,
    userId?: string
  ): Promise<string> {
    const pdkKey = await derivePdkKey(password, salt, userId);
    const umkExtractable = await unwrapKeyLocal(encryptedUMK, pdkKey, true, [
      "wrapKey",
      "unwrapKey",
    ]);
    const raw = await crypto.subtle.exportKey("raw", umkExtractable);
    try {
      return arrayBufferToBase64(raw);
    } finally {
      zeroize(raw);
    }
  }

  /** Drop all held key material. */
  destroy(): void {
    this.umk = null;
  }

  private requireUMK(): CryptoKey {
    if (!this.umk) {
      throw new Error("UMK is not unlocked in the worker");
    }
    return this.umk;
  }
}

// ─── Message protocol (shared by worker.ts and worker-client.ts) ───

export type WorkerRequest =
  | { id: number; op: "setupUserKeys"; password: string; userId?: string }
  | {
      id: number;
      op: "unlock";
      encryptedUMK: string;
      password: string;
      salt: string;
      userId?: string;
    }
  | { id: number; op: "lock" }
  | { id: number; op: "hasUMK" }
  | { id: number; op: "wrapREK"; rekBase64: string }
  | { id: number; op: "unwrapREK"; encryptedREK: string }
  | { id: number; op: "encryptBlob"; plaintext: ArrayBuffer; aad?: Uint8Array }
  | {
      id: number;
      op: "decryptBlob";
      ciphertext: ArrayBuffer;
      iv: string;
      authTag: string;
      encryptedREK: string;
      aad?: Uint8Array;
    }
  | {
      id: number;
      op: "generateRecoveryShares";
      encryptedUMK: string;
      password: string;
      salt: string;
      userId?: string;
    }
  | {
      id: number;
      op: "exportUMK";
      encryptedUMK: string;
      password: string;
      salt: string;
      userId?: string;
    }
  | { id: number; op: "destroy" };

export type WorkerResponse =
  | { id: number; ok: true; result: unknown }
  | { id: number; ok: false; error: string };

/**
 * Dispatch one request against the core. Returns the operation result; throws
 * on unknown ops or core errors (the caller converts that to a WorkerResponse).
 */
export async function handleRequest(
  core: WorkerCryptoCore,
  req: WorkerRequest
): Promise<unknown> {
  switch (req.op) {
    case "setupUserKeys":
      return core.setupUserKeys(req.password, req.userId);
    case "unlock":
      return core.unlock(req.encryptedUMK, req.password, req.salt, req.userId);
    case "lock":
      core.lock();
      return undefined;
    case "hasUMK":
      return core.hasUMK();
    case "wrapREK":
      return core.wrapREK(req.rekBase64);
    case "unwrapREK":
      return core.unwrapREK(req.encryptedREK);
    case "encryptBlob":
      return core.encryptBlob(req.plaintext, req.aad);
    case "decryptBlob":
      return core.decryptBlob(
        req.ciphertext,
        req.iv,
        req.authTag,
        req.encryptedREK,
        req.aad
      );
    case "generateRecoveryShares":
      return core.generateRecoveryShares(
        req.encryptedUMK,
        req.password,
        req.salt,
        req.userId
      );
    case "exportUMK":
      return core.exportUMK(req.encryptedUMK, req.password, req.salt, req.userId);
    case "destroy":
      core.destroy();
      return undefined;
    default: {
      const exhaustive: never = req;
      throw new Error(
        `Unknown worker op: ${JSON.stringify((exhaustive as { op?: string })?.op)}`
      );
    }
  }
}
