/**
 * Argon2id key derivation in the browser via hash-wasm.
 * PDK (Password-Derived Key) is never stored, never leaves the browser.
 */

import { argon2id } from "hash-wasm";
import { arrayBufferToBase64, importPDK } from "./browser-crypto.js";
import { zeroize } from "./zeroize.js";

export interface Argon2Options {
  pass: string;
  salt: string;
  time?: number;
  mem?: number;
  hashLen?: number;
  parallelism?: number;
}

function stringToUint8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Derive a 256-bit key from a password using Argon2id.
 * Returns the raw key as a base64 string.
 *
 * Defaults: time=3, mem=65536 (64MB), parallelism=4, hashLen=32
 */
export async function deriveKeyPDK(options: Argon2Options): Promise<string> {
  const saltBytes = stringToUint8Array(options.salt);
  const hashLen = options.hashLen ?? 32;

  // outputType "binary" returns the raw bytes directly — this avoids the
  // intermediate hex string, which (like all JS strings) cannot be zeroed.
  const bytes = await argon2id({
    password: options.pass,
    salt: saltBytes,
    parallelism: options.parallelism ?? 4,
    memorySize: options.mem ?? 65536,
    iterations: options.time ?? 3,
    hashLength: hashLen,
    outputType: "binary",
  });

  try {
    return arrayBufferToBase64(bytes);
  } finally {
    zeroize(bytes); // raw PDK bytes; the base64 string cannot be zeroed
  }
}

/**
 * Derive a 256-bit key from a password using PBKDF2 as a fallback.
 * Used if Argon2 fails.
 */
export async function deriveKeyPBKDF2(
  password: string,
  salt: string,
  iterations = 600000
): Promise<string> {
  const encoder = new TextEncoder();
  const passBuffer = encoder.encode(password);
  const saltBuffer = encoder.encode(salt);

  try {
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
        salt: saltBuffer,
        iterations,
        hash: "SHA-256",
      },
      keyMaterial,
      256
    );

    try {
      return arrayBufferToBase64(derivedBits);
    } finally {
      zeroize(derivedBits); // raw PDK bytes
    }
  } finally {
    zeroize(passBuffer); // password bytes
  }
}

/** Logger for loud KDF-fallback signalling. Defaults to console.warn. */
export type CryptoLogger = (message: string) => void;

const defaultLogger: CryptoLogger = (message) => console.warn(message);

/**
 * True only when `err` means the Argon2id WASM module itself could not be
 * loaded — never when the hash operation ran and merely failed. hash-wasm
 * throws a fixed message when the WebAssembly global is missing, and
 * WebAssembly.compile/instantiate rejections surface as WebAssembly.*Error.
 * Any other error (bad input, OOM inside the hash, etc.) must NOT trigger a
 * silent algorithm downgrade.
 */
export function isArgon2UnavailableError(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  if (err.message === "WebAssembly is not supported in this environment!") {
    return true;
  }
  const wasm = (globalThis as { WebAssembly?: typeof WebAssembly }).WebAssembly;
  if (wasm) {
    return (
      err instanceof wasm.CompileError ||
      err instanceof wasm.LinkError ||
      err instanceof wasm.RuntimeError
    );
  }
  return false;
}

/**
 * WRAP-time PDK derivation. Falls back to PBKDF2 ONLY when the Argon2id WASM
 * module cannot be loaded (see isArgon2UnavailableError); any other Argon2
 * failure is rethrown. The fallback is logged loudly because the algorithm
 * choice is not recorded in the stored format (yet): an account wrapped with
 * a PBKDF2-derived PDK is unwrapped via the legacy candidate in
 * tryWithPDKCandidates.
 */
export async function derivePDKWithFallback(
  password: string,
  salt: string,
  log: CryptoLogger = defaultLogger
): Promise<string> {
  try {
    return await deriveKeyPDK({ pass: password, salt });
  } catch (err) {
    if (!isArgon2UnavailableError(err)) throw err;
    log(
      "[hekatae-crypto] Argon2id WASM unavailable — falling back to PBKDF2 for PDK derivation. " +
        "Keys wrapped on this device use the legacy KDF and remain unlockable everywhere."
    );
    return deriveKeyPBKDF2(password, salt);
  }
}

/**
 * UNWRAP-time PDK resolution: run `attempt` with the Argon2id-derived PDK
 * first; if that fails, retry with the legacy PBKDF2-derived PDK so accounts
 * wrapped before Argon2id (or during a WASM outage) still unlock. When
 * Argon2id itself is unavailable, only the PBKDF2 candidate is tried.
 * A successful legacy-candidate attempt is logged loudly.
 */
export async function tryWithPDKCandidates<T>(
  password: string,
  salt: string,
  attempt: (pdk: CryptoKey) => Promise<T>,
  log: CryptoLogger = defaultLogger
): Promise<T> {
  let argon2AttemptFailed = false;
  try {
    const pdk = await importPDK(await deriveKeyPDK({ pass: password, salt }));
    try {
      return await attempt(pdk);
    } catch {
      argon2AttemptFailed = true; // fall through to the legacy candidate
    }
  } catch (err) {
    if (!isArgon2UnavailableError(err)) throw err;
    log(
      "[hekatae-crypto] Argon2id WASM unavailable — trying the PBKDF2-derived PDK."
    );
  }

  const legacyPdk = await importPDK(await deriveKeyPBKDF2(password, salt));
  const result = await attempt(legacyPdk);
  if (argon2AttemptFailed) {
    log(
      "[hekatae-crypto] Key material unlocked with the legacy PBKDF2-derived PDK " +
        "(account predates Argon2id or was wrapped during an Argon2 outage)."
    );
  }
  return result;
}
