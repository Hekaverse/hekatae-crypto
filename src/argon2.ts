/**
 * Argon2id key derivation in the browser via hash-wasm.
 * PDK (Password-Derived Key) is never stored, never leaves the browser.
 */

import { argon2id } from "hash-wasm";
import { arrayBufferToBase64 } from "./browser-crypto.js";

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

  const hashHex = await argon2id({
    password: options.pass,
    salt: saltBytes,
    parallelism: options.parallelism ?? 4,
    memorySize: options.mem ?? 65536,
    iterations: options.time ?? 3,
    hashLength: hashLen,
    outputType: "hex",
  });

  // Convert hex to base64
  const bytes = new Uint8Array(hashLen);
  for (let i = 0; i < hashLen; i++) {
    bytes[i] = parseInt(hashHex.substring(i * 2, i * 2 + 2), 16);
  }

  return arrayBufferToBase64(bytes);
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

  return arrayBufferToBase64(derivedBits);
}
