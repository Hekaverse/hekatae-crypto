/**
 * Shamir's Secret Sharing wrapper for threshold cryptography.
 * Splits a secret into n shares where k shares are needed to reconstruct.
 */

import { split, combine } from "shamir-secret-sharing";
import { arrayBufferToBase64, base64ToArrayBuffer } from "./browser-crypto.js";
import { zeroize } from "./zeroize.js";

/**
 * Split a secret (Uint8Array) into `shares` total shares,
 * requiring `threshold` shares to reconstruct.
 *
 * Returns an array of base64-encoded shares.
 */
export async function splitSecret(
  secret: Uint8Array,
  shares: number,
  threshold: number
): Promise<string[]> {
  // Ensure the secret is a plain Uint8Array (not a view or cross-realm instance)
  const normalized = new Uint8Array(secret);
  try {
    const shareBuffers = await split(normalized, shares, threshold);
    return shareBuffers.map((buf) => arrayBufferToBase64(buf));
  } finally {
    zeroize(normalized); // our internal copy of the secret
  }
}

/**
 * Combine base64-encoded shares to reconstruct the secret.
 *
 * Returns the reconstructed secret as a Uint8Array.
 */
export async function combineShares(
  shareBase64List: string[]
): Promise<Uint8Array> {
  const shareBuffers = shareBase64List.map((b64) =>
    new Uint8Array(base64ToArrayBuffer(b64))
  );
  return combine(shareBuffers);
}
