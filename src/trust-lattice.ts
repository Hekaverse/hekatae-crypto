/**
 * Trust Lattice — Multi-dimensional threshold encryption for legacy messaging.
 *
 * Core concept: A message's Content Key (CK) is split into N shares using
 * Shamir's Secret Sharing. Each share is protected by a different "dimension."
 * Decryption requires alignment across all required dimensions.
 *
 * Dimensions:
 *   T (Time)      — Server-enforced delivery time gating
 *   I (Identity)  — Recipient's password-derived key
 *   S (Server)    — Server-held secret key
 *   P (Physical)  — Physical keystone device (future)
 *   C (Consent)   — Recovery contact threshold (future)
 *
 * Contracts (user-selectable tiers):
 *   SIMPLE   : T + S                     (fallback for non-registered recipients)
 *   STANDARD : T + I + S                 (registered recipient, server-assisted)
 *   SECURE   : T + I + S + C             (registered + recovery contact confirmation)
 *   PARANOID : T + I + S + P + C         (all dimensions including physical token)
 *
 * Security properties (as implemented in the HEKATAE web app today):
 *   — No single client-side party holds the complete CK; the sender retains a
 *     UMK-wrapped copy (encryptedREK) for vault preview
 *   — HEKATAE holds and can unseal both the TIME and SERVER shares, which meet
 *     the threshold for SIMPLE/STANDARD on their own: those tiers are
 *     server-assisted delivery by design, not zero-knowledge
 *   — SECURE/PARANOID thresholds additionally require non-server shares
 *     (IDENTITY/CONSENT/PHYSICAL), which are KMS-encrypted at rest; binding
 *     them to recipients, trustees, or devices is on the roadmap
 *   — Subpoena to cloud provider reveals only ciphertext
 *   — Recipient must be authenticated AND delivery conditions met
 */

import { generateDataKey, exportKey, importDataKey, arrayBufferToBase64, base64ToArrayBuffer } from "./browser-crypto.js";
import { splitSecret, combineShares } from "./shamir.js";
import { zeroize } from "./zeroize.js";

export type DeliveryContract = "SIMPLE" | "STANDARD" | "SECURE" | "PARANOID";

export type Dimension = "TIME" | "IDENTITY" | "SERVER" | "PHYSICAL" | "CONSENT";

/** Which dimensions are required for each contract tier. */
export const CONTRACT_DIMENSIONS: Record<DeliveryContract, Dimension[]> = {
  SIMPLE: ["TIME", "SERVER"],
  STANDARD: ["TIME", "IDENTITY", "SERVER"],
  SECURE: ["TIME", "IDENTITY", "SERVER", "CONSENT"],
  PARANOID: ["TIME", "IDENTITY", "SERVER", "PHYSICAL", "CONSENT"],
};

/**
 * Threshold (k) for each contract tier: any k distinct dimension shares can
 * reconstruct the Content Key. This gives real M-of-N threshold semantics
 * instead of requiring every dimension.
 */
export const CONTRACT_THRESHOLD: Record<DeliveryContract, number> = {
  SIMPLE: 2,     // 2-of-2: only two dimensions exist
  STANDARD: 2,   // 2-of-3
  SECURE: 3,     // 3-of-4
  PARANOID: 4,   // 4-of-5
};

/**
 * Generate a random 256-bit AES key for encrypting message content.
 * This is the Content Key (CK) that will be split across the lattice.
 */
export async function generateContentKey(): Promise<CryptoKey> {
  return generateDataKey();
}

/**
 * Export a CryptoKey to a base64 string suitable for splitting.
 */
async function exportContentKey(key: CryptoKey): Promise<string> {
  return exportKey(key);
}

/**
 * Import a base64 string back into a Content Key CryptoKey.
 */
async function importContentKey(base64Key: string): Promise<CryptoKey> {
  return importDataKey(base64Key);
}

/**
 * Split a Content Key into shares based on a Delivery Contract.
 *
 * The number of shares equals the number of dimensions in the contract (n).
 * The threshold (k) is defined by CONTRACT_THRESHOLD so that any k distinct
 * shares can reconstruct the Content Key.
 */
export async function splitContentKey(
  ck: CryptoKey,
  contract: DeliveryContract
): Promise<{ contract: DeliveryContract; shares: { dimension: Dimension; share: string }[] }> {
  const dimensions = CONTRACT_DIMENSIONS[contract];
  const threshold = CONTRACT_THRESHOLD[contract];

  // Export CK to bytes
  const ckBase64 = await exportContentKey(ck);
  const ckBytes = new Uint8Array(base64ToArrayBuffer(ckBase64));

  // Split into shares: n total shares, k required to reconstruct.
  // Raw CK bytes are scrubbed immediately after splitting (the base64
  // string form cannot be zeroed — see zeroize.ts).
  let shareBase64List: string[];
  try {
    shareBase64List = await splitSecret(ckBytes, dimensions.length, threshold);
  } finally {
    zeroize(ckBytes);
  }

  // Map each share to its dimension
  const shares = dimensions.map((dimension, index) => ({
    dimension,
    share: shareBase64List[index],
  }));

  return {
    contract,
    shares,
  };
}

/**
 * Reconstruct a Content Key from a set of shares.
 *
 * Requires at least `threshold` shares (as defined by the contract).
 */
export async function reconstructContentKey(shareBase64List: string[]): Promise<CryptoKey> {
  const ckBytes = await combineShares(shareBase64List);
  try {
    const ckBase64 = arrayBufferToBase64(ckBytes);
    return await importContentKey(ckBase64);
  } finally {
    zeroize(ckBytes); // raw reconstructed CK bytes
  }
}

/**
 * Evaluate whether a set of available dimensions satisfies a delivery contract.
 *
 * A contract is satisfied when at least `CONTRACT_THRESHOLD[contract]` distinct
 * required dimensions are present. This gives true M-of-N threshold semantics
 * rather than requiring every dimension.
 *
 * Example:
 *   evaluateContract("STANDARD", ["TIME", "IDENTITY", "SERVER"]) → true
 *   evaluateContract("STANDARD", ["TIME", "SERVER"]) → true  (2-of-3)
 *   evaluateContract("STANDARD", ["TIME"]) → false
 */
export function evaluateContract(
  contract: DeliveryContract,
  availableDimensions: Dimension[]
): boolean {
  const required = CONTRACT_DIMENSIONS[contract];
  const threshold = CONTRACT_THRESHOLD[contract];
  const presentCount = required.filter((dim) => availableDimensions.includes(dim)).length;
  return presentCount >= threshold;
}

/**
 * Get the required dimensions for a contract.
 */
export function getRequiredDimensions(contract: DeliveryContract): Dimension[] {
  return CONTRACT_DIMENSIONS[contract];
}

/**
 * Get the threshold (number of shares required) for a contract.
 */
export function getContractThreshold(contract: DeliveryContract): number {
  return CONTRACT_THRESHOLD[contract];
}

/**
 * Get a human-readable label for a delivery contract.
 */
export function getContractLabel(contract: DeliveryContract): string {
  switch (contract) {
    case "SIMPLE":
      return "Simple";
    case "STANDARD":
      return "Standard";
    case "SECURE":
      return "Secure";
    case "PARANOID":
      return "Paranoid";
  }
}

/**
 * Get a description for a delivery contract.
 */
export function getContractDescription(contract: DeliveryContract): string {
  switch (contract) {
    case "SIMPLE":
      return "Time + Server validation. Works without a HEKATAE account.";
    case "STANDARD":
      return "Time + Identity + Server. Recipient needs a HEKATAE account.";
    case "SECURE":
      return "Time + Identity + Server + Recovery Contact confirmation.";
    case "PARANOID":
      return "All dimensions including physical Keystone device.";
  }
}
