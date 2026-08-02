/**
 * Encryption Type Discriminated Union
 *
 * Unifies all encryption schemes into a single, type-safe discriminated union.
 * This eliminates the scattered `!!recording.ciphertextUrl && !!recording.encryptedREK`
 * checks across the codebase and makes encryption handling explicit.
 *
 * Trust Lattice Note:
 *   For Trust Lattice recordings, `encryptedREK` stores the UMK-wrapped Content Key (CK).
 *   This is a "sender preview key" — it allows the sender to preview their own recording
 *   in the vault without needing recipient shares. Recipients reconstruct the CK from
 *   released shares instead.
 */

export type EncryptionType =
  | { kind: "NONE"; contentUrl: string }
  | {
      kind: "LEGACY_CLIENT_SIDE";
      ciphertextUrl: string;
      iv: string;
      authTag: string;
      encryptedREK: string;
    }
  | {
      kind: "SERVER_SIDE";
      contentUrl: string;
      encryptedDataKey: string;
      encryptionKeyId: string;
    }
  | {
      kind: "TRUST_LATTICE";
      ciphertextUrl: string;
      iv: string;
      authTag: string;
      deliveryContract: string;
      senderPreviewKey: string | null; // UMK-wrapped CK for vault preview
    };

export interface MediaManifestItem {
  iv?: string | null;
  authTag?: string | null;
  encryptedREK?: string | null;
  encryptedDataKey?: string | null;
  encryptionKeyId?: string | null;
  [key: string]: unknown;
}

export interface RecordingLike {
  ciphertextUrl?: string | null;
  iv?: string | null;
  authTag?: string | null;
  encryptedREK?: string | null;
  encryptedDataKey?: string | null;
  encryptionKeyId?: string | null;
  deliveryContract?: string | null;
  contentUrl?: string | null;
  mediaManifest?: MediaManifestItem[] | null;
}

/**
 * Infer the encryption type from a recording object.
 * Priority: Trust Lattice > Legacy Client-Side > Server-Side > None
 *
 * Trust Lattice requires ACTUAL encryption metadata — not just a deliveryContract.
 * The deliveryContract field has a Prisma default of "STANDARD", so ALL recordings
 * (including old unencrypted ones) have it. We must check for ciphertextUrl,
 * encryptedREK, or per-piece iv/authTag to confirm real encryption was applied.
 */
export function inferEncryptionType(recording: RecordingLike): EncryptionType {
  // Trust Lattice: must have delivery contract AND actual encryption evidence
  if (recording.deliveryContract) {
    const hasRecordingLevelEncryption =
      !!recording.ciphertextUrl || !!recording.encryptedREK;
    const hasManifestEncryption =
      recording.mediaManifest?.some(
        (p) => p.iv && p.authTag
      ) ?? false;

    if (hasRecordingLevelEncryption || hasManifestEncryption) {
      return {
        kind: "TRUST_LATTICE",
        ciphertextUrl: recording.ciphertextUrl || "",
        iv: recording.iv || "",
        authTag: recording.authTag || "",
        deliveryContract: recording.deliveryContract,
        senderPreviewKey: recording.encryptedREK || null,
      };
    }
  }

  // Legacy client-side encryption (UMK → REK → blob)
  if (recording.ciphertextUrl && recording.iv && recording.authTag && recording.encryptedREK) {
    return {
      kind: "LEGACY_CLIENT_SIDE",
      ciphertextUrl: recording.ciphertextUrl,
      iv: recording.iv,
      authTag: recording.authTag,
      encryptedREK: recording.encryptedREK,
    };
  }

  // Server-side envelope encryption
  if (recording.encryptedDataKey && recording.encryptionKeyId) {
    return {
      kind: "SERVER_SIDE",
      contentUrl: recording.contentUrl || "",
      encryptedDataKey: recording.encryptedDataKey,
      encryptionKeyId: recording.encryptionKeyId,
    };
  }

  // Unencrypted / plaintext
  return {
    kind: "NONE",
    contentUrl: recording.contentUrl || "",
  };
}

/**
 * Check if a recording is encrypted in any form.
 */
export function isEncrypted(recording: RecordingLike): boolean {
  return inferEncryptionType(recording).kind !== "NONE";
}

/**
 * Check if a recording uses Trust Lattice encryption.
 */
export function isTrustLattice(recording: RecordingLike): boolean {
  return inferEncryptionType(recording).kind === "TRUST_LATTICE";
}

/**
 * Check if a recording uses legacy client-side encryption.
 */
export function isLegacyClientSide(recording: RecordingLike): boolean {
  return inferEncryptionType(recording).kind === "LEGACY_CLIENT_SIDE";
}
