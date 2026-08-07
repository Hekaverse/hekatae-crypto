/**
 * Authenticated Additional Data (AAD) builder for AES-GCM.
 *
 * AAD binds a ciphertext to its operational context so that a blob cannot be
 * replayed or transplanted into another recording, contract, or format version.
 * It is non-secret and stored alongside the ciphertext (implicitly, via the
 * recording ID and contract known to both sender and recipient).
 */

export const AAD_VERSION = 1;

export interface RecordingAAD {
  version: number;
  recordingId: string;
  deliveryContract: string;
}

/**
 * Build a deterministic AAD payload for a recording.
 *
 * @param recordingId - Canonical recording UUID. For new recordings this is
 *   generated client-side before encryption and sent to the server as the `id`
 *   field; for existing recordings it is the persisted Prisma id.
 * @param deliveryContract - Trust Lattice contract (e.g. SIMPLE). For legacy
 *   UMK recordings without a contract, use `"LEGACY"`.
 * @param version - AAD format version. Defaults to the current version.
 */
export function buildRecordingAAD(
  recordingId: string,
  deliveryContract: string = "LEGACY",
  version: number = AAD_VERSION
): Uint8Array {
  if (!recordingId) {
    throw new Error("recordingId is required to build recording AAD");
  }
  const context = `hekatae:aad:v${version}:${recordingId}:${deliveryContract.toUpperCase()}`;
  return new TextEncoder().encode(context);
}

/**
 * Parse a previously-encoded AAD string back into its components.
 * Useful for tests and diagnostics; the format is deliberately simple.
 */
export function parseRecordingAAD(aad: Uint8Array): RecordingAAD {
  const decoded = new TextDecoder().decode(aad);
  const parts = decoded.split(":");
  if (parts.length !== 5 || parts[0] !== "hekatae" || parts[1] !== "aad") {
    throw new Error("Invalid recording AAD format");
  }
  const versionStr = parts[2].replace(/^v/, "");
  const version = Number(versionStr);
  if (versionStr === "" || !Number.isInteger(version)) {
    throw new Error("Invalid recording AAD format");
  }
  return {
    version,
    recordingId: parts[3],
    deliveryContract: parts[4],
  };
}
