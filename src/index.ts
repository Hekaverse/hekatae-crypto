/**
 * HEKATAE Client-Side Cryptography Module
 *
 * All encryption/decryption happens in the browser (or in a trusted Node
 * environment for server-side file helpers). The server sees only ciphertext
 * and encrypted shares.
 *
 * Key hierarchy for legacy recordings:
 *   Password -> Argon2id -> PDK -> encrypts UMK
 *   UMK -> splits into 3 shares (2-of-3 SSS)
 *   UMK -> encrypts per-recording keys (REK)
 *   REK -> encrypts recording blobs (AES-256-GCM)
 *
 * Trust Lattice hierarchy for legacy messages:
 *   Content Key (CK) -> split across dimensions (T, I, S, P, C)
 *   CK -> encrypts message content (AES-256-GCM)
 */

// ─── Base64 helpers ───
export {
  arrayBufferToBase64,
  base64ToArrayBuffer,
} from "./browser-crypto.js";

// ─── Authenticated Additional Data (AAD) ───
export {
  buildRecordingAAD,
  parseRecordingAAD,
  AAD_VERSION,
} from "./aad.js";
export type { RecordingAAD } from "./aad.js";

// ─── WebCrypto wrappers ───
export {
  generateAESKey,
  generateDataKey,
  generateWrappingKey,
  exportKey,
  importKey,
  importDataKey,
  importWrappingKey,
  importPDK,
  generateKeyBase64,
  encryptData,
  decryptData,
  encryptString,
  decryptToString,
  wrapKey,
  unwrapKey,
  generateSalt,
  encryptWithPassphrase,
  decryptWithPassphrase,
} from "./browser-crypto.js";

export type { EncryptionResult } from "./browser-crypto.js";

// ─── Argon2id / PBKDF2 key derivation ───
export { deriveKeyPDK, deriveKeyPBKDF2 } from "./argon2.js";
export type { Argon2Options } from "./argon2.js";

// ─── Shamir's Secret Sharing ───
export { splitSecret, combineShares } from "./shamir.js";

// ─── User Master Key lifecycle ───
export {
  setupUserKeys,
  decryptUMK,
  reconstructUMKFromShares,
  decryptShare,
  generateRecoveryShares,
} from "./key-derivation.js";

export type {
  KeySetupPayload,
  KeySetupResult,
  RecoverySharesResult,
} from "./key-derivation.js";

// ─── Per-recording encryption ───
export { encryptRecording, decryptRecording } from "./recording-crypto.js";
export type { EncryptedRecording } from "./recording-crypto.js";

// ─── Encryption type discriminator ───
export {
  inferEncryptionType,
  isEncrypted,
  isTrustLattice,
  isLegacyClientSide,
} from "./encryption-types.js";
export type { EncryptionType, RecordingLike, MediaManifestItem } from "./encryption-types.js";

// ─── Ciphertext blob integrity + decryption ───
export {
  extractAuthTagFromBlob,
  verifyAuthTag,
  decryptCiphertextBlob,
} from "./blob-decryption.js";

// ─── Node.js file encryption helpers ───
export { encryptFile, decryptFile } from "./file-encryption.js";
export type { FileEncryptionResult } from "./file-encryption.js";

// ─── Trust Lattice threshold encryption ───
export {
  generateContentKey,
  splitContentKey,
  reconstructContentKey,
  evaluateContract,
  getRequiredDimensions,
  getContractThreshold,
  getContractLabel,
  getContractDescription,
  CONTRACT_DIMENSIONS,
} from "./trust-lattice.js";

export type { DeliveryContract, Dimension } from "./trust-lattice.js";
