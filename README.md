# hekatae-crypto

Client-side cryptography for legacy messaging.

This package provides the cryptographic primitives used by HEKATAE to keep
user data encrypted end-to-end. All key generation, encryption, and
decryption happens in the browser. The server sees only ciphertext,
encrypted shares, and encrypted recording keys.

## What this package provides

| Module | Purpose |
|--------|---------|
| `browser-crypto` | WebCrypto wrappers: AES-256-GCM, key wrap/unwrap, base64 helpers |
| `argon2` | Argon2id password-derived keys via `hash-wasm`, with PBKDF2 fallback |
| `shamir` | Shamir's Secret Sharing wrapper for threshold key recovery |
| `key-derivation` | User Master Key (UMK) lifecycle: setup, password recovery, share reconstruction |
| `recording-crypto` | Per-recording encryption with unique Recording Encryption Keys (REK) |
| `blob-decryption` | Ciphertext blob integrity verification and decryption |
| `file-encryption` | Node.js AES-256-GCM helpers for server-side pipelines |
| `trust-lattice` | Multi-dimensional threshold encryption for legacy messages |

## Key hierarchy

### Legacy recordings

```
Password ──Argon2id──► PDK
PDK ──wraps──► UMK (User Master Key)
UMK ──splits──► 3 shares (2-of-3 threshold)
UMK ──wraps──► REK (per-recording key)
REK ──encrypts──► Recording blob (AES-256-GCM)
```

### Trust Lattice messages

```
Content Key (CK) ──splits──► N shares across dimensions
Dimensions: TIME · IDENTITY · SERVER · CONSENT · PHYSICAL
CK ──encrypts──► Message content (AES-256-GCM)
```

## Install

```bash
npm install hekatae-crypto
```

Requires Node.js 18+ or a modern browser with WebCrypto support.

## Usage

```ts
import {
  setupUserKeys,
  decryptUMK,
  reconstructUMKFromShares,
  encryptRecording,
  decryptRecording,
} from "hekatae-crypto";

// 1. Set up a new user
const keys = await setupUserKeys("correct horse battery staple", "user-123");
// keys.umkBase64, keys.pdkBase64, keys.encryptedUMK,
// keys.shareA, keys.shareB, keys.shareC, keys.salt, keys.sentinel

// 2. Recover UMK from password
const umk = await decryptUMK(keys.encryptedUMK, "correct horse battery staple", keys.salt, "user-123");

// 3. Recover UMK from any two shares (with sentinel verification)
const recovered = await reconstructUMKFromShares(keys.shareB, keys.shareC, keys.sentinel);

// 4. Encrypt a recording
const umkKey = await importWrappingKey(umk);
const encrypted = await encryptRecording(mediaBlob, umkKey);

// 5. Decrypt a recording
const decrypted = await decryptRecording(
  encrypted.ciphertextBlob,
  encrypted.iv,
  encrypted.authTag,
  encrypted.encryptedREK,
  umkKey
);
```

## Trust Lattice example

```ts
import { generateContentKey, splitContentKey, reconstructContentKey, encryptData, decryptData } from "hekatae-crypto";

const ck = await generateContentKey();
const { shares } = await splitContentKey(ck, "STANDARD");

// Later, when all required dimensions are available...
const reconstructed = await reconstructContentKey(shares.map((s) => s.share));
```

## Sentinel verification

`setupUserKeys()` generates a `sentinel`: a random key wrapped by the UMK. When
`reconstructUMKFromShares()` is called with a sentinel, it verifies the
reconstructed UMK by unwrapping the sentinel. If shares are corrupted or
tampered, unwrapping fails and the function throws before any decrypted data
is produced.

## Security notes

- AES-256-GCM with a 12-byte IV everywhere (browser and Node).
- Argon2id is the default password-based KDF; PBKDF2 is a fallback if the
  Argon2 WASM module fails to load.
- All wrapping uses the WebCrypto `wrapKey`/`unwrapKey` API with AES-GCM.
- The package does not do memory wiping: in JavaScript runtimes, strings and
  garbage-collected memory cannot be deterministically zeroed. Users who need
  hardware-level guarantees should run crypto inside an isolated Web Worker or
  native module.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
