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
// keys.umkBase64, keys.encryptedUMK,
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

## Production hardening: worker-based key isolation (recommended for the web app)

The classic API above keeps key material (UMK, PDK, REKs) in the page's main
JavaScript realm — as base64 strings and `CryptoKey` objects in the same heap
as every other script running in the page. Any XSS in the page can read them,
and base64 key strings cannot be scrubbed (JS strings are immutable).

The `hekatae-crypto/worker` subpath moves the UMK into a dedicated **Web
Worker** and is the recommended production path for browser apps. The worker
generates/imports and *holds* the UMK; the main thread sends operations and
receives only what must leave the enclave — ciphertexts, wrapped keys, and
recovery shares. Raw UMK/PDK bytes never cross the boundary in normal flows.

```ts
import { WorkerCryptoClient } from "hekatae-crypto/worker";

const worker = new Worker(
  new URL("hekatae-crypto/worker/entry", import.meta.url),
  { type: "module" }
);
const crypto = new WorkerCryptoClient(worker);

// Registration — UMK is generated and HELD inside the worker.
// Result has NO umkBase64 field; store these artifacts server-side.
const setup = await crypto.setupUserKeys(password, userId);
// → { encryptedUMK, shareA, shareB, shareC, salt, sentinel }

// Later sessions — worker-side equivalent of decryptUMK: unlocks the UMK
// inside the worker and returns nothing key-like.
await crypto.unlock(user.encryptedMasterKey, password, user.masterKeySalt);

// Blob encryption — a fresh REK is generated, used, and wrapped with the
// UMK entirely inside the worker. Only ciphertext + wrapped REK come back.
const enc = await crypto.encryptBlob(plaintextBytes, aad);
// → { ciphertext: ArrayBuffer, iv, authTag, encryptedREK }
const plain = await crypto.decryptBlob(
  enc.ciphertext, enc.iv, enc.authTag, enc.encryptedREK, aad
);

// Tear down on logout.
await crypto.destroy();
```

What crosses the worker boundary:

| Direction | Data |
|-----------|------|
| main → worker | passwords (transiently, for Argon2id), `encryptedUMK`, ciphertexts, wrapped REKs, AAD |
| worker → main | ciphertexts, `encryptedUMK`, wrapped REKs, Shamir shares, salt, sentinel, plaintext you explicitly decrypted |
| **never crosses** | raw UMK, raw PDK, raw REKs (with `encryptBlob`/`decryptBlob`) |

Compatibility operations for existing flows:

- `wrapREK(rekBase64)` / `unwrapREK(encryptedREK)` — for flows where the page
  legitimately holds a per-item key (e.g. Trust Lattice content keys that are
  split client-side, like the legacy recording flow). Prefer
  `encryptBlob`/`decryptBlob` in new code so REKs never enter the page.
- `exportUMK(encryptedUMK, password, salt, userId?)` — **escape hatch** for
  legacy flows that still require the raw UMK base64 on the main thread
  (e.g. code built around the classic `setupUserKeys().umkBase64` /
  `decryptUMK()` return value). It re-derives the PDK from the password,
  unwraps the UMK extractably for that single call, and zeroes the raw bytes
  immediately. It defeats the isolation for that key — migrate away from it.

Inside the worker, the session UMK is held as a **non-extractable**
`CryptoKey`. The one flow that fundamentally needs raw UMK bytes is Shamir
splitting (setup and recovery-share generation); there the key exists in
extractable form only for the duration of that operation, and the raw
`Uint8Array` is zeroed (`fill(0)`) in a `finally` block immediately after
splitting.

Honest limits:

- This is XSS **surface reduction, not elimination**. A page-context attacker
  can still *ask the worker to perform operations* (decrypt blobs, wrap keys)
  while it is unlocked — they just can't extract the raw keys. Lock the
  worker (`lock()`/`destroy()`) when the vault is not in use.
- Passwords and decrypted plaintext still cross the structured-clone
  boundary; the browser may keep copies of transferred/cloned data outside
  either realm's control.
- JavaScript offers no guaranteed memory wiping in any realm (strings are
  immutable; the GC moves and duplicates values). `zeroize()` is best-effort
  for `Uint8Array`/`ArrayBuffer` only. For stronger guarantees use a native
  module (mobile) or hardware-backed keys.

### Zeroing policy (classic API)

The synchronous API now scrubs intermediate raw key bytes (derived PDK bytes,
exported/unwrapped key bytes, plaintext share bytes, content-key bytes) with
an internal `zeroize()` helper immediately after use. Only buffers owned by
this package are zeroed — caller-provided and returned buffers are never
touched. Base64 key **strings** returned by the classic API (e.g.
`umkBase64`) cannot be zeroed; if that matters for your threat model, use the
worker path above.

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
- The package performs best-effort memory wiping of raw key bytes it owns
  (see "Zeroing policy" above), but JavaScript strings and garbage-collected
  memory cannot be deterministically zeroed. For browser apps, use the
  worker-based isolation path (`hekatae-crypto/worker`); users who need
  hardware-level guarantees should use a native module.

## Documentation

- [Trust Lattice Threat Model](../docs/architecture/TRUST_LATTICE_THREAT_MODEL.md) — threat model and share-custody analysis for the multi-dimensional threshold scheme

## License

Apache-2.0 — see [LICENSE](https://github.com/hekatae/hekatae-crypto/blob/main/LICENSE).
