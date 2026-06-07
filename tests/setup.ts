import { webcrypto } from "node:crypto";

// Vitest's Node environment does not expose globalThis.crypto in Node 18/20.
// The WebCrypto API is available via node:crypto.webcrypto, so we polyfill
// the global so the browser-facing crypto modules work in tests.
if (!globalThis.crypto) {
  // @ts-expect-error — globalThis.crypto types differ slightly from webcrypto
  globalThis.crypto = webcrypto;
}
