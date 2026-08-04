/**
 * Best-effort scrubbing of sensitive key material.
 *
 * IMPORTANT — the limits of zeroing in JavaScript:
 *   - Uint8Array / ArrayBuffer contents CAN be overwritten in place, so every
 *     intermediate buffer that holds raw key bytes (derived keys, unwrapped
 *     REKs, share bytes, exported UMK bytes) is zeroed immediately after use.
 *   - JavaScript STRINGS are immutable and cannot be reliably zeroed. Any
 *     base64 key string (e.g. `umkBase64`) may linger in the JS heap until
 *     garbage collection, and may be duplicated by the engine at will.
 *
 * This is exactly why the worker-based path (see `worker-client.ts` /
 * `hekatae-crypto/worker`) is the recommended production setup for the web
 * app: it confines raw key material to a separate worker realm — away from
 * page XSS — and keeps it in zeroable Uint8Arrays instead of base64 strings.
 *
 * Never zero a buffer that is owned by (or returned to) a caller; only zero
 * buffers this module created and finished using.
 */
export function zeroize(buf: Uint8Array | ArrayBuffer | null | undefined): void {
  if (!buf) return;
  const view = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  view.fill(0);
}
