import { describe, it, expect, vi, afterEach } from "vitest";
import { zeroize } from "../src/zeroize";
import {
  setupUserKeys,
  decryptUMK,
  reconstructUMKFromShares,
  generateRecoveryShares,
} from "../src/key-derivation";
import { splitContentKey, generateContentKey } from "../src/trust-lattice";
import { importPDK, deriveKeyFromPassphrase } from "../src/browser-crypto";
import { deriveKeyPDK } from "../src/argon2";

afterEach(() => {
  vi.restoreAllMocks();
});

describe("zeroize", () => {
  it("should overwrite a Uint8Array with zeros", () => {
    const buf = new Uint8Array([1, 2, 3, 255, 128]);
    zeroize(buf);
    expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0]);
  });

  it("should overwrite an ArrayBuffer with zeros", () => {
    const buf = new Uint8Array([7, 7, 7]).buffer;
    zeroize(buf);
    expect(Array.from(new Uint8Array(buf))).toEqual([0, 0, 0]);
  });

  it("should tolerate null and undefined", () => {
    expect(() => zeroize(null)).not.toThrow();
    expect(() => zeroize(undefined)).not.toThrow();
  });
});

/**
 * The sensitive intermediate buffers in these operations are local variables,
 * so we observe the zeroing by spying on Uint8Array.prototype.fill: every
 * zeroize() call routes through fill(0). We assert that fill(0) was applied
 * to at least one key-sized (>= 16 byte) buffer during the operation, and
 * that the operation still produces correct results.
 */
describe("sensitive intermediates are zeroed after use", () => {
  function spyOnFill() {
    const zeroed: number[] = [];
    const original = Uint8Array.prototype.fill;
    vi.spyOn(Uint8Array.prototype, "fill").mockImplementation(function (
      this: Uint8Array,
      value: number | Uint8Array,
      start?: number,
      end?: number
    ) {
      if (typeof value === "number" && value === 0 && this.length >= 16) {
        zeroed.push(this.length);
      }
      return original.call(this, value as number, start, end);
    });
    return zeroed;
  }

  it("setupUserKeys zeroes raw UMK bytes after Shamir splitting", async () => {
    const zeroed = spyOnFill();
    const result = await setupUserKeys("zeroize-test-password");
    expect(result.umkBase64).toBeTruthy();
    // UMK is 32 bytes
    expect(zeroed).toContain(32);
  });

  it("decryptUMK zeroes the exported raw UMK bytes", async () => {
    const setup = await setupUserKeys("zeroize-test-password");
    const zeroed = spyOnFill();
    const umk = await decryptUMK(setup.encryptedUMK, "zeroize-test-password", setup.salt);
    expect(umk).toBe(setup.umkBase64);
    expect(zeroed).toContain(32);
  });

  it("reconstructUMKFromShares zeroes the reconstructed UMK bytes", async () => {
    const setup = await setupUserKeys("zeroize-test-password");
    const zeroed = spyOnFill();
    const umk = await reconstructUMKFromShares(setup.shareB, setup.shareC);
    expect(umk).toBe(setup.umkBase64);
    expect(zeroed).toContain(32);
  });

  it("generateRecoveryShares zeroes raw UMK bytes after splitting", async () => {
    const setup = await setupUserKeys("zeroize-test-password");
    const pdkKey = await importPDK(
      await deriveKeyPDK({ pass: "pw", salt: "long-enough-salt" })
    );
    const zeroed = spyOnFill();
    const shares = await generateRecoveryShares(setup.umkBase64, pdkKey);
    expect(shares.shareA).toBeTruthy();
    expect(zeroed).toContain(32);
  });

  it("splitContentKey zeroes raw CK bytes after splitting", async () => {
    const ck = await generateContentKey();
    const zeroed = spyOnFill();
    const result = await splitContentKey(ck, "STANDARD");
    expect(result.shares).toHaveLength(3);
    expect(zeroed).toContain(32);
  });

  it("deriveKeyFromPassphrase zeroes password and derived key bytes", async () => {
    const zeroed = spyOnFill();
    const salt = new Uint8Array(16).fill(9);
    const key = await deriveKeyFromPassphrase("hunter2", salt);
    expect(key).toBeTruthy();
    // derived key (32 bytes) and password bytes (7 bytes — under our 16-byte
    // observation floor, so we only assert the 32-byte derived key here)
    expect(zeroed).toContain(32);
  });

  it("deriveKeyPDK zeroes the raw PDK bytes", async () => {
    const zeroed = spyOnFill();
    const pdk = await deriveKeyPDK({ pass: "pw", salt: "some-salt" });
    expect(pdk).toBeTruthy();
    expect(zeroed).toContain(32);
  });
});
