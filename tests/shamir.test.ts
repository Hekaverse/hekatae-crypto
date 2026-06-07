import { describe, it, expect } from "vitest";
import { splitSecret, combineShares } from "../src/shamir";

describe("Shamir's Secret Sharing", () => {
  describe("splitSecret + combineShares roundtrip", () => {
    it("should reconstruct a simple text secret", async () => {
      const secret = new TextEncoder().encode("hello world");
      const shares = await splitSecret(secret, 3, 3);
      expect(shares).toHaveLength(3);

      const reconstructed = await combineShares(shares);
      expect(new TextDecoder().decode(reconstructed)).toBe("hello world");
    });

    it("should reconstruct a 32-byte key", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares = await splitSecret(secret, 5, 5);

      const reconstructed = await combineShares(shares);
      expect(reconstructed).toEqual(secret);
    });

    it("should reconstruct with varying secret sizes", async () => {
      for (const size of [1, 16, 32, 64, 128, 256]) {
        const secret = crypto.getRandomValues(new Uint8Array(size));
        const shares = await splitSecret(secret, 3, 3);
        const reconstructed = await combineShares(shares);
        expect(reconstructed).toEqual(secret);
      }
    });

    it("should produce valid base64 shares", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares = await splitSecret(secret, 3, 3);

      shares.forEach((share) => {
        expect(() => atob(share)).not.toThrow();
      });
    });

    it("should produce different shares each time", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares1 = await splitSecret(secret, 3, 3);
      const shares2 = await splitSecret(secret, 3, 3);

      // All shares should be different between runs
      for (let i = 0; i < 3; i++) {
        expect(shares1[i]).not.toBe(shares2[i]);
      }
    });

    it("should produce garbage with fewer than threshold shares", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares = await splitSecret(secret, 5, 3);

      // With fewer than threshold shares, reconstruction returns garbage (not the original)
      const partialShares = shares.slice(0, 2);
      const garbage = await combineShares(partialShares);
      expect(garbage).not.toEqual(secret);
    });

    it("should succeed with exactly threshold shares", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares = await splitSecret(secret, 5, 3);

      const reconstructed = await combineShares(shares.slice(0, 3));
      expect(reconstructed).toEqual(secret);
    });

    it("should succeed with more than threshold shares", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares = await splitSecret(secret, 5, 3);

      const reconstructed = await combineShares(shares.slice(0, 4));
      expect(reconstructed).toEqual(secret);
    });

    it("should handle binary data with null bytes", async () => {
      const secret = new Uint8Array(32);
      secret[0] = 0x00;
      secret[15] = 0x00;
      secret[31] = 0x00;

      const shares = await splitSecret(secret, 3, 3);
      const reconstructed = await combineShares(shares);
      expect(reconstructed).toEqual(secret);
    });

    it("should handle binary data with high bytes (0xFF)", async () => {
      const secret = new Uint8Array(32).fill(0xFF);
      const shares = await splitSecret(secret, 3, 3);
      const reconstructed = await combineShares(shares);
      expect(reconstructed).toEqual(secret);
    });

    it("should handle binary data with mixed bytes", async () => {
      const secret = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        secret[i] = i * 7; // Mix of values
      }

      const shares = await splitSecret(secret, 3, 3);
      const reconstructed = await combineShares(shares);
      expect(reconstructed).toEqual(secret);
    });
  });

  describe("edge cases", () => {
    it("should handle single-byte secret", async () => {
      const secret = new Uint8Array([0x42]);
      const shares = await splitSecret(secret, 2, 2);
      const reconstructed = await combineShares(shares);
      expect(reconstructed).toEqual(secret);
    });

    it("should handle large number of shares", async () => {
      const secret = crypto.getRandomValues(new Uint8Array(32));
      const shares = await splitSecret(secret, 10, 10);
      expect(shares).toHaveLength(10);

      const reconstructed = await combineShares(shares);
      expect(reconstructed).toEqual(secret);
    });

    it("should handle empty shares array", async () => {
      await expect(combineShares([])).rejects.toThrow();
    });

    it("should handle invalid base64 in shares", async () => {
      await expect(combineShares(["not-valid-base64!!!"])).rejects.toThrow();
    });
  });
});
