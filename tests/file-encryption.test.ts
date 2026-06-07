import { describe, it, expect } from "vitest";
import { encryptFile, decryptFile } from "../src/file-encryption";

describe("File Encryption (AES-256-GCM)", () => {
  function randomKey(): Buffer {
    return Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
  }

  describe("encryptFile", () => {
    it("should encrypt a plaintext buffer and return ciphertext + iv + authTag", () => {
      const key = randomKey();
      const plaintext = Buffer.from("Hello, world!");

      const result = encryptFile(plaintext, key);

      expect(Buffer.isBuffer(result.ciphertext)).toBe(true);
      expect(result.ciphertext.length).toBeGreaterThan(0);
      expect(result.iv).toMatch(/^[0-9a-f]{24}$/); // 12 bytes = 24 hex chars (NIST SP 800-38D)
      expect(result.authTag).toMatch(/^[0-9a-f]{32}$/); // 16 bytes = 32 hex chars
    });

    it("should reject a key that is not 32 bytes", () => {
      const shortKey = Buffer.from("short");
      const plaintext = Buffer.from("data");

      expect(() => encryptFile(plaintext, shortKey)).toThrow(
        "Encryption key must be 32 bytes (256 bits)"
      );
    });

    it("should produce different IVs and ciphertexts for identical plaintexts", () => {
      const key = randomKey();
      const plaintext = Buffer.from("same input");

      const result1 = encryptFile(plaintext, key);
      const result2 = encryptFile(plaintext, key);

      expect(result1.iv).not.toBe(result2.iv);
      expect(result1.authTag).not.toBe(result2.authTag);
      expect(result1.ciphertext).not.toEqual(result2.ciphertext);
    });

    it("should handle empty plaintext", () => {
      const key = randomKey();
      const plaintext = Buffer.alloc(0);

      const result = encryptFile(plaintext, key);

      expect(result.ciphertext.length).toBe(0);
      expect(result.iv).toMatch(/^[0-9a-f]{24}$/);
      expect(result.authTag).toMatch(/^[0-9a-f]{32}$/);
    });

    it("should handle large plaintext", () => {
      const key = randomKey();
      const plaintext = Buffer.from("x".repeat(10_000_000));

      const result = encryptFile(plaintext, key);

      expect(result.ciphertext.length).toBe(10_000_000); // GCM doesn't expand ciphertext
    });

    it("should handle binary data with null bytes", () => {
      const key = randomKey();
      const plaintext = Buffer.from([0x00, 0x01, 0x00, 0xff, 0x00]);

      const result = encryptFile(plaintext, key);
      const decrypted = decryptFile(result.ciphertext, result.iv, result.authTag, key);

      expect(decrypted).toEqual(plaintext);
    });
  });

  describe("decryptFile", () => {
    it("should roundtrip a plaintext buffer", () => {
      const key = randomKey();
      const plaintext = Buffer.from("Roundtrip test data");

      const encrypted = encryptFile(plaintext, key);
      const decrypted = decryptFile(encrypted.ciphertext, encrypted.iv, encrypted.authTag, key);

      expect(decrypted).toEqual(plaintext);
    });

    it("should reject a key that is not 32 bytes", () => {
      const key = randomKey();
      const plaintext = Buffer.from("data");
      const encrypted = encryptFile(plaintext, key);

      const shortKey = Buffer.from("short");
      expect(() => decryptFile(encrypted.ciphertext, encrypted.iv, encrypted.authTag, shortKey)).toThrow(
        "Encryption key must be 32 bytes (256 bits)"
      );
    });

    it("should fail decryption with a wrong key", () => {
      const key1 = randomKey();
      const key2 = randomKey();
      const plaintext = Buffer.from("secret");

      const encrypted = encryptFile(plaintext, key1);

      expect(() =>
        decryptFile(encrypted.ciphertext, encrypted.iv, encrypted.authTag, key2)
      ).toThrow();
    });

    it("should fail decryption with a tampered authTag", () => {
      const key = randomKey();
      const plaintext = Buffer.from("secret");

      const encrypted = encryptFile(plaintext, key);
      const tamperedAuthTag = encrypted.authTag.slice(0, -2) + "00";

      expect(() =>
        decryptFile(encrypted.ciphertext, encrypted.iv, tamperedAuthTag, key)
      ).toThrow();
    });

    it("should fail decryption with a tampered ciphertext", () => {
      const key = randomKey();
      const plaintext = Buffer.from("secret");

      const encrypted = encryptFile(plaintext, key);
      const tamperedCiphertext = Buffer.concat([encrypted.ciphertext, Buffer.from([0x00])]);

      expect(() =>
        decryptFile(tamperedCiphertext, encrypted.iv, encrypted.authTag, key)
      ).toThrow();
    });

    it("should fail decryption with a tampered IV", () => {
      const key = randomKey();
      const plaintext = Buffer.from("secret");

      const encrypted = encryptFile(plaintext, key);
      const tamperedIv = encrypted.iv.slice(0, -2) + "00";

      expect(() =>
        decryptFile(encrypted.ciphertext, tamperedIv, encrypted.authTag, key)
      ).toThrow();
    });

    it("should roundtrip empty plaintext", () => {
      const key = randomKey();
      const plaintext = Buffer.alloc(0);

      const encrypted = encryptFile(plaintext, key);
      const decrypted = decryptFile(encrypted.ciphertext, encrypted.iv, encrypted.authTag, key);

      expect(decrypted).toEqual(plaintext);
    });
  });
});
