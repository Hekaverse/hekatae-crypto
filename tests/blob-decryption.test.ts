import { describe, it, expect, beforeAll } from "vitest";
import {
  extractAuthTagFromBlob,
  verifyAuthTag,
  decryptCiphertextBlob,
} from "../src/blob-decryption";
import { generateAESKey, encryptData, constantTimeEqual } from "../src/browser-crypto";

// Polyfill Blob.prototype.arrayBuffer for jsdom if needed
beforeAll(() => {
  if (!Blob.prototype.arrayBuffer) {
    Blob.prototype.arrayBuffer = function (): Promise<ArrayBuffer> {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result as ArrayBuffer);
        reader.onerror = reject;
        reader.readAsArrayBuffer(this);
      });
    };
  }
});

async function blobToText(blob: Blob): Promise<string> {
  const ab = await blob.arrayBuffer();
  return new TextDecoder().decode(ab);
}

describe("Blob Decryption", () => {
  describe("extractAuthTagFromBlob", () => {
    it("should extract auth tag from the end of a blob", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
      const { dataCipher, storedAuthTag } = extractAuthTagFromBlob(data);
      expect(dataCipher.length).toBe(4);
      expect(storedAuthTag.length).toBe(16);
      expect(Array.from(dataCipher)).toEqual([1, 2, 3, 4]);
      expect(Array.from(storedAuthTag)).toEqual([5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    });

    it("should handle exactly 16 bytes (empty cipher)", () => {
      const data = new Uint8Array(16).fill(0xAB);
      const { dataCipher, storedAuthTag } = extractAuthTagFromBlob(data);
      expect(dataCipher.length).toBe(0);
      expect(storedAuthTag.length).toBe(16);
      expect(Array.from(storedAuthTag).every((b) => b === 0xAB)).toBe(true);
    });

    it("should handle large blobs", () => {
      const cipher = new Uint8Array(1000).fill(0xCC);
      const tag = new Uint8Array(16).fill(0xDD);
      const combined = new Uint8Array(cipher.length + tag.length);
      combined.set(cipher, 0);
      combined.set(tag, cipher.length);
      const { dataCipher, storedAuthTag } = extractAuthTagFromBlob(combined);
      expect(dataCipher.length).toBe(1000);
      expect(storedAuthTag.length).toBe(16);
      expect(Array.from(dataCipher).every((b) => b === 0xCC)).toBe(true);
      expect(Array.from(storedAuthTag).every((b) => b === 0xDD)).toBe(true);
    });

    it("should throw when blob is shorter than 16 bytes", () => {
      const data = new Uint8Array([1, 2, 3]);
      expect(() => extractAuthTagFromBlob(data)).toThrow("Ciphertext blob is too short");
    });

    it("should throw when blob is empty", () => {
      expect(() => extractAuthTagFromBlob(new Uint8Array(0))).toThrow("Ciphertext blob is too short");
    });
  });

  describe("verifyAuthTag", () => {
    it("should return true when tags match", () => {
      const tag = new Uint8Array(16).fill(0x42);
      const b64 = btoa(String.fromCharCode(...tag));
      expect(verifyAuthTag(tag, b64)).toBe(true);
    });

    it("should return false when tags differ", () => {
      const tag = new Uint8Array(16).fill(0x42);
      const otherB64 = btoa(String.fromCharCode(0x43));
      expect(verifyAuthTag(tag, otherB64)).toBe(false);
    });

    it("should return false for empty metadata tag", () => {
      const tag = new Uint8Array(16).fill(0x42);
      expect(verifyAuthTag(tag, "")).toBe(false);
    });

    it("should handle base64 with padding correctly", () => {
      const tag = crypto.getRandomValues(new Uint8Array(16));
      const b64 = btoa(String.fromCharCode(...tag));
      expect(verifyAuthTag(tag, b64)).toBe(true);
    });
  });

  describe("constantTimeEqual", () => {
    it("should return true for identical byte arrays", () => {
      const a = crypto.getRandomValues(new Uint8Array(16));
      expect(constantTimeEqual(a, new Uint8Array(a))).toBe(true);
    });

    it("should return false when one byte differs", () => {
      const a = crypto.getRandomValues(new Uint8Array(16));
      const b = new Uint8Array(a);
      b[7] ^= 0x01;
      expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("should return false on length mismatch", () => {
      expect(constantTimeEqual(new Uint8Array(16), new Uint8Array(24))).toBe(false);
    });

    it("should return true for two empty arrays", () => {
      expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    });
  });

  describe("decryptCiphertextBlob", () => {
    async function buildCiphertextBlob(plaintext: string, key: CryptoKey, aad?: Uint8Array): Promise<{ blob: Blob; iv: string; authTag: string }> {
      const plaintextBytes = new TextEncoder().encode(plaintext);
      const encrypted = await encryptData(plaintextBytes, key, aad);
      // Build blob: ciphertext || authTag (16 bytes)
      const cipherBytes = new Uint8Array(
        atob(encrypted.ciphertext)
          .split("")
          .map((c) => c.charCodeAt(0))
      );
      const authTagBytes = new Uint8Array(
        atob(encrypted.authTag)
          .split("")
          .map((c) => c.charCodeAt(0))
      );
      const combined = new Uint8Array(cipherBytes.length + authTagBytes.length);
      combined.set(cipherBytes, 0);
      combined.set(authTagBytes, cipherBytes.length);
      return {
        blob: new Blob([combined]),
        iv: encrypted.iv,
        authTag: encrypted.authTag,
      };
    }

    it("should decrypt a valid ciphertext blob", async () => {
      const key = await generateAESKey();
      const { blob, iv, authTag } = await buildCiphertextBlob("Hello, World!", key);
      const decrypted = await decryptCiphertextBlob(blob, iv, authTag, key, "text/plain");
      expect(decrypted.type).toBe("text/plain");
      expect(await blobToText(decrypted)).toBe("Hello, World!");
    });

    it("should use default blob type when not specified", async () => {
      const key = await generateAESKey();
      const { blob, iv, authTag } = await buildCiphertextBlob("data", key);
      const decrypted = await decryptCiphertextBlob(blob, iv, authTag, key);
      expect(decrypted.type).toBe("application/octet-stream");
    });

    it("should preserve blob type from original blob", async () => {
      const key = await generateAESKey();
      const { blob, iv, authTag } = await buildCiphertextBlob("audio data", key);
      const typedBlob = new Blob([await blob.arrayBuffer()], { type: "audio/wav" });
      const decrypted = await decryptCiphertextBlob(typedBlob, iv, authTag, key);
      expect(decrypted.type).toBe("audio/wav");
    });

    it("should handle empty plaintext", async () => {
      const key = await generateAESKey();
      const { blob, iv, authTag } = await buildCiphertextBlob("", key);
      const decrypted = await decryptCiphertextBlob(blob, iv, authTag, key);
      expect(decrypted.size).toBe(0);
    });

    it("should handle unicode content", async () => {
      const key = await generateAESKey();
      const text = "Hello 世界 🌍 مرحبا";
      const { blob, iv, authTag } = await buildCiphertextBlob(text, key);
      const decrypted = await decryptCiphertextBlob(blob, iv, authTag, key);
      expect(await blobToText(decrypted)).toBe(text);
    });

    it("should fail decryption with wrong key", async () => {
      const key1 = await generateAESKey();
      const key2 = await generateAESKey();
      const { blob, iv, authTag } = await buildCiphertextBlob("secret", key1);
      await expect(decryptCiphertextBlob(blob, iv, authTag, key2)).rejects.toThrow();
    });

    it("should fail decryption with tampered auth tag", async () => {
      const key = await generateAESKey();
      const { blob, iv, authTag } = await buildCiphertextBlob("secret", key);
      // Corrupt the last byte of the blob (part of auth tag)
      const bytes = new Uint8Array(await blob.arrayBuffer());
      bytes[bytes.length - 1] ^= 0xFF;
      const tamperedBlob = new Blob([bytes]);
      await expect(decryptCiphertextBlob(tamperedBlob, iv, authTag, key)).rejects.toThrow();
    });

    it("strict mode: mismatched AAD must fail with no fallback", async () => {
      const key = await generateAESKey();
      const aadA = new TextEncoder().encode("hekatae:aad:v1:recording-A:STANDARD");
      const aadB = new TextEncoder().encode("hekatae:aad:v1:recording-B:STANDARD");
      const { blob, iv, authTag } = await buildCiphertextBlob("secret", key, aadA);
      await expect(
        decryptCiphertextBlob(blob, iv, authTag, key, undefined, aadB, { requireAAD: true })
      ).rejects.toThrow();
    });

    it("strict mode: correct AAD still decrypts", async () => {
      const key = await generateAESKey();
      const aad = new TextEncoder().encode("hekatae:aad:v1:recording-1:STANDARD");
      const { blob, iv, authTag } = await buildCiphertextBlob("secret", key, aad);
      const decrypted = await decryptCiphertextBlob(blob, iv, authTag, key, undefined, aad, {
        requireAAD: true,
      });
      expect(await blobToText(decrypted)).toBe("secret");
    });

    it("strict mode: legacy no-AAD blob does NOT silently decrypt when AAD is supplied", async () => {
      // Blob was encrypted WITHOUT AAD; the caller supplies AAD and strict
      // mode must refuse the silent no-AAD retry.
      const key = await generateAESKey();
      const aad = new TextEncoder().encode("hekatae:aad:v1:recording-1:LEGACY");
      const { blob, iv, authTag } = await buildCiphertextBlob("legacy secret", key);
      await expect(
        decryptCiphertextBlob(blob, iv, authTag, key, undefined, aad, { requireAAD: true })
      ).rejects.toThrow();
    });

    it("non-strict mode: legacy no-AAD blob still decrypts via the fallback", async () => {
      const key = await generateAESKey();
      const aad = new TextEncoder().encode("hekatae:aad:v1:recording-1:LEGACY");
      const { blob, iv, authTag } = await buildCiphertextBlob("legacy secret", key);
      const decrypted = await decryptCiphertextBlob(blob, iv, authTag, key, undefined, aad);
      expect(await blobToText(decrypted)).toBe("legacy secret");
    });
  });
});
