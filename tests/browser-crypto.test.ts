import { describe, it, expect } from "vitest";
import {
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
} from "../src/browser-crypto";

describe("Browser Crypto (WebCrypto API)", () => {
  describe("generateAESKey", () => {
    it("should generate a 256-bit extractable AES-GCM data key by default", async () => {
      const key = await generateAESKey();
      expect(key.type).toBe("secret");
      expect(key.algorithm.name).toBe("AES-GCM");
      expect((key.algorithm as AesKeyAlgorithm).length).toBe(256);
      expect(key.extractable).toBe(true);
      expect(key.usages).toEqual(["encrypt", "decrypt"]);
    });

    it("should generate a wrapping key when requested", async () => {
      const key = await generateAESKey(["wrapKey", "unwrapKey"]);
      expect(key.usages).toEqual(["wrapKey", "unwrapKey"]);
    });

    it("should generate unique keys each time", async () => {
      const key1 = await generateAESKey();
      const key2 = await generateAESKey();
      const raw1 = await crypto.subtle.exportKey("raw", key1);
      const raw2 = await crypto.subtle.exportKey("raw", key2);
      expect(new Uint8Array(raw1)).not.toEqual(new Uint8Array(raw2));
    });
  });

  describe("generateDataKey", () => {
    it("should generate a key with only encrypt/decrypt usages", async () => {
      const key = await generateDataKey();
      expect(key.usages).toEqual(["encrypt", "decrypt"]);
      expect(key.extractable).toBe(true);
    });
  });

  describe("generateWrappingKey", () => {
    it("should generate a key with only wrapKey/unwrapKey usages", async () => {
      const key = await generateWrappingKey();
      expect(key.usages).toEqual(["wrapKey", "unwrapKey"]);
      expect(key.extractable).toBe(true);
    });
  });

  describe("exportKey / importKey", () => {
    it("should roundtrip a data key with default usages", async () => {
      const key = await generateDataKey();
      const exported = await exportKey(key);
      expect(typeof exported).toBe("string");
      expect(exported.length).toBeGreaterThan(0);

      const imported = await importKey(exported);
      expect(imported.type).toBe("secret");
      expect(imported.algorithm.name).toBe("AES-GCM");
      expect(imported.extractable).toBe(false); // imported keys are not extractable by default
      expect(imported.usages).toEqual(["encrypt", "decrypt"]);
    });

    it("should unwrap to an equivalent key", async () => {
      const key = await generateDataKey();
      const exported = await exportKey(key);
      const imported = await importKey(exported);

      // Verify by encryption roundtrip
      const plaintext = new TextEncoder().encode("test");
      const encrypted = await encryptData(plaintext, key);
      const decrypted = await decryptData(encrypted, imported);
      expect(new TextDecoder().decode(decrypted)).toBe("test");
    });

    it("should support extractable import for keys that need wrapping", async () => {
      const key = await generateDataKey();
      const exported = await exportKey(key);

      const imported = await importKey(exported, true);
      expect(imported.extractable).toBe(true);
      expect(imported.usages).toEqual(["encrypt", "decrypt"]);

      // Verify the imported extractable key can be wrapped
      const wrappingKey = await generateWrappingKey();
      const wrapped = await wrapKey(imported, wrappingKey);
      expect(typeof wrapped).toBe("string");
    });

    it("should import wrapping keys with correct usages", async () => {
      const key = await generateWrappingKey();
      const exported = await exportKey(key);
      const imported = await importWrappingKey(exported);
      expect(imported.usages).toEqual(["wrapKey", "unwrapKey"]);
      expect(imported.extractable).toBe(true);
    });

    it("should import PDK with correct usages", async () => {
      const key = await generateAESKey(["encrypt", "wrapKey", "unwrapKey"]);
      const exported = await exportKey(key);
      const imported = await importPDK(exported);
      expect(imported.usages).toEqual(["encrypt", "wrapKey", "unwrapKey"]);
      expect(imported.extractable).toBe(false);
    });
  });

  describe("importDataKey / importWrappingKey / importPDK", () => {
    it("should reject wrapKey operation on a data key", async () => {
      const dataKey = await generateDataKey();
      const targetKey = await generateDataKey();
      await expect(wrapKey(targetKey, dataKey)).rejects.toThrow();
    });

    it("should allow wrapKey operation on a wrapping key", async () => {
      const wrappingKey = await generateWrappingKey();
      const targetKey = await generateDataKey();
      const wrapped = await wrapKey(targetKey, wrappingKey);
      expect(typeof wrapped).toBe("string");
    });

    it("should allow wrapKey operation on a PDK", async () => {
      const pdk = await generateAESKey(["encrypt", "wrapKey", "unwrapKey"]);
      const targetKey = await generateDataKey();
      const wrapped = await wrapKey(targetKey, pdk);
      expect(typeof wrapped).toBe("string");
    });
  });

  describe("generateKeyBase64", () => {
    it("should return a valid base64 string", async () => {
      const keyB64 = await generateKeyBase64();
      expect(typeof keyB64).toBe("string");
      expect(() => atob(keyB64)).not.toThrow();
    });

    it("should be importable as a data key", async () => {
      const keyB64 = await generateKeyBase64();
      const key = await importDataKey(keyB64);
      expect(key.algorithm.name).toBe("AES-GCM");
      expect(key.usages).toEqual(["encrypt", "decrypt"]);
    });

    it("should generate wrapping keys with correct usages", async () => {
      const keyB64 = await generateKeyBase64(["wrapKey", "unwrapKey"]);
      const key = await importWrappingKey(keyB64);
      expect(key.usages).toEqual(["wrapKey", "unwrapKey"]);
    });
  });

  describe("encryptData / decryptData", () => {
    it("should roundtrip plaintext", async () => {
      const key = await generateAESKey();
      const plaintext = new TextEncoder().encode("Hello, World!");
      const encrypted = await encryptData(plaintext, key);

      expect(encrypted.ciphertext).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.authTag).toBeTruthy();

      const decrypted = await decryptData(encrypted, key);
      expect(new TextDecoder().decode(decrypted)).toBe("Hello, World!");
    });

    it("should handle binary data", async () => {
      const key = await generateAESKey();
      const plaintext = crypto.getRandomValues(new Uint8Array(1024));
      const encrypted = await encryptData(plaintext, key);
      const decrypted = await decryptData(encrypted, key);
      expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });

    it("should produce different ciphertexts for same plaintext (IV uniqueness)", async () => {
      const key = await generateAESKey();
      const plaintext = new TextEncoder().encode("same plaintext");
      const encrypted1 = await encryptData(plaintext, key);
      const encrypted2 = await encryptData(plaintext, key);

      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
      expect(encrypted1.authTag).not.toBe(encrypted2.authTag);
    });

    it("should fail decryption with wrong key", async () => {
      const key1 = await generateAESKey();
      const key2 = await generateAESKey();
      const plaintext = new TextEncoder().encode("secret");
      const encrypted = await encryptData(plaintext, key1);

      await expect(decryptData(encrypted, key2)).rejects.toThrow();
    });

    it("should fail decryption with tampered ciphertext", async () => {
      const key = await generateAESKey();
      const plaintext = new TextEncoder().encode("secret");
      const encrypted = await encryptData(plaintext, key);

      // Tamper with ciphertext
      const tamperedCipher = atob(encrypted.ciphertext);
      const tamperedBytes = new Uint8Array(tamperedCipher.split("").map((c) => c.charCodeAt(0)));
      tamperedBytes[0] ^= 0xFF; // Flip bits
      let binary = "";
      for (let i = 0; i < tamperedBytes.length; i++) {
        binary += String.fromCharCode(tamperedBytes[i]);
      }
      encrypted.ciphertext = btoa(binary);

      await expect(decryptData(encrypted, key)).rejects.toThrow();
    });

    it("should fail decryption with wrong authTag", async () => {
      const key = await generateAESKey();
      const plaintext = new TextEncoder().encode("secret");
      const encrypted = await encryptData(plaintext, key);

      const tamperedTag = atob(encrypted.authTag);
      const tagBytes = new Uint8Array(tamperedTag.split("").map((c) => c.charCodeAt(0)));
      tagBytes[0] ^= 0xFF;
      let binary = "";
      for (let i = 0; i < tagBytes.length; i++) {
        binary += String.fromCharCode(tagBytes[i]);
      }
      encrypted.authTag = btoa(binary);

      await expect(decryptData(encrypted, key)).rejects.toThrow();
    });

    it("should handle empty plaintext", async () => {
      const key = await generateAESKey();
      const plaintext = new Uint8Array(0);
      const encrypted = await encryptData(plaintext, key);
      const decrypted = await decryptData(encrypted, key);
      expect(decrypted.byteLength).toBe(0);
    });

    it("should handle large plaintext", async () => {
      const key = await generateAESKey();
      // jsdom's crypto.getRandomValues is limited to 65536 bytes,
      // so we build larger arrays in chunks
      const chunkSize = 65536;
      const totalSize = 256 * 1024; // 256KB
      const plaintext = new Uint8Array(totalSize);
      for (let i = 0; i < totalSize; i += chunkSize) {
        const chunk = crypto.getRandomValues(new Uint8Array(Math.min(chunkSize, totalSize - i)));
        plaintext.set(chunk, i);
      }
      const encrypted = await encryptData(plaintext, key);
      const decrypted = await decryptData(encrypted, key);
      expect(new Uint8Array(decrypted)).toEqual(plaintext);
    });
  });

  describe("encryptString / decryptToString", () => {
    it("should roundtrip a string", async () => {
      const key = await generateAESKey();
      const text = "The quick brown fox jumps over the lazy dog. 🦊";
      const encrypted = await encryptString(text, key);
      const decrypted = await decryptToString(encrypted, key);
      expect(decrypted).toBe(text);
    });

    it("should handle unicode", async () => {
      const key = await generateAESKey();
      const text = "你好世界 🌍 مرحبا بالعالم שלום עולם";
      const encrypted = await encryptString(text, key);
      const decrypted = await decryptToString(encrypted, key);
      expect(decrypted).toBe(text);
    });
  });

  describe("wrapKey / unwrapKey", () => {
    it("should roundtrip a wrapped data key", async () => {
      const wrappingKey = await generateWrappingKey();
      const keyToWrap = await generateDataKey();

      const wrapped = await wrapKey(keyToWrap, wrappingKey);
      expect(typeof wrapped).toBe("string");
      expect(wrapped.length).toBeGreaterThan(0);

      const unwrapped = await unwrapKey(wrapped, wrappingKey);
      expect(unwrapped.algorithm.name).toBe("AES-GCM");
      expect(unwrapped.extractable).toBe(true);
      expect(unwrapped.usages).toEqual(["encrypt", "decrypt"]);
    });

    it("should unwrap a UMK with wrapping key usages", async () => {
      const pdk = await generateAESKey(["encrypt", "wrapKey", "unwrapKey"]);
      const umk = await generateWrappingKey();

      const wrapped = await wrapKey(umk, pdk);
      const unwrapped = await unwrapKey(wrapped, pdk, ["wrapKey", "unwrapKey"]);
      expect(unwrapped.usages).toEqual(["wrapKey", "unwrapKey"]);
    });

    it("should unwrap to an equivalent key", async () => {
      const wrappingKey = await generateWrappingKey();
      const keyToWrap = await generateDataKey();

      const wrapped = await wrapKey(keyToWrap, wrappingKey);
      const unwrapped = await unwrapKey(wrapped, wrappingKey);

      // Verify by encryption roundtrip
      const plaintext = new TextEncoder().encode("wrap test");
      const encrypted = await encryptData(plaintext, keyToWrap);
      const decrypted = await decryptData(encrypted, unwrapped);
      expect(new TextDecoder().decode(decrypted)).toBe("wrap test");
    });

    it("should fail wrapKey when wrapping key lacks wrapKey usage", async () => {
      const dataKey = await generateDataKey(); // lacks wrapKey
      const targetKey = await generateDataKey();
      await expect(wrapKey(targetKey, dataKey)).rejects.toThrow();
    });

    it("should fail unwrap with wrong wrapping key", async () => {
      const wrappingKey1 = await generateWrappingKey();
      const wrappingKey2 = await generateWrappingKey();
      const keyToWrap = await generateDataKey();

      const wrapped = await wrapKey(keyToWrap, wrappingKey1);
      await expect(unwrapKey(wrapped, wrappingKey2)).rejects.toThrow();
    });

    it("should fail unwrap with tampered wrapped key", async () => {
      const wrappingKey = await generateWrappingKey();
      const keyToWrap = await generateDataKey();

      const wrapped = await wrapKey(keyToWrap, wrappingKey);
      const tampered = wrapped.slice(0, -4) + "XXXX";
      await expect(unwrapKey(tampered, wrappingKey)).rejects.toThrow();
    });
  });

  describe("generateSalt", () => {
    it("should generate a base64 string", () => {
      const salt = generateSalt();
      expect(typeof salt).toBe("string");
      expect(() => atob(salt)).not.toThrow();
    });

    it("should generate unique salts", () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      expect(salt1).not.toBe(salt2);
    });

    it("should respect length parameter", () => {
      const salt16 = generateSalt(16);
      const salt32 = generateSalt(32);
      expect(atob(salt16).length).toBe(16);
      expect(atob(salt32).length).toBe(32);
    });
  });

  describe("encryptWithPassphrase / decryptWithPassphrase", () => {
    it("should roundtrip with a passphrase", async () => {
      const passphrase = "correct horse battery staple";
      const data = new TextEncoder().encode("secret data");
      const encrypted = await encryptWithPassphrase(data, passphrase);

      expect(encrypted.ciphertext).toBeTruthy();
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.salt).toBeTruthy();

      const decrypted = await decryptWithPassphrase(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.salt,
        passphrase
      );
      expect(new TextDecoder().decode(decrypted)).toBe("secret data");
    });

    it("should fail with wrong passphrase", async () => {
      const passphrase = "correct horse battery staple";
      const wrongPassphrase = "wrong passphrase";
      const data = new TextEncoder().encode("secret data");
      const encrypted = await encryptWithPassphrase(data, passphrase);

      await expect(
        decryptWithPassphrase(encrypted.ciphertext, encrypted.iv, encrypted.salt, wrongPassphrase)
      ).rejects.toThrow();
    });

    it("should produce different salts for same data", async () => {
      const passphrase = "same passphrase";
      const data = new TextEncoder().encode("same data");
      const encrypted1 = await encryptWithPassphrase(data, passphrase);
      const encrypted2 = await encryptWithPassphrase(data, passphrase);

      expect(encrypted1.salt).not.toBe(encrypted2.salt);
      expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
    });
  });
});
