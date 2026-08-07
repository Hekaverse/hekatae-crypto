import { describe, it, expect, beforeAll } from "vitest";
import {
  setupUserKeys,
  decryptUMK,
  reconstructUMKFromShares,
  generateRecoveryShares,
  decryptShare,
} from "../src/key-derivation";
import {
  importPDK,
  importWrappingKey,
  generateAESKey,
  generateKeyBase64,
  generateSalt,
  wrapKey,
} from "../src/browser-crypto";
import { deriveKeyPDK, deriveKeyPBKDF2 } from "../src/argon2";

// Ensure crypto.subtle is available
beforeAll(() => {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto API not available in test environment");
  }
});

async function derivePdkForTest(password: string, salt: string) {
  return deriveKeyPDK({
    pass: password,
    salt,
  });
}

describe("Key Derivation (UMK / PDK)", () => {
  describe("setupUserKeys", () => {
    it("should generate all required key material including sentinel", async () => {
      const result = await setupUserKeys("my-password");
      expect(result.umkBase64).toBeTruthy();
      expect(result.encryptedUMK).toBeTruthy();
      expect(result.shareA).toBeTruthy();
      expect(result.shareB).toBeTruthy();
      expect(result.shareC).toBeTruthy();
      expect(result.salt).toBeTruthy();
      expect(result.sentinel).toBeTruthy();
    });

    it("should generate unique material each call", async () => {
      const r1 = await setupUserKeys("password");
      const r2 = await setupUserKeys("password");
      expect(r1.umkBase64).not.toBe(r2.umkBase64);
      expect(r1.salt).not.toBe(r2.salt);
      expect(r1.encryptedUMK).not.toBe(r2.encryptedUMK);
    });

    it("should generate valid base64 strings", async () => {
      const result = await setupUserKeys("password");
      expect(() => atob(result.umkBase64)).not.toThrow();
      expect(() => atob(result.encryptedUMK)).not.toThrow();
      expect(() => atob(result.shareA)).not.toThrow();
      expect(() => atob(result.shareB)).not.toThrow();
      expect(() => atob(result.shareC)).not.toThrow();
      expect(() => atob(result.salt)).not.toThrow();
    });

    it("should produce 32-byte UMK", async () => {
      const result = await setupUserKeys("password");
      expect(atob(result.umkBase64).length).toBe(32);
    });

    it("should reject an empty password (no silent PBKDF2 downgrade)", async () => {
      // hash-wasm rejects empty passwords with a validation error. Before the
      // KDF-fallback fix, this silently wrapped the account with PBKDF2 —
      // exactly the undetectable downgrade F1 removes. Empty passwords are
      // now refused instead of silently changing algorithms.
      await expect(setupUserKeys("")).rejects.toThrow();
    });

    it("should handle unicode password", async () => {
      const result = await setupUserKeys("пароль 🔐 密码");
      expect(result.umkBase64).toBeTruthy();
      expect(result.encryptedUMK).toBeTruthy();
    });
  });

  describe("decryptUMK", () => {
    it("should roundtrip encrypt/decrypt UMK", async () => {
      const setup = await setupUserKeys("my-password");
      const decrypted = await decryptUMK(setup.encryptedUMK, "my-password", setup.salt);
      expect(decrypted).toBe(setup.umkBase64);
    });

    it("should fail with wrong password", async () => {
      const setup = await setupUserKeys("correct-password");
      await expect(decryptUMK(setup.encryptedUMK, "wrong-password", setup.salt)).rejects.toThrow();
    });

    it("should fail with wrong salt", async () => {
      const setup = await setupUserKeys("password");
      await expect(decryptUMK(setup.encryptedUMK, "password", "wrong-salt")).rejects.toThrow();
    });
  });

  describe("KDF interop (legacy PBKDF2-wrapped accounts)", () => {
    /** Wrap a UMK with the PBKDF2-derived PDK, as pre-Argon2id accounts did. */
    async function wrapWithPBKDF2(password: string) {
      const umkBase64 = await generateKeyBase64(["wrapKey", "unwrapKey"]);
      const umkKey = await importWrappingKey(umkBase64);
      const salt = generateSalt(32);
      const pdkKey = await importPDK(await deriveKeyPBKDF2(password, salt));
      const encryptedUMK = await wrapKey(umkKey, pdkKey);
      return { umkBase64, encryptedUMK, salt };
    }

    it("decrypts a PBKDF2-wrapped UMK via the normal path", async () => {
      const { umkBase64, encryptedUMK, salt } = await wrapWithPBKDF2("legacy-password");
      const decrypted = await decryptUMK(encryptedUMK, "legacy-password", salt);
      expect(decrypted).toBe(umkBase64);
    });

    it("flags the legacy-candidate success via the injected logger", async () => {
      const { encryptedUMK, salt } = await wrapWithPBKDF2("legacy-password");
      const messages: string[] = [];
      await decryptUMK(encryptedUMK, "legacy-password", salt, (m) => messages.push(m));
      expect(messages.some((m) => m.includes("PBKDF2"))).toBe(true);
    });

    it("still rejects a wrong password against a PBKDF2-wrapped UMK", async () => {
      const { encryptedUMK, salt } = await wrapWithPBKDF2("legacy-password");
      await expect(decryptUMK(encryptedUMK, "wrong-password", salt)).rejects.toThrow();
    });

    it("still decrypts an Argon2id-wrapped UMK without invoking the logger", async () => {
      const setup = await setupUserKeys("modern-password");
      const messages: string[] = [];
      const decrypted = await decryptUMK(
        setup.encryptedUMK,
        "modern-password",
        setup.salt,
        (m) => messages.push(m)
      );
      expect(decrypted).toBe(setup.umkBase64);
      expect(messages).toHaveLength(0);
    });
  });

  describe("reconstructUMKFromShares", () => {
    it("should reconstruct UMK from shareB and shareC", async () => {
      const setup = await setupUserKeys("password");
      const reconstructed = await reconstructUMKFromShares(setup.shareB, setup.shareC);
      expect(reconstructed).toBe(setup.umkBase64);
    });

    it("should verify sentinel and succeed with valid shares", async () => {
      const setup = await setupUserKeys("password");
      const reconstructed = await reconstructUMKFromShares(
        setup.shareB,
        setup.shareC,
        setup.sentinel
      );
      expect(reconstructed).toBe(setup.umkBase64);
    });

    it("should throw when sentinel verification fails (tampered shares)", async () => {
      const setup = await setupUserKeys("password");
      // Tamper a payload byte, NOT the tail: the last share byte is the
      // x-coordinate, and corrupting it can trip the library's duplicate-x
      // guard before sentinel verification (flaky). Middle bytes always
      // reach the sentinel check.
      const tampered = "A" + setup.shareB.slice(1);
      await expect(
        reconstructUMKFromShares(setup.shareC, tampered, setup.sentinel)
      ).rejects.toThrow("Share verification failed");
    });

    it("should work without sentinel for backward compatibility", async () => {
      const setup = await setupUserKeys("password");
      const reconstructed = await reconstructUMKFromShares(setup.shareB, setup.shareC);
      expect(reconstructed).toBe(setup.umkBase64);
    });
  });

  describe("generateRecoveryShares", () => {
    it("should generate new shares from existing UMK", async () => {
      const setup = await setupUserKeys("password");
      const pdkBase64 = await derivePdkForTest("password", setup.salt);
      const pdkKey = await importPDK(pdkBase64);
      const recovery = await generateRecoveryShares(setup.umkBase64, pdkKey);
      expect(recovery.shareA).toBeTruthy();
      expect(recovery.shareB).toBeTruthy();
      expect(recovery.shareC).toBeTruthy();
    });

    it("should reconstruct UMK from recovery shares", async () => {
      const setup = await setupUserKeys("password");
      const pdkBase64 = await derivePdkForTest("password", setup.salt);
      const pdkKey = await importPDK(pdkBase64);
      const recovery = await generateRecoveryShares(setup.umkBase64, pdkKey);
      const reconstructed = await reconstructUMKFromShares(recovery.shareB, recovery.shareC);
      expect(reconstructed).toBe(setup.umkBase64);
    });

    it("should generate different shares than original", async () => {
      const setup = await setupUserKeys("password");
      const pdkBase64 = await derivePdkForTest("password", setup.salt);
      const pdkKey = await importPDK(pdkBase64);
      const recovery = await generateRecoveryShares(setup.umkBase64, pdkKey);
      // New shares will be different due to randomness in SSS
      expect(recovery.shareA).not.toBe(setup.shareA);
      expect(recovery.shareB).not.toBe(setup.shareB);
      expect(recovery.shareC).not.toBe(setup.shareC);
    });
  });

  describe("decryptShare", () => {
    it("should roundtrip encrypt/decrypt a share", async () => {
      // decryptShare requires a key with decrypt usage
      const key = await generateAESKey(["encrypt", "decrypt"]);
      const share = "test-share-data";
      const encrypted = await encryptShareForTest(share, key);
      const decrypted = await decryptShare(encrypted, key);
      // decryptShare returns base64 of the decrypted bytes
      expect(decrypted).toBe(btoa(share));
    });

    it("should fail with wrong key", async () => {
      const key1 = await generateAESKey(["encrypt", "decrypt"]);
      const key2 = await generateAESKey(["encrypt", "decrypt"]);
      const share = "test-share-data";
      const encrypted = await encryptShareForTest(share, key1);
      await expect(decryptShare(encrypted, key2)).rejects.toThrow();
    });

    it("should fail with tampered share", async () => {
      const key = await generateAESKey(["encrypt", "decrypt"]);
      const share = "test-share-data";
      const encrypted = await encryptShareForTest(share, key);
      const tampered = encrypted.slice(0, -4) + "XXXX";
      await expect(decryptShare(tampered, key)).rejects.toThrow();
    });
  });
});

async function encryptShareForTest(plaintext: string, key: CryptoKey): Promise<string> {
  const bytes = new TextEncoder().encode(plaintext);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bytes);
  const full = new Uint8Array(iv.length + encrypted.byteLength);
  full.set(iv, 0);
  full.set(new Uint8Array(encrypted), iv.length);
  let binary = "";
  for (let i = 0; i < full.length; i++) {
    binary += String.fromCharCode(full[i]);
  }
  return btoa(binary);
}
