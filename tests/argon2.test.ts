import { describe, it, expect } from "vitest";
import { deriveKeyPDK, deriveKeyPBKDF2 } from "../src/argon2";

describe("Argon2 Key Derivation", () => {
  describe("deriveKeyPDK (Argon2id)", () => {
    it("should derive a key from password and salt", async () => {
      const key = await deriveKeyPDK({
        pass: "password123",
        salt: "somesaltvalue",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      expect(typeof key).toBe("string");
      expect(key.length).toBeGreaterThan(0);
    });

    it("should derive a 256-bit key by default", async () => {
      const key = await deriveKeyPDK({
        pass: "password",
        salt: "longersalt",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      // base64 of 32 bytes = 44 chars (with padding)
      expect(key.length).toBe(44);
    });

    it("should produce different keys for different passwords", async () => {
      const key1 = await deriveKeyPDK({
        pass: "password1",
        salt: "samesaltvalue",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      const key2 = await deriveKeyPDK({
        pass: "password2",
        salt: "samesaltvalue",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      expect(key1).not.toBe(key2);
    });

    it("should produce different keys for different salts", async () => {
      const key1 = await deriveKeyPDK({
        pass: "samepassword",
        salt: "saltvalue1",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      const key2 = await deriveKeyPDK({
        pass: "samepassword",
        salt: "saltvalue2",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      expect(key1).not.toBe(key2);
    });

    it("should produce the same key for same password+salt", async () => {
      const key1 = await deriveKeyPDK({
        pass: "samepassword",
        salt: "samesaltvalue",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      const key2 = await deriveKeyPDK({
        pass: "samepassword",
        salt: "samesaltvalue",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      expect(key1).toBe(key2);
    });

    it("should support custom hashLen", async () => {
      const key = await deriveKeyPDK({
        pass: "password",
        salt: "longersalt",
        time: 1,
        mem: 1024,
        parallelism: 1,
        hashLen: 16,
      });
      // base64 of 16 bytes = 24 chars (with padding)
      expect(key.length).toBe(24);
    });

    it("should handle unicode passwords", async () => {
      const key = await deriveKeyPDK({
        pass: "пароль 🔐 密码",
        salt: "longersalt",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      expect(typeof key).toBe("string");
      expect(key.length).toBe(44);
    });

    it("should handle minimum-length salt", async () => {
      const key = await deriveKeyPDK({
        pass: "x",
        salt: "8chars!!",
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      expect(typeof key).toBe("string");
      expect(key.length).toBe(44);
    });
  });

  describe("deriveKeyPBKDF2 (fallback)", () => {
    it("should derive a key from password and salt", async () => {
      const key = await deriveKeyPBKDF2("password", "salt");
      expect(typeof key).toBe("string");
      expect(key.length).toBe(44);
    });

    it("should produce different keys for different passwords", async () => {
      const key1 = await deriveKeyPBKDF2("password1", "samesalt");
      const key2 = await deriveKeyPBKDF2("password2", "samesalt");
      expect(key1).not.toBe(key2);
    });

    it("should produce different keys for different salts", async () => {
      const key1 = await deriveKeyPBKDF2("samepassword", "salt1");
      const key2 = await deriveKeyPBKDF2("samepassword", "salt2");
      expect(key1).not.toBe(key2);
    });

    it("should produce the same key for same password+salt", async () => {
      const key1 = await deriveKeyPBKDF2("samepassword", "samesalt");
      const key2 = await deriveKeyPBKDF2("samepassword", "samesalt");
      expect(key1).toBe(key2);
    });

    it("should support custom iteration count", async () => {
      const key = await deriveKeyPBKDF2("password", "salt", 1000);
      expect(typeof key).toBe("string");
      expect(key.length).toBe(44);
    });

    it("should handle unicode passwords", async () => {
      const key = await deriveKeyPBKDF2("пароль 🔐 密码", "salt");
      expect(typeof key).toBe("string");
      expect(key.length).toBe(44);
    });

    it("should handle empty password", async () => {
      const key = await deriveKeyPBKDF2("", "salt");
      expect(typeof key).toBe("string");
      expect(key.length).toBe(44);
    });

    it("should produce different outputs from Argon2 for same input", async () => {
      const pass = "password";
      const salt = "somesalt";
      const argonKey = await deriveKeyPDK({
        pass,
        salt,
        time: 1,
        mem: 1024,
        parallelism: 1,
      });
      const pbkdf2Key = await deriveKeyPBKDF2(pass, salt);
      expect(argonKey).not.toBe(pbkdf2Key);
    });
  });
});
