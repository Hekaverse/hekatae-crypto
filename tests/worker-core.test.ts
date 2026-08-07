import { describe, it, expect, beforeAll } from "vitest";
import { WorkerCryptoCore, handleRequest, type WorkerRequest } from "../src/worker-core";
import {
  importWrappingKey,
  importPDK,
  wrapKey,
  unwrapKey,
  generateDataKey,
  generateKeyBase64,
  generateSalt,
  exportKey,
} from "../src/browser-crypto";
import { deriveKeyPBKDF2 } from "../src/argon2";
import { combineShares } from "../src/shamir";
import { decryptUMK } from "../src/key-derivation";

beforeAll(() => {
  if (!globalThis.crypto?.subtle) {
    throw new Error("WebCrypto API not available in test environment");
  }
});

const PASSWORD = "worker-core-test-password";

describe("WorkerCryptoCore", () => {
  describe("setupUserKeys", () => {
    it("should return setup artifacts but NEVER the raw UMK", async () => {
      const core = new WorkerCryptoCore();
      const result = await core.setupUserKeys(PASSWORD);

      expect(result.encryptedUMK).toBeTruthy();
      expect(result.shareA).toBeTruthy();
      expect(result.shareB).toBeTruthy();
      expect(result.shareC).toBeTruthy();
      expect(result.salt).toBeTruthy();
      expect(result.sentinel).toBeTruthy();

      // The whole point: no raw key material leaves the core.
      expect(result).not.toHaveProperty("umkBase64");
      expect(result).not.toHaveProperty("pdkBase64");
      // And the core holds the UMK afterwards.
      expect(core.hasUMK()).toBe(true);
    });

    it("should produce an encryptedUMK that the classic API can decrypt (interop)", async () => {
      const core = new WorkerCryptoCore();
      const result = await core.setupUserKeys(PASSWORD);
      // The server-stored artifacts must be compatible with the existing
      // synchronous API (mobile + web depend on these formats).
      const umk = await decryptUMK(result.encryptedUMK, PASSWORD, result.salt);
      expect(umk).toBeTruthy();
      expect(() => atob(umk)).not.toThrow();
    });
  });

  describe("unlock", () => {
    it("should unlock with the correct password and resolve to nothing key-like", async () => {
      const core = new WorkerCryptoCore();
      const setup = await core.setupUserKeys(PASSWORD);
      core.lock();
      expect(core.hasUMK()).toBe(false);

      const ret = await core.unlock(setup.encryptedUMK, PASSWORD, setup.salt);
      expect(ret).toBeUndefined();
      expect(core.hasUMK()).toBe(true);
    });

    it("should reject with a wrong password and hold no UMK", async () => {
      // Set up with one core, then try to unlock a FRESH core wrongly.
      const setupCore = new WorkerCryptoCore();
      const setup = await setupCore.setupUserKeys(PASSWORD);

      const core = new WorkerCryptoCore();
      await expect(
        core.unlock(setup.encryptedUMK, "wrong-password", setup.salt)
      ).rejects.toThrow();
      expect(core.hasUMK()).toBe(false);
    });

    it("should keep the existing UMK if a re-unlock attempt fails", async () => {
      const core = new WorkerCryptoCore();
      const setup = await core.setupUserKeys(PASSWORD);
      expect(core.hasUMK()).toBe(true);
      await expect(
        core.unlock(setup.encryptedUMK, "wrong-password", setup.salt)
      ).rejects.toThrow();
      // A failed unlock must not clobber a previously held, valid UMK.
      expect(core.hasUMK()).toBe(true);
    });

    it("should unlock a legacy PBKDF2-wrapped UMK via the second candidate", async () => {
      // Simulate an account whose UMK was wrapped with a PBKDF2-derived PDK
      // (pre-Argon2id or wrapped during a WASM outage).
      const umkBase64 = await generateKeyBase64(["wrapKey", "unwrapKey"]);
      const umkKey = await importWrappingKey(umkBase64);
      const salt = generateSalt(32);
      const legacyPdk = await importPDK(await deriveKeyPBKDF2(PASSWORD, salt));
      const encryptedUMK = await wrapKey(umkKey, legacyPdk);

      const core = new WorkerCryptoCore();
      await core.unlock(encryptedUMK, PASSWORD, salt);
      expect(core.hasUMK()).toBe(true);
      // And the exported UMK matches the originally wrapped key.
      const exported = await core.exportUMK(encryptedUMK, PASSWORD, salt);
      expect(exported).toBe(umkBase64);
    });

    it("should reject a wrong password against a PBKDF2-wrapped UMK", async () => {
      const umkBase64 = await generateKeyBase64(["wrapKey", "unwrapKey"]);
      const umkKey = await importWrappingKey(umkBase64);
      const salt = generateSalt(32);
      const legacyPdk = await importPDK(await deriveKeyPBKDF2(PASSWORD, salt));
      const encryptedUMK = await wrapKey(umkKey, legacyPdk);

      const core = new WorkerCryptoCore();
      await expect(core.unlock(encryptedUMK, "wrong-password", salt)).rejects.toThrow();
      expect(core.hasUMK()).toBe(false);
    });
  });

  describe("encryptBlob / decryptBlob", () => {
    it("should round-trip a blob without any raw key leaving the core", async () => {
      const core = new WorkerCryptoCore();
      const setup = await core.setupUserKeys(PASSWORD);
      expect(setup).not.toHaveProperty("umkBase64");

      const plaintext = new TextEncoder().encode("a very secret legacy message");
      const enc = await core.encryptBlob(
        plaintext.buffer.slice(0) as ArrayBuffer
      );

      expect(enc.ciphertext).toBeInstanceOf(ArrayBuffer);
      expect(enc.iv).toBeTruthy();
      expect(enc.authTag).toBeTruthy();
      expect(enc.encryptedREK).toBeTruthy();
      // No raw REK in the result either.
      expect(enc).not.toHaveProperty("rekBase64");

      const decrypted = await core.decryptBlob(
        enc.ciphertext,
        enc.iv,
        enc.authTag,
        enc.encryptedREK
      );
      expect(new TextDecoder().decode(decrypted)).toBe(
        "a very secret legacy message"
      );
    });

    it("should round-trip with AAD and reject mismatched AAD", async () => {
      const core = new WorkerCryptoCore();
      await core.setupUserKeys(PASSWORD);
      const aad = new TextEncoder().encode("recording:123:STANDARD");
      const plaintext = new TextEncoder().encode("aad-bound plaintext");

      const enc = await core.encryptBlob(plaintext.buffer.slice(0) as ArrayBuffer, aad);
      const ok = await core.decryptBlob(enc.ciphertext, enc.iv, enc.authTag, enc.encryptedREK, aad);
      expect(new TextDecoder().decode(ok)).toBe("aad-bound plaintext");

      const wrongAad = new TextEncoder().encode("recording:999:STANDARD");
      await expect(
        core.decryptBlob(enc.ciphertext, enc.iv, enc.authTag, enc.encryptedREK, wrongAad)
      ).rejects.toThrow();
    });

    it("should reject tampered ciphertext (GCM auth failure)", async () => {
      const core = new WorkerCryptoCore();
      await core.setupUserKeys(PASSWORD);
      const plaintext = new TextEncoder().encode("integrity matters");
      const enc = await core.encryptBlob(plaintext.buffer.slice(0) as ArrayBuffer);

      const tampered = new Uint8Array(enc.ciphertext.slice(0));
      tampered[0] ^= 0xff;
      await expect(
        core.decryptBlob(tampered.buffer as ArrayBuffer, enc.iv, enc.authTag, enc.encryptedREK)
      ).rejects.toThrow();
    });

    it("should reject tampered wrapped REK", async () => {
      const core = new WorkerCryptoCore();
      await core.setupUserKeys(PASSWORD);
      const plaintext = new TextEncoder().encode("rek integrity");
      const enc = await core.encryptBlob(plaintext.buffer.slice(0) as ArrayBuffer);

      const rekBytes = Uint8Array.from(atob(enc.encryptedREK), (c) => c.charCodeAt(0));
      rekBytes[rekBytes.length - 1] ^= 0xff;
      const tamperedREK = btoa(String.fromCharCode(...rekBytes));
      await expect(
        core.decryptBlob(enc.ciphertext, enc.iv, enc.authTag, tamperedREK)
      ).rejects.toThrow();
    });

    it("should reject blob operations before unlock", async () => {
      const core = new WorkerCryptoCore();
      const plaintext = new TextEncoder().encode("x");
      await expect(
        core.encryptBlob(plaintext.buffer.slice(0) as ArrayBuffer)
      ).rejects.toThrow(/not unlocked/);
      await expect(core.wrapREK("AAAA")).rejects.toThrow(/not unlocked/);
      await expect(core.unwrapREK("AAAA")).rejects.toThrow(/not unlocked/);
    });
  });

  describe("wrapREK / unwrapREK", () => {
    it("should wrap a main-thread REK and unwrap it back", async () => {
      const core = new WorkerCryptoCore();
      await core.setupUserKeys(PASSWORD);

      const rek = await generateDataKey();
      const rekBase64 = await exportKey(rek);
      const wrapped = await core.wrapREK(rekBase64);
      expect(wrapped).toBeTruthy();

      const unwrapped = await core.unwrapREK(wrapped);
      expect(unwrapped).toBe(rekBase64);
    });

    it("should produce wrapped REKs compatible with the classic API", async () => {
      const core = new WorkerCryptoCore();
      const setup = await core.setupUserKeys(PASSWORD);
      const umkBase64 = await core.exportUMK(setup.encryptedUMK, PASSWORD, setup.salt);

      const rek = await generateDataKey();
      const rekBase64 = await exportKey(rek);
      const wrapped = await core.wrapREK(rekBase64);

      // Classic main-thread path can unwrap what the worker wrapped.
      const umkKey = await importWrappingKey(umkBase64);
      const unwrapped = await unwrapKey(wrapped, umkKey);
      expect(await exportKey(unwrapped)).toBe(rekBase64);
    });
  });

  describe("generateRecoveryShares", () => {
    it("should generate shares that reconstruct the same UMK", async () => {
      const core = new WorkerCryptoCore();
      const setup = await core.setupUserKeys(PASSWORD);
      const umkBase64 = await core.exportUMK(setup.encryptedUMK, PASSWORD, setup.salt);

      const shares = await core.generateRecoveryShares(
        setup.encryptedUMK,
        PASSWORD,
        setup.salt
      );
      const reconstructed = await combineShares([shares.shareB, shares.shareC]);
      const reconstructedB64 = btoa(String.fromCharCode(...reconstructed));
      expect(reconstructedB64).toBe(umkBase64);
    });
  });

  describe("exportUMK (documented escape hatch)", () => {
    it("should export the same UMK the classic decryptUMK returns", async () => {
      const core = new WorkerCryptoCore();
      const setup = await core.setupUserKeys(PASSWORD);
      const fromWorker = await core.exportUMK(setup.encryptedUMK, PASSWORD, setup.salt);
      const fromClassic = await decryptUMK(setup.encryptedUMK, PASSWORD, setup.salt);
      expect(fromWorker).toBe(fromClassic);
    });
  });

  describe("destroy", () => {
    it("should drop the held UMK", async () => {
      const core = new WorkerCryptoCore();
      await core.setupUserKeys(PASSWORD);
      expect(core.hasUMK()).toBe(true);
      core.destroy();
      expect(core.hasUMK()).toBe(false);
    });
  });
});

describe("handleRequest dispatch", () => {
  it("should dispatch ops and correlate by request shape", async () => {
    const core = new WorkerCryptoCore();
    const setup = (await handleRequest(core, {
      id: 1,
      op: "setupUserKeys",
      password: PASSWORD,
    })) as { encryptedUMK: string; salt: string };
    expect(setup.encryptedUMK).toBeTruthy();

    expect(await handleRequest(core, { id: 2, op: "hasUMK" })).toBe(true);
    await handleRequest(core, { id: 3, op: "lock" });
    expect(await handleRequest(core, { id: 4, op: "hasUMK" })).toBe(false);
    await handleRequest(core, {
      id: 5,
      op: "unlock",
      encryptedUMK: setup.encryptedUMK,
      password: PASSWORD,
      salt: setup.salt,
    });
    expect(await handleRequest(core, { id: 6, op: "hasUMK" })).toBe(true);
    await handleRequest(core, { id: 7, op: "destroy" });
    expect(await handleRequest(core, { id: 8, op: "hasUMK" })).toBe(false);
  });

  it("should throw on an unknown op", async () => {
    const core = new WorkerCryptoCore();
    await expect(
      handleRequest(core, { id: 1, op: "nope" } as unknown as WorkerRequest)
    ).rejects.toThrow(/Unknown worker op/);
  });
});
