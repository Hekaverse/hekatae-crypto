import { describe, it, expect } from "vitest";
import {
  generateAESKey,
  generateDataKey,
  generateWrappingKey,
  exportKey,
  importKey,
  importDataKey,
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
import {
  generateContentKey,
  splitContentKey,
  reconstructContentKey,
  evaluateContract,
  getRequiredDimensions,
  CONTRACT_DIMENSIONS,
  type DeliveryContract,
} from "../src/trust-lattice";

/**
 * Property-Based Crypto Tests
 *
 * Instead of testing specific inputs, we test INVARIANTS that must hold
 * for ALL inputs. We verify these invariants with many random iterations.
 *
 * Invariants tested:
 *   1. encrypt(decrypt(x)) === x  (roundtrip)
 *   2. encrypt(x) !== encrypt(x)  (IV uniqueness)
 *   3. decrypt with wrong key fails (confidentiality)
 *   4. Any subset below threshold cannot reconstruct (threshold security)
 *   5. Key generation produces unique keys (no collisions)
 */

// ─── Helpers for generating random data ───

function randomBytes(size: number): Uint8Array {
  // jsdom limits getRandomValues to 65536 bytes per call
  const result = new Uint8Array(size);
  const chunkSize = 65536;
  for (let i = 0; i < size; i += chunkSize) {
    const chunk = crypto.getRandomValues(new Uint8Array(Math.min(chunkSize, size - i)));
    result.set(chunk, i);
  }
  return result;
}

function randomString(minLen: number, maxLen: number): string {
  const length = Math.floor(Math.random() * (maxLen - minLen + 1)) + minLen;
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function randomUnicodeString(length: number): string {
  // Mix of ASCII, BMP, and supplementary characters
  const ranges = [
    [0x0020, 0x007f], // ASCII
    [0x00a0, 0x00ff], // Latin-1 supplement
    [0x0400, 0x04ff], // Cyrillic
    [0x4e00, 0x9fff], // CJK
    [0x1f600, 0x1f64f], // Emoji
  ];
  let result = "";
  for (let i = 0; i < length; i++) {
    const range = ranges[Math.floor(Math.random() * ranges.length)];
    const codePoint = Math.floor(Math.random() * (range[1] - range[0] + 1)) + range[0];
    result += String.fromCodePoint(codePoint);
  }
  return result;
}

// ─── Property 1: Encryption Roundtrip ───

describe("Property: encrypt(decrypt(x)) === x", () => {
  it("should roundtrip random plaintexts of varying sizes", async () => {
    const key = await generateAESKey();
    const sizes = [0, 1, 16, 100, 1024, 65536, 131072, 262144]; // 0B to 256KB

    for (const size of sizes) {
      const plaintext = randomBytes(size);
      const encrypted = await encryptData(plaintext, key);
      const decrypted = await decryptData(encrypted, key);
      expect(new Uint8Array(decrypted)).toEqual(plaintext);
    }
  });

  it("should roundtrip random strings with unicode", async () => {
    const key = await generateAESKey();

    for (let i = 0; i < 50; i++) {
      const text = randomUnicodeString(Math.floor(Math.random() * 500) + 1);
      const encrypted = await encryptString(text, key);
      const decrypted = await decryptToString(encrypted, key);
      expect(decrypted).toBe(text);
    }
  });

  it("should roundtrip with freshly generated keys each time", async () => {
    for (let i = 0; i < 20; i++) {
      const key = await generateAESKey();
      const plaintext = randomBytes(Math.floor(Math.random() * 4096) + 1);
      const encrypted = await encryptData(plaintext, key);
      const decrypted = await decryptData(encrypted, key);
      expect(new Uint8Array(decrypted)).toEqual(plaintext);
    }
  });
});

// ─── Property 2: IV Uniqueness (No Two Ciphertexts Are Identical) ───

describe("Property: encrypt(x) !== encrypt(x) — IV uniqueness", () => {
  it("should never produce identical ciphertexts for the same plaintext", async () => {
    const key = await generateAESKey();
    const plaintext = randomBytes(1024);

    const ciphertexts = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const encrypted = await encryptData(plaintext, key);
      const combined = encrypted.ciphertext + encrypted.iv + encrypted.authTag;
      expect(ciphertexts.has(combined)).toBe(false);
      ciphertexts.add(combined);
    }
  });

  it("should have unique IVs across 100 encryptions", async () => {
    const key = await generateAESKey();
    const ivs = new Set<string>();

    for (let i = 0; i < 100; i++) {
      const plaintext = randomBytes(100);
      const encrypted = await encryptData(plaintext, key);
      expect(ivs.has(encrypted.iv)).toBe(false);
      ivs.add(encrypted.iv);
    }
  });
});

// ─── Property 3: Wrong Key Rejects Decryption ───

describe("Property: decrypt with wrong key fails", () => {
  it("should reject decryption with a different key", async () => {
    const key1 = await generateAESKey();
    const key2 = await generateAESKey();

    for (let i = 0; i < 20; i++) {
      const plaintext = randomBytes(Math.floor(Math.random() * 4096) + 1);
      const encrypted = await encryptData(plaintext, key1);
      await expect(decryptData(encrypted, key2)).rejects.toThrow();
    }
  });

  it("should reject decryption with tampered ciphertext (single bit flip)", async () => {
    const key = await generateAESKey();

    for (let i = 0; i < 20; i++) {
      const plaintext = randomBytes(Math.floor(Math.random() * 4096) + 50);
      const encrypted = await encryptData(plaintext, key);

      // Flip a random bit in ciphertext
      const cipherBytes = new Uint8Array(atob(encrypted.ciphertext).split("").map((c) => c.charCodeAt(0)));
      const flipPos = Math.floor(Math.random() * cipherBytes.length);
      cipherBytes[flipPos] ^= 0x01;
      const tamperedCipher = btoa(String.fromCharCode(...cipherBytes));

      await expect(
        decryptData({ ...encrypted, ciphertext: tamperedCipher }, key)
      ).rejects.toThrow();
    }
  });

  it("should reject decryption with tampered IV", async () => {
    const key = await generateAESKey();
    const plaintext = randomBytes(100);
    const encrypted = await encryptData(plaintext, key);

    // Flip a bit in IV
    const ivBytes = new Uint8Array(atob(encrypted.iv).split("").map((c) => c.charCodeAt(0)));
    ivBytes[0] ^= 0xFF;
    const tamperedIv = btoa(String.fromCharCode(...ivBytes));

    await expect(decryptData({ ...encrypted, iv: tamperedIv }, key)).rejects.toThrow();
  });
});

// ─── Property 4: Trust Lattice Threshold Security ───

describe("Property: Any subset below threshold cannot reconstruct", () => {
  const ALL_CONTRACTS: DeliveryContract[] = ["SIMPLE", "STANDARD", "SECURE", "PARANOID"];

  it.each(ALL_CONTRACTS.filter((c) => getRequiredDimensions(c).length > 2))(
    "should produce a different key when reconstructing %s with insufficient shares",
    async (contract) => {
      const ck = await generateContentKey();
      const { shares } = await splitContentKey(ck, contract);
      const threshold = getRequiredDimensions(contract).length;

      // With insufficient shares, reconstruction returns a different key (not the original)
      const subset = shares.slice(0, threshold - 1).map((s) => s.share);
      const reconstructed = await reconstructContentKey(subset);

      // Verify it's a valid key but different from original
      expect(reconstructed.type).toBe("secret");

      // It should NOT decrypt correctly with the original key's ciphertext
      const plaintext = randomBytes(100);
      const encrypted = await encryptData(plaintext, ck);

      // Decrypting with wrong key should fail (auth tag mismatch)
      await expect(decryptData(encrypted, reconstructed)).rejects.toThrow();
    }
  );

  it.each(ALL_CONTRACTS)(
    "should succeed to reconstruct %s with threshold or more shares",
    async (contract) => {
      const ck = await generateContentKey();
      const { shares } = await splitContentKey(ck, contract);
      const threshold = getRequiredDimensions(contract).length;

      // Pick threshold shares (minimum needed)
      const subset = shares.slice(0, threshold).map((s) => s.share);
      const reconstructed = await reconstructContentKey(subset);
      expect(reconstructed.type).toBe("secret");

      // Verify it can decrypt
      const plaintext = randomBytes(100);
      const encrypted = await encryptData(plaintext, ck);
      const decrypted = await decryptData(encrypted, reconstructed);
      expect(new Uint8Array(decrypted)).toEqual(plaintext);
    }
  );
});

// ─── Property 5: Key Generation Uniqueness ───

describe("Property: Key generation produces unique keys", () => {
  it("should never produce duplicate AES keys", async () => {
    const keys = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const key = await generateAESKey();
      const exported = await exportKey(key);
      expect(keys.has(exported)).toBe(false);
      keys.add(exported);
    }
  });

  it("should never produce duplicate content keys for Trust Lattice", async () => {
    const keys = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const key = await generateContentKey();
      const exported = await crypto.subtle.exportKey("raw", key);
      const hex = Array.from(new Uint8Array(exported))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      expect(keys.has(hex)).toBe(false);
      keys.add(hex);
    }
  });
});

// ─── Property 6: Salt Uniqueness ───

describe("Property: Salts are unique", () => {
  it("should never produce duplicate salts", () => {
    const salts = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const salt = generateSalt();
      expect(salts.has(salt)).toBe(false);
      salts.add(salt);
    }
  });
});

// ─── Property 7: Passphrase Encryption ───

describe("Property: Passphrase encryption roundtrips with random inputs", () => {
  it("should roundtrip with random passphrases and data", async () => {
    for (let i = 0; i < 20; i++) {
      const passphrase = randomString(8, 64);
      const dataSize = Math.floor(Math.random() * 4096) + 1;
      const data = randomBytes(dataSize);

      const encrypted = await encryptWithPassphrase(data, passphrase);
      const decrypted = await decryptWithPassphrase(
        encrypted.ciphertext,
        encrypted.iv,
        encrypted.salt,
        passphrase
      );
      expect(new Uint8Array(decrypted)).toEqual(data);
    }
  });

  it("should produce different ciphertexts for same data + passphrase (salt uniqueness)", async () => {
    const passphrase = "test passphrase";
    const data = randomBytes(100);

    const encrypted1 = await encryptWithPassphrase(data, passphrase);
    const encrypted2 = await encryptWithPassphrase(data, passphrase);

    expect(encrypted1.salt).not.toBe(encrypted2.salt);
    expect(encrypted1.ciphertext).not.toBe(encrypted2.ciphertext);
  });
});

// ─── Property 8: Wrap/Unwrap Roundtrip ───

describe("Property: wrap(unwrap(x)) === x", () => {
  it("should roundtrip wrapped keys with random wrapping keys", async () => {
    for (let i = 0; i < 20; i++) {
      const wrappingKey = await generateWrappingKey();
      const keyToWrap = await generateDataKey();

      const wrapped = await wrapKey(keyToWrap, wrappingKey);
      const unwrapped = await unwrapKey(wrapped, wrappingKey);

      // Verify functional equivalence by encryption roundtrip
      const plaintext = randomBytes(100);
      const encrypted = await encryptData(plaintext, keyToWrap);
      const decrypted = await decryptData(encrypted, unwrapped);
      expect(new Uint8Array(decrypted)).toEqual(plaintext);
    }
  });
});

// ─── Property 9: Contract Evaluation Invariants ───

describe("Property: Contract evaluation invariants", () => {
  const ALL_CONTRACTS: DeliveryContract[] = ["SIMPLE", "STANDARD", "SECURE", "PARANOID"];

  it.each(ALL_CONTRACTS)(
    "should require exactly %s threshold dimensions",
    (contract) => {
      const required = getRequiredDimensions(contract);
      const threshold = required.length;

      // All required dimensions present → true
      expect(evaluateContract(contract, required)).toBe(true);

      // All required + extras → true
      const extra = [...required, "FAMILY"];
      expect(evaluateContract(contract, extra)).toBe(true);

      // Missing one → false
      if (threshold > 1) {
        const missingOne = required.slice(1);
        expect(evaluateContract(contract, missingOne)).toBe(false);
      }

      // Empty → false
      expect(evaluateContract(contract, [])).toBe(false);
    }
  );
});

// ─── Property 10: Deterministic Contract Dimensions ───

describe("Property: Contract dimensions are deterministic", () => {
  it("should return the same dimensions for the same contract every time", () => {
    for (let i = 0; i < 10; i++) {
      expect(getRequiredDimensions("SIMPLE")).toEqual(["TIME", "SERVER"]);
      expect(getRequiredDimensions("STANDARD")).toEqual(["TIME", "IDENTITY", "SERVER"]);
      expect(getRequiredDimensions("SECURE")).toEqual(["TIME", "IDENTITY", "SERVER", "CONSENT"]);
      expect(getRequiredDimensions("PARANOID")).toEqual([
        "TIME",
        "IDENTITY",
        "SERVER",
        "PHYSICAL",
        "CONSENT",
      ]);
    }
  });
});
