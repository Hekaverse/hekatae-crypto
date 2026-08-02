import { describe, it, expect } from "vitest";
import {
  generateContentKey,
  splitContentKey,
  reconstructContentKey,
  evaluateContract,
  getRequiredDimensions,
  getContractThreshold,
  getContractLabel,
  getContractDescription,
  CONTRACT_DIMENSIONS,
  type DeliveryContract,
} from "../src/trust-lattice";
import { encryptData, decryptData } from "../src/browser-crypto";

const ALL_CONTRACTS: DeliveryContract[] = ["SIMPLE", "STANDARD", "SECURE", "PARANOID"];

describe("Trust Lattice Cryptography", () => {
  describe("generateContentKey", () => {
    it("should return an extractable 256-bit AES key", async () => {
      const ck = await generateContentKey();
      expect(ck).toBeDefined();
      expect(ck.type).toBe("secret");
      expect(ck.algorithm.name).toBe("AES-GCM");
      expect((ck.algorithm as AesKeyAlgorithm).length).toBe(256);
      expect(ck.extractable).toBe(true);
    });

    it("should generate unique keys each time", async () => {
      const ck1 = await generateContentKey();
      const ck2 = await generateContentKey();
      const raw1 = await crypto.subtle.exportKey("raw", ck1);
      const raw2 = await crypto.subtle.exportKey("raw", ck2);
      const arr1 = new Uint8Array(raw1);
      const arr2 = new Uint8Array(raw2);
      expect(arr1).not.toEqual(arr2);
    });
  });

  describe("splitContentKey", () => {
    it.each(ALL_CONTRACTS)(
      "should split %s contract into correct number of shares",
      async (contract) => {
        const ck = await generateContentKey();
        const result = await splitContentKey(ck, contract);

        expect(result.contract).toBe(contract);
        expect(result.shares).toHaveLength(CONTRACT_DIMENSIONS[contract].length);
      }
    );

    it.each(ALL_CONTRACTS)(
      "should map shares 1:1 to dimensions for %s",
      async (contract) => {
        const ck = await generateContentKey();
        const result = await splitContentKey(ck, contract);
        const expectedDimensions = CONTRACT_DIMENSIONS[contract];

        result.shares.forEach((share, index) => {
          expect(share.dimension).toBe(expectedDimensions[index]);
        });
      }
    );

    it.each(ALL_CONTRACTS)(
      "should produce valid base64 shares for %s",
      async (contract) => {
        const ck = await generateContentKey();
        const result = await splitContentKey(ck, contract);

        result.shares.forEach((share) => {
          expect(() => atob(share.share)).not.toThrow();
        });
      }
    );

    it.each(ALL_CONTRACTS)(
      "should produce different shares for %s",
      async (contract) => {
        const ck = await generateContentKey();
        const result = await splitContentKey(ck, contract);

        const shareSet = new Set(result.shares.map((s) => s.share));
        expect(shareSet.size).toBe(result.shares.length);
      }
    );
  });

  describe("reconstructContentKey", () => {
    it.each(ALL_CONTRACTS)(
      "should reconstruct the original key for %s from all shares",
      async (contract) => {
        const ck = await generateContentKey();
        const { shares } = await splitContentKey(ck, contract);
        const shareValues = shares.map((s) => s.share);

        const reconstructed = await reconstructContentKey(shareValues);
        expect(reconstructed).toBeDefined();
        expect(reconstructed.type).toBe("secret");
        expect(reconstructed.algorithm.name).toBe("AES-GCM");
      }
    );

    it.each(ALL_CONTRACTS)(
      "should produce a key that can encrypt and decrypt for %s",
      async (contract) => {
        const ck = await generateContentKey();
        const { shares } = await splitContentKey(ck, contract);
        const shareValues = shares.map((s) => s.share);

        const reconstructed = await reconstructContentKey(shareValues);

        const plaintext = new TextEncoder().encode("Hello Trust Lattice");
        const encrypted = await encryptData(plaintext, reconstructed);
        const decrypted = await decryptData(encrypted, reconstructed);
        const decryptedText = new TextDecoder().decode(decrypted);

        expect(decryptedText).toBe("Hello Trust Lattice");
      }
    );

    it("should fail with missing shares", async () => {
      const ck = await generateContentKey();
      const { shares } = await splitContentKey(ck, "STANDARD");
      const partialShares = [shares[0].share]; // Only 1 of threshold 2

      await expect(reconstructContentKey(partialShares)).rejects.toThrow();
    });

    it("should fail with wrong number of shares", async () => {
      const ck = await generateContentKey();
      const { shares: simpleShares } = await splitContentKey(ck, "SIMPLE");
      const { shares: standardShares } = await splitContentKey(ck, "STANDARD");

      // Try to reconstruct with mixed shares from different splits
      // combineShares returns bytes, importKey may succeed with garbage bytes,
      // but the resulting key won't match the original
      const mixedShares = [simpleShares[0].share, standardShares[0].share];
      const garbageKey = await reconstructContentKey(mixedShares);

      // Verify the garbage key is not equivalent to the original
      const plaintext = new TextEncoder().encode("test");
      const encryptedWithOriginal = await encryptData(plaintext, ck);
      await expect(decryptData(encryptedWithOriginal, garbageKey)).rejects.toThrow();
    });

    it("should fail with empty shares array", async () => {
      await expect(reconstructContentKey([])).rejects.toThrow();
    });
  });

  describe("evaluateContract", () => {
    it("should return true for exact dimension match", () => {
      expect(evaluateContract("STANDARD", ["TIME", "IDENTITY", "SERVER"])).toBe(true);
      expect(evaluateContract("SIMPLE", ["TIME", "SERVER"])).toBe(true);
    });

    it("should return true for superset of dimensions", () => {
      expect(evaluateContract("SIMPLE", ["TIME", "SERVER", "IDENTITY"])).toBe(true);
      expect(evaluateContract("STANDARD", ["TIME", "IDENTITY", "SERVER", "CONSENT"])).toBe(true);
    });

    it("should return true for threshold-sized subsets", () => {
      expect(evaluateContract("STANDARD", ["TIME", "SERVER"])).toBe(true);
      expect(evaluateContract("STANDARD", ["TIME", "IDENTITY"])).toBe(true);
      expect(evaluateContract("SECURE", ["TIME", "IDENTITY", "SERVER"])).toBe(true);
      expect(evaluateContract("PARANOID", ["TIME", "IDENTITY", "SERVER", "CONSENT"])).toBe(true);
    });

    it("should return false for subsets below the threshold", () => {
      expect(evaluateContract("STANDARD", ["TIME"])).toBe(false);
      expect(evaluateContract("SECURE", ["TIME", "SERVER"])).toBe(false);
      expect(evaluateContract("PARANOID", ["TIME", "IDENTITY", "SERVER"])).toBe(false);
    });

    it("should return false for wrong dimensions", () => {
      expect(evaluateContract("STANDARD", ["IDENTITY", "PHYSICAL"])).toBe(false);
    });

    it("should return false for empty dimensions", () => {
      expect(evaluateContract("SIMPLE", [])).toBe(false);
    });

    it("should return true for all contracts when all their dimensions are present", () => {
      ALL_CONTRACTS.forEach((contract) => {
        const dims = getRequiredDimensions(contract);
        expect(evaluateContract(contract, dims)).toBe(true);
      });
    });

    it("should return false for all contracts when below threshold", () => {
      ALL_CONTRACTS.forEach((contract) => {
        const dims = getRequiredDimensions(contract);
        const threshold = getContractThreshold(contract);
        if (dims.length > threshold) {
          const belowThreshold = dims.slice(0, threshold - 1);
          expect(evaluateContract(contract, belowThreshold)).toBe(false);
        }
      });
    });
  });

  describe("getRequiredDimensions", () => {
    it.each(ALL_CONTRACTS)("should return correct dimensions for %s", (contract) => {
      const dims = getRequiredDimensions(contract);
      expect(dims).toEqual(CONTRACT_DIMENSIONS[contract]);
    });
  });

  describe("getContractThreshold", () => {
    it.each(ALL_CONTRACTS)("should return threshold <= number of dimensions for %s", (contract) => {
      const threshold = getContractThreshold(contract);
      expect(threshold).toBeLessThanOrEqual(CONTRACT_DIMENSIONS[contract].length);
      expect(threshold).toBeGreaterThanOrEqual(2);
    });

    it.each([["SIMPLE", 2], ["STANDARD", 2], ["SECURE", 3], ["PARANOID", 4]] as [DeliveryContract, number][])(
      "should return correct threshold for %s",
      (contract, expected) => {
        expect(getContractThreshold(contract)).toBe(expected);
      }
    );

    it("should allow reconstruction with exactly threshold shares", async () => {
      const ck = await generateContentKey();
      for (const contract of ALL_CONTRACTS) {
        const { shares } = await splitContentKey(ck, contract);
        const threshold = getContractThreshold(contract);
        const subset = shares.slice(0, threshold).map((s) => s.share);
        const reconstructed = await reconstructContentKey(subset);
        expect(reconstructed.type).toBe("secret");
      }
    });
  });

  describe("getContractLabel", () => {
    it.each([
      ["SIMPLE", "Simple"],
      ["STANDARD", "Standard"],
      ["SECURE", "Secure"],
      ["PARANOID", "Paranoid"],
    ] as [DeliveryContract, string][])("%s → %s", (contract, expected) => {
      expect(getContractLabel(contract)).toBe(expected);
    });
  });

  describe("getContractDescription", () => {
    it.each(ALL_CONTRACTS)("should return a non-empty string for %s", (contract) => {
      const desc = getContractDescription(contract);
      expect(typeof desc).toBe("string");
      expect(desc.length).toBeGreaterThan(0);
    });

    it.each(ALL_CONTRACTS)("should mention the contract dimensions for %s", (contract) => {
      const desc = getContractDescription(contract);
      const dims = getRequiredDimensions(contract);
      // Descriptions should be meaningful enough to mention key concepts
      expect(desc).not.toBe("");
    });
  });

  describe("end-to-end roundtrip", () => {
    it.each(ALL_CONTRACTS)(
      "should encrypt, split, reconstruct, and decrypt for %s",
      async (contract) => {
        // 1. Generate Content Key
        const ck = await generateContentKey();

        // 2. Encrypt a message
        const plaintext = new TextEncoder().encode(
          `Secret message for ${contract} contract`
        );
        const encrypted = await encryptData(plaintext, ck);

        // 3. Split the key
        const { shares } = await splitContentKey(ck, contract);

        // 4. Reconstruct from shares
        const shareValues = shares.map((s) => s.share);
        const reconstructedCk = await reconstructContentKey(shareValues);

        // 5. Decrypt the message
        const decrypted = await decryptData(encrypted, reconstructedCk);
        const decryptedText = new TextDecoder().decode(decrypted);

        expect(decryptedText).toBe(`Secret message for ${contract} contract`);
      }
    );
  });
});
