import { describe, it, expect, beforeAll } from "vitest";
import {
  encryptRecording,
  decryptRecording,
} from "../src/recording-crypto";

// Polyfill Blob.prototype.arrayBuffer and Blob.prototype.text for jsdom
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
  if (!Blob.prototype.text) {
    Blob.prototype.text = function (): Promise<string> {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result as string);
        reader.onerror = reject;
        reader.readAsText(this);
      });
    };
  }
});

describe("Recording Crypto", () => {
  async function createTestUMK(): Promise<CryptoKey> {
    // UMK needs wrapKey/unwrapKey usages for recording encryption
    return crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["wrapKey", "unwrapKey"]
    ) as Promise<CryptoKey>;
  }

  describe("encryptRecording + decryptRecording", () => {
    it("should roundtrip a video blob", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob(["fake video data"], { type: "video/webm" });

      const encrypted = await encryptRecording(plaintext, umk);
      expect(encrypted.ciphertextBlob).toBeInstanceOf(Blob);
      expect(encrypted.iv).toBeTruthy();
      expect(encrypted.authTag).toBeTruthy();
      expect(encrypted.encryptedREK).toBeTruthy();

      const decrypted = await decryptRecording(
        encrypted.ciphertextBlob,
        encrypted.iv,
        encrypted.authTag,
        encrypted.encryptedREK,
        umk
      );

      expect(decrypted.type).toBe("video/webm");
      const decryptedText = await decrypted.text();
      expect(decryptedText).toBe("fake video data");
    });

    it("should roundtrip an audio blob", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob(["fake audio data"], { type: "audio/wav" });

      const encrypted = await encryptRecording(plaintext, umk);
      const decrypted = await decryptRecording(
        encrypted.ciphertextBlob,
        encrypted.iv,
        encrypted.authTag,
        encrypted.encryptedREK,
        umk
      );

      expect(decrypted.type).toBe("audio/wav");
    });

    it("should roundtrip a text blob", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob(["Hello, this is a text message."], { type: "text/plain" });

      const encrypted = await encryptRecording(plaintext, umk);
      const decrypted = await decryptRecording(
        encrypted.ciphertextBlob,
        encrypted.iv,
        encrypted.authTag,
        encrypted.encryptedREK,
        umk
      );

      expect(await decrypted.text()).toBe("Hello, this is a text message.");
    });

    it("should fail decryption with wrong UMK", async () => {
      const umk1 = await createTestUMK();
      const umk2 = await createTestUMK();
      const plaintext = new Blob(["secret"], { type: "text/plain" });

      const encrypted = await encryptRecording(plaintext, umk1);
      await expect(
        decryptRecording(
          encrypted.ciphertextBlob,
          encrypted.iv,
          encrypted.authTag,
          encrypted.encryptedREK,
          umk2
        )
      ).rejects.toThrow();
    });

    it("should fail decryption with tampered encryptedREK", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob(["secret"], { type: "text/plain" });

      const encrypted = await encryptRecording(plaintext, umk);
      const tamperedREK = encrypted.encryptedREK.slice(0, -4) + "XXXX";

      await expect(
        decryptRecording(
          encrypted.ciphertextBlob,
          encrypted.iv,
          encrypted.authTag,
          tamperedREK,
          umk
        )
      ).rejects.toThrow();
    });

    it("should produce different ciphertexts for same plaintext", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob(["same"], { type: "text/plain" });

      const encrypted1 = await encryptRecording(plaintext, umk);
      const encrypted2 = await encryptRecording(plaintext, umk);

      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.authTag).not.toBe(encrypted2.authTag);

      // Blobs should have different content
      const arr1 = new Uint8Array(await encrypted1.ciphertextBlob.arrayBuffer());
      const arr2 = new Uint8Array(await encrypted2.ciphertextBlob.arrayBuffer());
      expect(arr1).not.toEqual(arr2);
    });

    it("should preserve blob type when unspecified", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob(["data"]);

      const encrypted = await encryptRecording(plaintext, umk);
      expect(encrypted.ciphertextBlob.type).toBe("application/octet-stream");
    });

    it("should handle empty blob", async () => {
      const umk = await createTestUMK();
      const plaintext = new Blob([], { type: "text/plain" });

      const encrypted = await encryptRecording(plaintext, umk);
      const decrypted = await decryptRecording(
        encrypted.ciphertextBlob,
        encrypted.iv,
        encrypted.authTag,
        encrypted.encryptedREK,
        umk
      );

      expect(decrypted.size).toBe(0);
    });
  });
});
