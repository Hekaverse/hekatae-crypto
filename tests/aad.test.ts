import { describe, it, expect } from "vitest";
import { buildRecordingAAD, parseRecordingAAD, AAD_VERSION } from "../src/aad";

describe("Recording AAD", () => {
  describe("buildRecordingAAD", () => {
    it("should build the canonical context string", () => {
      const aad = buildRecordingAAD("rec-123", "SIMPLE");
      expect(new TextDecoder().decode(aad)).toBe(
        `hekatae:aad:v${AAD_VERSION}:rec-123:SIMPLE`
      );
    });

    it("should default to the LEGACY contract", () => {
      const aad = buildRecordingAAD("rec-123");
      expect(new TextDecoder().decode(aad)).toBe(
        `hekatae:aad:v${AAD_VERSION}:rec-123:LEGACY`
      );
    });

    it("should throw without a recordingId", () => {
      expect(() => buildRecordingAAD("")).toThrow("recordingId is required");
    });
  });

  describe("parseRecordingAAD", () => {
    it("should roundtrip a built AAD", () => {
      const aad = buildRecordingAAD("rec-123", "STANDARD");
      const parsed = parseRecordingAAD(aad);
      expect(parsed.version).toBe(AAD_VERSION);
      expect(parsed.recordingId).toBe("rec-123");
      expect(parsed.deliveryContract).toBe("STANDARD");
    });

    it("should strip the v prefix from the version (no NaN)", () => {
      const aad = new TextEncoder().encode("hekatae:aad:v1:rec-123:LEGACY");
      const parsed = parseRecordingAAD(aad);
      expect(parsed.version).toBe(1);
      expect(Number.isNaN(parsed.version)).toBe(false);
    });

    it("should parse a multi-digit version", () => {
      const aad = new TextEncoder().encode("hekatae:aad:v12:rec-123:LEGACY");
      expect(parseRecordingAAD(aad).version).toBe(12);
    });

    it("should throw on a non-integer version", () => {
      const aad = new TextEncoder().encode("hekatae:aad:vX:rec-123:LEGACY");
      expect(() => parseRecordingAAD(aad)).toThrow("Invalid recording AAD format");
    });

    it("should throw on an empty version", () => {
      const aad = new TextEncoder().encode("hekatae:aad:v:rec-123:LEGACY");
      expect(() => parseRecordingAAD(aad)).toThrow("Invalid recording AAD format");
    });

    it("should throw on a malformed prefix", () => {
      const aad = new TextEncoder().encode("other:aad:v1:rec-123:LEGACY");
      expect(() => parseRecordingAAD(aad)).toThrow("Invalid recording AAD format");
    });

    it("should throw on wrong field count", () => {
      const aad = new TextEncoder().encode("hekatae:aad:v1:rec-123");
      expect(() => parseRecordingAAD(aad)).toThrow("Invalid recording AAD format");
    });
  });
});
