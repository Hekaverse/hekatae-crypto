import { describe, it, expect, vi, beforeEach } from "vitest";

const argon2idMock = vi.fn();

vi.mock("hash-wasm", () => ({
  // The closure reads argon2idMock lazily at call time, so the hoisted
  // factory never touches the const before it is initialized.
  argon2id: (options: unknown) => argon2idMock(options),
}));

import { setupUserKeys, decryptUMK } from "../src/key-derivation";
import { isArgon2UnavailableError } from "../src/argon2";

const WASM_MISSING = "WebAssembly is not supported in this environment!";

beforeEach(() => {
  argon2idMock.mockReset();
});

describe("isArgon2UnavailableError", () => {
  it("recognizes the hash-wasm missing-WebAssembly error", () => {
    expect(isArgon2UnavailableError(new Error(WASM_MISSING))).toBe(true);
  });

  it("recognizes WebAssembly compile/link/runtime errors", () => {
    expect(isArgon2UnavailableError(new WebAssembly.CompileError())).toBe(true);
    expect(isArgon2UnavailableError(new WebAssembly.LinkError())).toBe(true);
    expect(isArgon2UnavailableError(new WebAssembly.RuntimeError())).toBe(true);
  });

  it("rejects ordinary errors and non-errors", () => {
    expect(isArgon2UnavailableError(new Error("hash operation failed"))).toBe(false);
    expect(isArgon2UnavailableError("not an error")).toBe(false);
    expect(isArgon2UnavailableError(null)).toBe(false);
  });
});

describe("Argon2id → PBKDF2 fallback discipline", () => {
  it("falls back ONLY on WASM-load failure, and logs loudly", async () => {
    argon2idMock.mockRejectedValue(new Error(WASM_MISSING));
    const messages: string[] = [];
    const setup = await setupUserKeys("pw", (m) => messages.push(m));
    expect(setup.encryptedUMK).toBeTruthy();
    expect(messages.some((m) => m.includes("Argon2id WASM unavailable"))).toBe(true);
  });

  it("falls back on WebAssembly.CompileError", async () => {
    argon2idMock.mockRejectedValue(new WebAssembly.CompileError());
    const messages: string[] = [];
    const setup = await setupUserKeys("pw", (m) => messages.push(m));
    expect(setup.encryptedUMK).toBeTruthy();
    expect(messages.some((m) => m.includes("Argon2id WASM unavailable"))).toBe(true);
  });

  it("does NOT fall back on ordinary Argon2 errors", async () => {
    argon2idMock.mockRejectedValue(new Error("hash operation failed"));
    const messages: string[] = [];
    await expect(
      setupUserKeys("pw", (m) => messages.push(m))
    ).rejects.toThrow("hash operation failed");
    expect(messages).toHaveLength(0);
  });

  it("accounts wrapped during a WASM outage decrypt once Argon2id is back", async () => {
    // Wrap while Argon2id is down → PBKDF2-derived PDK.
    argon2idMock.mockRejectedValue(new Error(WASM_MISSING));
    const setup = await setupUserKeys("pw", () => {});

    // Argon2id is back: the normal path must still unlock this account via
    // the legacy PBKDF2 candidate.
    const real = await vi.importActual<typeof import("hash-wasm")>("hash-wasm");
    argon2idMock.mockImplementation(real.argon2id as (o: unknown) => unknown);
    const umk = await decryptUMK(setup.encryptedUMK, "pw", setup.salt, () => {});
    expect(umk).toBe(setup.umkBase64);
  });

  it("unlock under a continuing outage uses the PBKDF2 candidate directly", async () => {
    argon2idMock.mockRejectedValue(new Error(WASM_MISSING));
    const setup = await setupUserKeys("pw", () => {});
    const messages: string[] = [];
    const umk = await decryptUMK(setup.encryptedUMK, "pw", setup.salt, (m) =>
      messages.push(m)
    );
    expect(umk).toBe(setup.umkBase64);
    expect(messages.some((m) => m.includes("Argon2id WASM unavailable"))).toBe(true);
  });
});
