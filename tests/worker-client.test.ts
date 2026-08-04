import { describe, it, expect } from "vitest";
import { WorkerCryptoClient, type WorkerLike } from "../src/worker-client";
import { wireWorker, type WorkerPort } from "../src/worker";
import { WorkerCryptoCore } from "../src/worker-core";
import type { WorkerRequest, WorkerResponse } from "../src/worker-core";

const PASSWORD = "worker-client-test-password";

/**
 * A fake Worker that runs a REAL WorkerCryptoCore on the microtask queue.
 * jsdom/Node have no real Web Workers, so this simulates the message pump:
 * postMessage → handleRequest(core, req) → onmessage(response).
 */
class FakeWorker implements WorkerLike {
  onmessage: ((event: { data: WorkerResponse }) => void) | null = null;
  onerror: ((event: { message?: string }) => void) | null = null;
  terminated = false;
  sentRequests: WorkerRequest[] = [];

  private port: WorkerPort;

  constructor(core = new WorkerCryptoCore()) {
    // Reuse the real worker-entry wiring against a loopback port.
    this.port = {
      onmessage: null,
      postMessage: (message: WorkerResponse) => {
        queueMicrotask(() => this.onmessage?.({ data: message }));
      },
    };
    wireWorker(this.port, core);
  }

  postMessage(message: WorkerRequest): void {
    this.sentRequests.push(message);
    const handler = this.port.onmessage;
    if (handler) {
      queueMicrotask(() => handler({ data: message }));
    }
  }

  terminate(): void {
    this.terminated = true;
  }
}

describe("WorkerCryptoClient", () => {
  it("should correlate requests and responses by id (out of order)", async () => {
    // A scripted mock that responds to ids in reverse order.
    const responses: WorkerResponse[] = [
      { id: 1, ok: true, result: "first" },
      { id: 2, ok: true, result: "second" },
    ];
    let onmsg: ((e: { data: WorkerResponse }) => void) | null = null;
    const scripted: WorkerLike = {
      onmessage: null,
      onerror: null,
      postMessage(req: WorkerRequest) {
        const res = responses.find((r) => r.id === req.id)!;
        // Respond LIFO: id 2 resolves before id 1.
        setTimeout(() => onmsg?.({ data: res }), res.id === 2 ? 0 : 5);
      },
      terminate() {},
    };
    scripted.onmessage = null;
    const client = new WorkerCryptoClient({
      ...scripted,
      set onmessage(fn) {
        onmsg = fn;
      },
      get onmessage() {
        return onmsg;
      },
    } as unknown as WorkerLike);

    const p1 = (client as unknown as { call: (r: unknown) => Promise<unknown> }).call({ op: "hasUMK" });
    const p2 = (client as unknown as { call: (r: unknown) => Promise<unknown> }).call({ op: "hasUMK" });
    await expect(p1).resolves.toBe("first");
    await expect(p2).resolves.toBe("second");
  });

  it("should reject the pending call when the worker responds with an error", async () => {
    const client = new WorkerCryptoClient(new FakeWorker());
    // wrapREK before unlock → core throws → error response
    await expect(client.wrapREK("AAAA")).rejects.toThrow(/not unlocked/);
  });

  it("should ignore stale responses with unknown ids", async () => {
    const worker = new FakeWorker();
    const client = new WorkerCryptoClient(worker);
    // Inject a response nobody is waiting for; must not break anything.
    worker.onmessage?.({ data: { id: 9999, ok: true, result: null } });
    await expect(client.hasUMK()).resolves.toBe(false);
  });

  it("should run the full lifecycle through the message protocol", async () => {
    const client = new WorkerCryptoClient(new FakeWorker());

    // setup — result must NOT contain raw key material
    const setup = await client.setupUserKeys(PASSWORD);
    expect(setup.encryptedUMK).toBeTruthy();
    expect(setup).not.toHaveProperty("umkBase64");
    await expect(client.hasUMK()).resolves.toBe(true);

    // encrypt → decrypt round-trip through the protocol
    const plaintext = new TextEncoder().encode("protocol round-trip");
    const enc = await client.encryptBlob(plaintext.buffer.slice(0) as ArrayBuffer);
    expect(enc.ciphertext).toBeInstanceOf(ArrayBuffer);
    expect(enc.encryptedREK).toBeTruthy();
    const decrypted = await client.decryptBlob(
      enc.ciphertext,
      enc.iv,
      enc.authTag,
      enc.encryptedREK
    );
    expect(new TextDecoder().decode(decrypted)).toBe("protocol round-trip");

    // lock / unlock
    await client.lock();
    await expect(client.hasUMK()).resolves.toBe(false);
    await client.unlock(setup.encryptedUMK, PASSWORD, setup.salt);
    await expect(client.hasUMK()).resolves.toBe(true);

    // recovery shares through the protocol
    const shares = await client.generateRecoveryShares(
      setup.encryptedUMK,
      PASSWORD,
      setup.salt
    );
    expect(shares.shareA).toBeTruthy();

    // escape hatch
    const umk = await client.exportUMK(setup.encryptedUMK, PASSWORD, setup.salt);
    expect(() => atob(umk)).not.toThrow();
  });

  it("should reject calls after destroy and terminate the worker", async () => {
    const worker = new FakeWorker();
    const client = new WorkerCryptoClient(worker);
    await client.setupUserKeys(PASSWORD);

    await client.destroy();
    expect(worker.terminated).toBe(true);
    await expect(client.hasUMK()).rejects.toThrow(/destroyed/);
    // destroy is idempotent
    await client.destroy();
  });

  it("should reject all pending calls when the worker errors", async () => {
    const worker = new FakeWorker();
    const client = new WorkerCryptoClient(worker);
    const pending = client.hasUMK();
    worker.onerror?.({ message: "boom" });
    await expect(pending).rejects.toThrow("boom");
  });
});
