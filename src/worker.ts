/**
 * Web Worker entry point for key isolation.
 *
 * This module contains no cryptography itself — it wires a WorkerCryptoCore
 * instance to the worker's message port. All logic lives in worker-core.ts so
 * it can be unit-tested without a real Web Worker environment.
 *
 * Usage from the main thread (see worker-client.ts):
 *   const worker = new Worker(new URL("hekatae-crypto/worker/entry", import.meta.url));
 */

import {
  WorkerCryptoCore,
  handleRequest,
  type WorkerRequest,
  type WorkerResponse,
} from "./worker-core.js";

/** Minimal message-port shape so tests can drive this with a mock. */
export interface WorkerPort {
  onmessage: ((event: { data: WorkerRequest }) => void) | null;
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void;
}

/**
 * Attach a request handler to a worker message port. Exported (and
 * dependency-injected) so unit tests can exercise the wiring without a real
 * DedicatedWorkerGlobalScope.
 */
export function wireWorker(
  port: WorkerPort,
  core: WorkerCryptoCore = new WorkerCryptoCore()
): WorkerCryptoCore {
  port.onmessage = async (event: { data: WorkerRequest }) => {
    const req = event.data;
    let response: WorkerResponse;
    let transfer: Transferable[] | undefined;
    try {
      const result = await handleRequest(core, req);
      response = { id: req.id, ok: true, result };
      // Return large binary results as transferable (zero-copy) where possible.
      if (result instanceof ArrayBuffer) {
        transfer = [result];
      } else if (
        result !== null &&
        typeof result === "object" &&
        (result as { ciphertext?: unknown }).ciphertext instanceof ArrayBuffer
      ) {
        transfer = [(result as { ciphertext: ArrayBuffer }).ciphertext];
      }
    } catch (err) {
      // Deliberately collapse errors to a message string — never leak key
      // material or stack internals through the boundary.
      response = {
        id: req.id,
        ok: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
    port.postMessage(response, transfer);
  };
  return core;
}

// Auto-wire when this module runs inside a real Web Worker global scope.
// (DedicatedWorkerGlobalScope exposes importScripts; windows and Node do not.)
const workerScope = globalThis as unknown as {
  importScripts?: unknown;
  postMessage?: unknown;
};
if (
  typeof workerScope.importScripts === "function" &&
  typeof workerScope.postMessage === "function"
) {
  wireWorker(globalThis as unknown as WorkerPort);
}
