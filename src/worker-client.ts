/**
 * Main-thread async client for the worker-based key isolation path.
 *
 * This is the RECOMMENDED production path for the web app: the UMK (and all
 * operations that touch raw key material) run inside a dedicated Web Worker,
 * so page-context XSS cannot read key material out of the main thread's JS
 * heap. See README "Production hardening: worker-based key isolation".
 *
 * Usage:
 *   import { WorkerCryptoClient } from "hekatae-crypto/worker";
 *
 *   const worker = new Worker(
 *     new URL("hekatae-crypto/worker/entry", import.meta.url),
 *     { type: "module" }
 *   );
 *   const crypto = new WorkerCryptoClient(worker);
 *
 *   // Registration — the UMK is generated and HELD inside the worker.
 *   const setup = await crypto.setupUserKeys(password);
 *   await api.saveKeys(setup); // encryptedUMK, shareA/B/C, salt, sentinel
 *
 *   // Later sessions — unlock inside the worker; nothing key-like returns.
 *   await crypto.unlock(user.encryptedMasterKey, password, user.masterKeySalt);
 *
 *   // Blob encryption — REK never leaves the worker either.
 *   const enc = await crypto.encryptBlob(plaintextBytes, aad);
 *   const plain = await crypto.decryptBlob(enc.ciphertext, enc.iv, enc.authTag, enc.encryptedREK, aad);
 */

import type {
  WorkerEncryptedBlob,
  WorkerKeySetupResult,
  WorkerRecoveryShares,
  WorkerRequest,
  WorkerResponse,
} from "./worker-core.js";

/** Structural subset of the Worker interface (easy to mock in tests). */
export interface WorkerLike {
  onmessage: ((event: { data: WorkerResponse }) => void) | null;
  onerror: ((event: { message?: string }) => void) | null;
  postMessage(message: WorkerRequest, transfer?: Transferable[]): void;
  terminate(): void;
}

interface PendingCall {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
}

/** Distributive Omit so the request union survives removing "id". */
type RequestPayload<T, K extends PropertyKey> = T extends unknown
  ? Omit<T, K>
  : never;

export class WorkerCryptoClient {
  private worker: WorkerLike;
  private nextId = 1;
  private pending = new Map<number, PendingCall>();
  private destroyed = false;

  constructor(worker: WorkerLike) {
    this.worker = worker;
    this.worker.onmessage = (event: { data: WorkerResponse }) => {
      const res = event.data;
      const call = this.pending.get(res.id);
      if (!call) return; // stale/unknown response — ignore
      this.pending.delete(res.id);
      if (res.ok) {
        call.resolve(res.result);
      } else {
        call.reject(new Error(res.error));
      }
    };
    this.worker.onerror = (event: { message?: string }) => {
      const err = new Error(event.message ?? "Crypto worker error");
      for (const call of this.pending.values()) call.reject(err);
      this.pending.clear();
    };
  }

  /**
   * Generate a fresh UMK inside the worker and return the setup artifacts.
   * The result deliberately contains NO raw UMK — it stays in the worker.
   */
  async setupUserKeys(
    password: string
  ): Promise<WorkerKeySetupResult> {
    return (await this.call({
      op: "setupUserKeys",
      password,
    })) as WorkerKeySetupResult;
  }

  /**
   * Worker-side decryptUMK: derive the PDK and unlock the UMK inside the
   * worker. Resolves to nothing — the UMK is never returned.
   */
  async unlock(
    encryptedUMK: string,
    password: string,
    salt: string
  ): Promise<void> {
    await this.call({ op: "unlock", encryptedUMK, password, salt });
  }

  /** Whether the worker currently holds an unlocked UMK. */
  async hasUMK(): Promise<boolean> {
    return (await this.call({ op: "hasUMK" })) as boolean;
  }

  /** Lock the worker (drop the held UMK). */
  async lock(): Promise<void> {
    await this.call({ op: "lock" });
  }

  /**
   * Encrypt a blob inside the worker with a fresh REK; the REK is wrapped
   * with the worker-held UMK and only the wrapped form is returned.
   */
  async encryptBlob(
    plaintext: ArrayBuffer,
    aad?: Uint8Array
  ): Promise<WorkerEncryptedBlob> {
    return (await this.call(
      { op: "encryptBlob", plaintext, aad },
      [plaintext]
    )) as WorkerEncryptedBlob;
  }

  /**
   * Decrypt a blob inside the worker (REK is unwrapped with the worker-held
   * UMK). Returns the plaintext bytes. Rejects on tampered data.
   */
  async decryptBlob(
    ciphertext: ArrayBuffer,
    iv: string,
    authTag: string,
    encryptedREK: string,
    aad?: Uint8Array
  ): Promise<ArrayBuffer> {
    return (await this.call(
      { op: "decryptBlob", ciphertext, iv, authTag, encryptedREK, aad },
      [ciphertext]
    )) as ArrayBuffer;
  }

  /**
   * Wrap a main-thread-held REK/content key with the worker-held UMK.
   * Compatibility op — prefer encryptBlob so the REK never enters the page.
   */
  async wrapREK(rekBase64: string): Promise<string> {
    return (await this.call({ op: "wrapREK", rekBase64 })) as string;
  }

  /**
   * Unwrap a REK and return it as base64. The raw REK crosses the boundary —
   * compatibility op; prefer decryptBlob in new code.
   */
  async unwrapREK(encryptedREK: string): Promise<string> {
    return (await this.call({ op: "unwrapREK", encryptedREK })) as string;
  }

  /** Fresh 2-of-3 recovery shares for the account UMK (see worker-core docs). */
  async generateRecoveryShares(
    encryptedUMK: string,
    password: string,
    salt: string
  ): Promise<WorkerRecoveryShares> {
    return (await this.call({
      op: "generateRecoveryShares",
      encryptedUMK,
      password,
      salt,
    })) as WorkerRecoveryShares;
  }

  /**
   * ESCAPE HATCH — export the raw UMK base64 for legacy main-thread flows.
   * Defeats the isolation this module provides; do not use in new code.
   */
  async exportUMK(
    encryptedUMK: string,
    password: string,
    salt: string
  ): Promise<string> {
    return (await this.call({
      op: "exportUMK",
      encryptedUMK,
      password,
      salt,
    })) as string;
  }

  /** Destroy the core's key material and terminate the worker. */
  async destroy(): Promise<void> {
    if (this.destroyed) return;
    try {
      await this.call({ op: "destroy" });
    } finally {
      this.destroyed = true;
      this.worker.onmessage = null;
      this.worker.onerror = null;
      this.worker.terminate();
      for (const call of this.pending.values()) {
        call.reject(new Error("Crypto worker destroyed"));
      }
      this.pending.clear();
    }
  }

  private call(
    req: RequestPayload<WorkerRequest, "id">,
    transfer?: Transferable[]
  ): Promise<unknown> {
    if (this.destroyed) {
      return Promise.reject(new Error("Crypto worker client is destroyed"));
    }
    const id = this.nextId++;
    return new Promise<unknown>((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ ...req, id } as WorkerRequest, transfer);
    });
  }
}
