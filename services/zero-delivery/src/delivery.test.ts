import { describe, expect, test } from "bun:test";
import { readConfig } from "./config";
import { createHttpCiphertextBlobSink, validateDelivery, validateResolvedDelivery } from "./delivery";
import { createHandler } from "./server";

describe("zero-delivery config", () => {
  test("requires zero-access mode", () => {
    expect(() => readConfig({ ZERO_ACCESS_REQUIRED: "n" })).toThrow("ZERO_ACCESS_REQUIRED must be y");
  });
});

describe("zero-delivery validation", () => {
  test("rejects delivery without recipient key", () => {
    expect(
      validateDelivery({
        recipient: "bob@example.test",
        ciphertextBlobId: "blob-id",
        encryptionState: "local_e2ee"
      })
    ).toEqual({ ok: false, error: "recipient_key_required" });
  });

  test("rejects delivery without ciphertext", () => {
    expect(
      validateDelivery({
        recipient: "bob@example.test",
        ciphertextBlobId: "",
        recipientKeyId: "key-id",
        encryptionState: "local_e2ee"
      })
    ).toEqual({ ok: false, error: "ciphertext_required" });
  });

  test("accepts encrypted delivery with recipient key", () => {
    expect(
      validateDelivery({
        recipient: "bob@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "key-id",
        encryptionState: "local_e2ee"
      })
    ).toEqual({
      ok: true,
      recipient: "bob@example.test",
      ciphertextBlobId: "blob-id",
      accepted: {
        recipient: "bob@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "key-id",
        encryptionState: "local_e2ee"
      }
    });
  });

  test("rejects delivery with cleartext fields", () => {
    expect(
      validateDelivery({
        recipient: "bob@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "key-id",
        encryptionState: "local_e2ee",
        body: "hello"
      } as never)
    ).toEqual({ ok: false, error: "cleartext_rejected" });
  });

  test("resolves recipient key before accepting delivery", async () => {
    await expect(
      validateResolvedDelivery(
        {
          recipient: "bob@example.test",
          ciphertextBlobId: "blob-id",
          encryptionState: "local_e2ee"
        },
        {
          async resolve(address) {
            return { address, primaryKeyId: "bob-key" };
          }
        }
      )
    ).resolves.toEqual({
      ok: true,
      recipient: "bob@example.test",
      ciphertextBlobId: "blob-id",
      accepted: {
        recipient: "bob@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "bob-key",
        encryptionState: "local_e2ee"
      }
    });
  });
});

describe("zero-delivery handler", () => {
  test("serves a no-store healthcheck", async () => {
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }));
    const response = await handler(new Request("http://zero-delivery/health"));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toEqual({
      ok: true,
      service: "zero-delivery",
      zeroAccessRequired: true
    });
  });

  test("rejects delivery when zero-api has no recipient key", async () => {
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve() {
          return undefined;
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipient: "bob@example.test",
          ciphertextBlobId: "blob-id",
          encryptionState: "local_e2ee"
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ ok: false, error: "recipient_key_required", recipient: "bob@example.test" });
  });

  test("stores delivery after resolving recipient key", async () => {
    const stored: unknown[] = [];
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve(address) {
          return { address, primaryKeyId: "bob-key" };
        }
      },
      messageSink: {
        async store(message) {
          stored.push(message);
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipient: "bob@example.test",
          ciphertextBlobId: "blob-id",
          encryptionState: "local_e2ee"
        })
      })
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      ok: true,
      recipient: "bob@example.test",
      ciphertextBlobId: "blob-id"
    });
    expect(stored).toEqual([
      {
        recipient: "bob@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "bob-key",
        encryptionState: "local_e2ee"
      }
    ]);
  });

  test("uploads inline ciphertext before storing delivery metadata", async () => {
    const stored: unknown[] = [];
    const uploaded: Uint8Array[] = [];
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve(address) {
          return { address, primaryKeyId: "bob-key" };
        }
      },
      ciphertextBlobSink: {
        async store(ciphertext) {
          uploaded.push(ciphertext);
          return { id: "uploaded-blob-id" };
        }
      },
      messageSink: {
        async store(message) {
          stored.push(message);
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipient: "bob@example.test",
          ciphertext: Buffer.from([1, 2, 3, 4]).toString("base64"),
          encryptionState: "local_e2ee"
        })
      })
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      ok: true,
      recipient: "bob@example.test",
      ciphertextBlobId: "uploaded-blob-id"
    });
    expect(uploaded).toEqual([new Uint8Array([1, 2, 3, 4])]);
    expect(stored).toEqual([
      {
        recipient: "bob@example.test",
        ciphertextBlobId: "uploaded-blob-id",
        recipientKeyId: "bob-key",
        encryptionState: "local_e2ee"
      }
    ]);
  });

  test("fans out inline ciphertext delivery to multiple local recipients", async () => {
    const stored: unknown[] = [];
    const uploaded: Uint8Array[] = [];
    const resolved: string[] = [];
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve(address) {
          resolved.push(address);
          return { address, primaryKeyId: `${address}-key` };
        }
      },
      ciphertextBlobSink: {
        async store(ciphertext) {
          uploaded.push(ciphertext);
          return { id: `uploaded-blob-${uploaded.length}` };
        }
      },
      messageSink: {
        async store(message) {
          stored.push(message);
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipients: ["alice@example.test", "bob@example.test"],
          ciphertext: Buffer.from([9, 9, 9]).toString("base64"),
          encryptionState: "local_e2ee"
        })
      })
    );

    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      ok: true,
      deliveries: [
        { recipient: "alice@example.test", ciphertextBlobId: "uploaded-blob-1" },
        { recipient: "bob@example.test", ciphertextBlobId: "uploaded-blob-2" }
      ]
    });
    expect(resolved).toEqual(["alice@example.test", "bob@example.test"]);
    expect(uploaded).toEqual([new Uint8Array([9, 9, 9]), new Uint8Array([9, 9, 9])]);
    expect(stored).toEqual([
      {
        recipient: "alice@example.test",
        ciphertextBlobId: "uploaded-blob-1",
        recipientKeyId: "alice@example.test-key",
        encryptionState: "local_e2ee"
      },
      {
        recipient: "bob@example.test",
        ciphertextBlobId: "uploaded-blob-2",
        recipientKeyId: "bob@example.test-key",
        encryptionState: "local_e2ee"
      }
    ]);
  });

  test("does not store partial multi-recipient delivery when one key is missing", async () => {
    const uploaded: Uint8Array[] = [];
    const stored: unknown[] = [];
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve(address) {
          if (address === "bob@example.test") {
            return undefined;
          }

          return { address, primaryKeyId: `${address}-key` };
        }
      },
      ciphertextBlobSink: {
        async store(ciphertext) {
          uploaded.push(ciphertext);
          return { id: `uploaded-blob-${uploaded.length}` };
        }
      },
      messageSink: {
        async store(message) {
          stored.push(message);
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipients: ["alice@example.test", "bob@example.test"],
          ciphertext: Buffer.from([9, 9, 9]).toString("base64"),
          encryptionState: "local_e2ee"
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ ok: false, error: "recipient_key_required", recipient: "bob@example.test" });
    expect(uploaded).toEqual([]);
    expect(stored).toEqual([]);
  });

  test("does not upload inline ciphertext when cleartext fields are present", async () => {
    const uploaded: Uint8Array[] = [];
    const stored: unknown[] = [];
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve(address) {
          return { address, primaryKeyId: "bob-key" };
        }
      },
      ciphertextBlobSink: {
        async store(ciphertext) {
          uploaded.push(ciphertext);
          return { id: "uploaded-blob-id" };
        }
      },
      messageSink: {
        async store(message) {
          stored.push(message);
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipient: "bob@example.test",
          ciphertext: Buffer.from([1, 2, 3, 4]).toString("base64"),
          encryptionState: "local_e2ee",
          body: "hello"
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ ok: false, error: "cleartext_rejected" });
    expect(uploaded).toEqual([]);
    expect(stored).toEqual([]);
  });

  test("uploads ciphertext to zero-api with ciphertext-only headers", async () => {
    const requests: Request[] = [];
    const sink = createHttpCiphertextBlobSink("http://zero-api", async (request) => {
      requests.push(request);
      return new Response(JSON.stringify({ id: "blob-id" }), { status: 201 });
    });

    await expect(sink.store(new Uint8Array([7, 8, 9]))).resolves.toEqual({ id: "blob-id" });
    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe("http://zero-api/blob");
    expect(requests[0].method).toBe("POST");
    expect(requests[0].headers.get("content-type")).toBe("application/octet-stream");
    expect(requests[0].headers.get("x-zero-blob-kind")).toBe("ciphertext");
    expect(new Uint8Array(await requests[0].arrayBuffer())).toEqual(new Uint8Array([7, 8, 9]));
  });

  test("does not store delivery with cleartext fields", async () => {
    const stored: unknown[] = [];
    const handler = createHandler(readConfig({ ZERO_ACCESS_REQUIRED: "y" }), {
      recipientKeyResolver: {
        async resolve(address) {
          return { address, primaryKeyId: "bob-key" };
        }
      },
      messageSink: {
        async store(message) {
          stored.push(message);
        }
      }
    });
    const response = await handler(
      new Request("http://zero-delivery/deliver", {
        method: "POST",
        body: JSON.stringify({
          recipient: "bob@example.test",
          ciphertextBlobId: "blob-id",
          encryptionState: "local_e2ee",
          html: "<p>hello</p>"
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ ok: false, error: "cleartext_rejected" });
    expect(stored).toEqual([]);
  });
});
