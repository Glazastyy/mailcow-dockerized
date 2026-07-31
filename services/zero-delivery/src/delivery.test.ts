import { describe, expect, test } from "bun:test";
import { readConfig } from "./config";
import { validateDelivery, validateResolvedDelivery } from "./delivery";
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
      ciphertextBlobId: "blob-id"
    });
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
      ciphertextBlobId: "blob-id"
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
    expect(await response.json()).toEqual({ ok: false, error: "recipient_key_required" });
  });
});
