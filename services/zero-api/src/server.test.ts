import { describe, expect, test } from "bun:test";
import { readConfig } from "./config";
import { createHandler } from "./server";

describe("zero-api config", () => {
  test("requires zero-access mode", () => {
    expect(() => readConfig({ ZERO_ACCESS_REQUIRED: "n" })).toThrow("ZERO_ACCESS_REQUIRED must be y");
  });

  test("accepts the generated zero-access defaults", () => {
    const config = readConfig({
      ZERO_ACCESS_REQUIRED: "y",
      ZERO_API_PORT: "8080",
      DBNAME: "mailcow",
      DBUSER: "mailcow",
      REDISPASS: "secret",
      TZ: "UTC"
    });

    expect(config.zeroAccessRequired).toBe(true);
    expect(config.port).toBe(8080);
    expect(config.databaseName).toBe("mailcow");
    expect(config.redisConfigured).toBe(true);
  });
});

describe("zero-api handler", () => {
  test("serves a no-store healthcheck", async () => {
    const config = readConfig({
      ZERO_ACCESS_REQUIRED: "y",
      DBNAME: "mailcow",
      DBUSER: "mailcow",
      REDISPASS: "secret"
    });
    const handler = createHandler(config);
    const response = await handler(new Request("http://zero-api/health"));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toEqual({
      ok: true,
      service: "zero-api",
      zeroAccessRequired: true,
      databaseConfigured: true,
      redisConfigured: true
    });
  });

  test("does not fake unfinished crypto and mail endpoints", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const handler = createHandler(config);

    expect((await handler(new Request("http://zero-api/crypto/bootstrap"))).status).toBe(501);
    expect((await handler(new Request("http://zero-api/mail/messages"))).status).toBe(501);
  });

  test("accepts only ciphertext blob uploads", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const blobs = new Map<string, Uint8Array>();
    const handler = createHandler(config, { blobs });

    const cleartextResponse = await handler(
      new Request("http://zero-api/blob", {
        method: "POST",
        headers: {
          "content-type": "text/plain"
        },
        body: "hello"
      })
    );

    const ciphertextResponse = await handler(
      new Request("http://zero-api/blob", {
        method: "POST",
        headers: {
          "content-type": "application/octet-stream",
          "x-zero-blob-kind": "ciphertext"
        },
        body: new Uint8Array([1, 2, 3, 4])
      })
    );
    const ciphertextBody = await ciphertextResponse.json();

    expect(cleartextResponse.status).toBe(415);
    expect(ciphertextResponse.status).toBe(201);
    expect(ciphertextBody).toEqual({
      id: expect.any(String),
      size: 4,
      sha256: expect.any(String)
    });
  });

  test("returns stored ciphertext blobs without caching", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const blobId = "11111111-1111-4111-8111-111111111111";
    const blobs = new Map<string, Uint8Array>([[blobId, new Uint8Array([7, 8, 9])]]);
    const handler = createHandler(config, { blobs });
    const response = await handler(new Request(`http://zero-api/blob/${blobId}`));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("content-type")).toBe("application/octet-stream");
    expect(new Uint8Array(await response.arrayBuffer())).toEqual(new Uint8Array([7, 8, 9]));
  });
});
