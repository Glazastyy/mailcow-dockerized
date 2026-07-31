import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { readConfig } from "./config";
import { createHandler } from "./server";
import { createMemoryKeyStore } from "./key-store";
import { createMemoryKeyEventStore } from "./key-event-store";

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
  async function withTempBlobDir<T>(run: (root: string) => Promise<T>): Promise<T> {
    const root = await mkdtemp(join(tmpdir(), "zero-api-"));

    try {
      return await run(root);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  }

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

  test("rejects clear private keys when registering user keys", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const handler = createHandler(config, { keyStore: createMemoryKeyStore() });
    const response = await handler(
      new Request("http://zero-api/crypto/keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "alice@example.test",
          primaryKeyId: "alice-key",
          publicKeyArmored: "public",
          privateKey: "clear-secret",
          encryptedPrivateKey: "encrypted",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { memory: 65536 }
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "clear_private_key_rejected" });
  });

  test("registers encrypted user keys and exposes only public key material", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const keyEvents: unknown[] = [];
    const handler = createHandler(config, {
      keyStore: createMemoryKeyStore(),
      keyEventStore: {
        async append(event) {
          keyEvents.push(event);
        }
      }
    });
    const createResponse = await handler(
      new Request("http://zero-api/crypto/keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "Alice@Example.Test",
          primaryKeyId: "alice-key",
          publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
          encryptedPrivateKey: "ciphertext-private-key",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { memory: 65536, iterations: 3 },
          keyVersion: 1
        })
      })
    );
    const publicResponse = await handler(new Request("http://zero-api/keys/local/alice@example.test"));
    const publicBody = await publicResponse.json();

    expect(createResponse.status).toBe(201);
    expect(await createResponse.json()).toEqual({
      address: "alice@example.test",
      primaryKeyId: "alice-key",
      keyVersion: 1,
      status: "active"
    });
    expect(publicResponse.status).toBe(200);
    expect(publicBody).toEqual({
      address: "alice@example.test",
      primaryKeyId: "alice-key",
      publicKeyArmored: "-----BEGIN PGP PUBLIC KEY BLOCK-----",
      keyVersion: 1
    });
    expect(JSON.stringify(publicBody)).not.toContain("ciphertext-private-key");
    expect(keyEvents).toEqual([
      expect.objectContaining({
        address: "alice@example.test",
        eventType: "created",
        primaryKeyId: "alice-key",
        keyVersion: 1,
        rotationMode: "initial"
      })
    ]);
    expect(JSON.stringify(keyEvents)).not.toContain("ciphertext-private-key");
  });

  test("re-encrypts private key envelope when the current password is available client-side", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const keyStore = createMemoryKeyStore();
    const keyEvents: unknown[] = [];
    const handler = createHandler(config, {
      keyStore,
      keyEventStore: {
        async append(event) {
          keyEvents.push(event);
        }
      }
    });
    await keyStore.saveUserKey({
      address: "alice@example.test",
      primaryKeyId: "alice-key",
      publicKeyArmored: "public",
      encryptedPrivateKey: "old-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: { salt: "old" },
      keyVersion: 1,
      status: "active"
    });
    const response = await handler(
      new Request("http://zero-api/crypto/password/reencrypt", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "alice@example.test",
          currentPrimaryKeyId: "alice-key",
          reencryptedPrivateKey: "new-envelope",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { salt: "new" },
          currentPrivateKeyProof: "signature"
        })
      })
    );
    const publicResponse = await handler(new Request("http://zero-api/keys/local/alice@example.test"));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      address: "alice@example.test",
      primaryKeyId: "alice-key",
      keyVersion: 2,
      status: "active",
      mode: "reencrypted"
    });
    expect(await publicResponse.json()).toEqual({
      address: "alice@example.test",
      primaryKeyId: "alice-key",
      publicKeyArmored: "public",
      keyVersion: 2
    });
    expect(keyEvents).toEqual([
      expect.objectContaining({
        address: "alice@example.test",
        eventType: "password_reencrypted",
        primaryKeyId: "alice-key",
        keyVersion: 2,
        rotationMode: "password_reencrypt",
        previousKeyId: expect.any(String)
      })
    ]);
    expect(JSON.stringify(keyEvents)).not.toContain("old-envelope");
    expect(JSON.stringify(keyEvents)).not.toContain("new-envelope");
  });

  test("rejects raw passwords during private key envelope re-encryption", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const handler = createHandler(config, { keyStore: createMemoryKeyStore() });
    const response = await handler(
      new Request("http://zero-api/crypto/password/reencrypt", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "alice@example.test",
          currentPrimaryKeyId: "alice-key",
          reencryptedPrivateKey: "new-envelope",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { salt: "new" },
          currentPrivateKeyProof: "signature",
          newPassword: "clear-password"
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "clear_password_rejected" });
  });

  test("resets cryptographic identity when current password is unavailable", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const keyStore = createMemoryKeyStore();
    const keyEvents: unknown[] = [];
    const handler = createHandler(config, {
      keyStore,
      keyEventStore: {
        async append(event) {
          keyEvents.push(event);
        }
      }
    });
    await keyStore.saveUserKey({
      address: "alice@example.test",
      primaryKeyId: "old-key",
      publicKeyArmored: "old-public",
      encryptedPrivateKey: "old-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: {},
      keyVersion: 1,
      status: "active"
    });
    const response = await handler(
      new Request("http://zero-api/crypto/password/reset", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "alice@example.test",
          primaryKeyId: "new-key",
          publicKeyArmored: "new-public",
          encryptedPrivateKey: "new-envelope",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { salt: "new" },
          resetReason: "lost_password"
        })
      })
    );
    const publicResponse = await handler(new Request("http://zero-api/keys/local/alice@example.test"));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      address: "alice@example.test",
      primaryKeyId: "new-key",
      keyVersion: 2,
      status: "active",
      mode: "reset_new_identity",
      previousKeysReadable: false
    });
    expect(await publicResponse.json()).toEqual({
      address: "alice@example.test",
      primaryKeyId: "new-key",
      publicKeyArmored: "new-public",
      keyVersion: 2
    });
    expect(keyEvents).toEqual([
      expect.objectContaining({
        address: "alice@example.test",
        eventType: "password_reset",
        primaryKeyId: "new-key",
        keyVersion: 2,
        rotationMode: "password_reset",
        previousKeyId: expect.any(String)
      })
    ]);
    expect(JSON.stringify(keyEvents)).not.toContain("old-envelope");
    expect(JSON.stringify(keyEvents)).not.toContain("new-envelope");
  });

  test("returns the public key event chain for an address", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const keyStore = createMemoryKeyStore();
    const keyEventStore = createMemoryKeyEventStore();
    const handler = createHandler(config, { keyStore, keyEventStore });
    await handler(
      new Request("http://zero-api/crypto/keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "Alice@Example.Test",
          primaryKeyId: "alice-key",
          publicKeyArmored: "public",
          encryptedPrivateKey: "old-envelope",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { salt: "old" },
          keyVersion: 1
        })
      })
    );
    await handler(
      new Request("http://zero-api/crypto/password/reencrypt", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          address: "alice@example.test",
          currentPrimaryKeyId: "alice-key",
          reencryptedPrivateKey: "new-envelope",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { salt: "new" },
          currentPrivateKeyProof: "signature"
        })
      })
    );

    const response = await handler(new Request("http://zero-api/events/key/Alice%40Example.Test"));
    const body = await response.json();

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(body).toEqual({
      address: "alice@example.test",
      events: [
        expect.objectContaining({
          address: "alice@example.test",
          eventType: "created",
          primaryKeyId: "alice-key",
          keyVersion: 1,
          rotationMode: "initial",
          eventHash: expect.stringMatching(/^[a-f0-9]{64}$/)
        }),
        expect.objectContaining({
          address: "alice@example.test",
          eventType: "password_reencrypted",
          primaryKeyId: "alice-key",
          keyVersion: 2,
          rotationMode: "password_reencrypt",
          previousEventHash: expect.stringMatching(/^[a-f0-9]{64}$/),
          eventHash: expect.stringMatching(/^[a-f0-9]{64}$/)
        })
      ]
    });
    expect(body.events[1].previousEventHash).toBe(body.events[0].eventHash);
    expect(JSON.stringify(body)).not.toContain("old-envelope");
    expect(JSON.stringify(body)).not.toContain("new-envelope");
    expect(JSON.stringify(body)).not.toContain("salt");
  });

  test("stores only encrypted mail message metadata", async () => {
    await withTempBlobDir(async (root) => {
      const config = readConfig({ ZERO_ACCESS_REQUIRED: "y", ZERO_BLOB_DIR: root });
      const handler = createHandler(config);
      const createResponse = await handler(
        new Request("http://zero-api/mail/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            recipient: "Bob@Example.Test",
            ciphertextBlobId: "11111111-1111-4111-8111-111111111111",
            recipientKeyId: "bob-key",
            encryptionState: "local_e2ee"
          })
        })
      );
      const created = await createResponse.json();
      const readResponse = await handler(new Request(`http://zero-api/mail/messages/${created.id}`));
      const readBody = await readResponse.json();

      expect(createResponse.status).toBe(201);
      expect(created).toEqual({
        id: expect.any(String),
        recipient: "bob@example.test",
        ciphertextBlobId: "11111111-1111-4111-8111-111111111111",
        recipientKeyId: "bob-key",
        encryptionState: "local_e2ee"
      });
      expect(readResponse.status).toBe(200);
      expect(readBody).toEqual(created);
      expect(JSON.stringify(readBody)).not.toContain("body");
      expect(JSON.stringify(readBody)).not.toContain("hello");
    });
  });

  test("rejects cleartext fields in mail message creation", async () => {
    const config = readConfig({ ZERO_ACCESS_REQUIRED: "y" });
    const handler = createHandler(config);
    const response = await handler(
      new Request("http://zero-api/mail/messages", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          recipient: "bob@example.test",
          ciphertextBlobId: "11111111-1111-4111-8111-111111111111",
          recipientKeyId: "bob-key",
          encryptionState: "local_e2ee",
          body: "hello"
        })
      })
    );

    expect(response.status).toBe(422);
    expect(await response.json()).toEqual({ error: "cleartext_rejected" });
  });

  test("persists encrypted mail message metadata across handler instances", async () => {
    await withTempBlobDir(async (root) => {
      const config = readConfig({ ZERO_ACCESS_REQUIRED: "y", ZERO_BLOB_DIR: root });
      const createHandlerInstance = createHandler(config);
      const createResponse = await createHandlerInstance(
        new Request("http://zero-api/mail/messages", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            recipient: "bob@example.test",
            ciphertextBlobId: "11111111-1111-4111-8111-111111111111",
            recipientKeyId: "bob-key",
            encryptionState: "local_e2ee"
          })
        })
      );
      const created = await createResponse.json();
      const readHandlerInstance = createHandler(config);
      const readResponse = await readHandlerInstance(new Request(`http://zero-api/mail/messages/${created.id}`));

      expect(createResponse.status).toBe(201);
      expect(readResponse.status).toBe(200);
      expect(await readResponse.json()).toEqual(created);
    });
  });
});
