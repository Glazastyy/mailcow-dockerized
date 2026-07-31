import { readConfig, type ZeroApiConfig } from "./config";
import { createFileBlobStore, createMemoryBlobStore, type BlobStore } from "./blob-store";
import { createMemoryKeyStore, validatePasswordReencryptPayload, validateUserKeyPayload, type KeyStore } from "./key-store";
import { createFileKeyEventStore, keyEventForUserKey, verifyKeyEventChain, type KeyEventStore } from "./key-event-store";
import { createFileMessageStore, validateMessagePayload, type MessageStore } from "./message-store";

type JsonValue = Record<string, unknown>;
type HandlerDeps = {
  blobStore?: BlobStore;
  blobs?: Map<string, Uint8Array>;
  keyStore?: KeyStore;
  keyEventStore?: KeyEventStore;
  messageStore?: MessageStore;
};

function jsonResponse(body: JsonValue, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function createHandler(config: ZeroApiConfig, deps: HandlerDeps = {}) {
  return createHandlerWithDeps(config, deps);
}

export function createHandlerWithDeps(config: ZeroApiConfig, deps: HandlerDeps = {}) {
  const blobStore = deps.blobStore ?? (deps.blobs ? createMemoryBlobStore(deps.blobs) : createFileBlobStore(config.blobDir));
  const keyStore = deps.keyStore ?? createMemoryKeyStore();
  const keyEventStore = deps.keyEventStore ?? createFileKeyEventStore(config.blobDir);
  const messageStore = deps.messageStore ?? createFileMessageStore(config.blobDir);

  return async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({
        ok: true,
        service: "zero-api",
        zeroAccessRequired: config.zeroAccessRequired,
        databaseConfigured: Boolean(config.databaseName && config.databaseUser),
        redisConfigured: config.redisConfigured
      });
    }

    if (request.method === "POST" && url.pathname === "/crypto/keys") {
      if (request.headers.get("content-type") !== "application/json") {
        return jsonResponse({ error: "json_required" }, 415);
      }

      const validation = validateUserKeyPayload((await request.json()) as Record<string, unknown>);

      if (!validation.ok) {
        return jsonResponse({ error: validation.error }, 422);
      }

      const key = await keyStore.saveUserKey(validation.key);
      await keyEventStore.append(keyEventForUserKey(key, "created"));

      return jsonResponse(
        {
          address: key.address,
          primaryKeyId: key.primaryKeyId,
          keyVersion: key.keyVersion,
          status: key.status
        },
        201
      );
    }

    if (request.method === "POST" && url.pathname === "/crypto/password/reencrypt") {
      if (request.headers.get("content-type") !== "application/json") {
        return jsonResponse({ error: "json_required" }, 415);
      }

      const validation = validatePasswordReencryptPayload((await request.json()) as Record<string, unknown>);

      if (!validation.ok) {
        return jsonResponse({ error: validation.error }, 422);
      }

      const key = await keyStore.reencryptUserKey(validation.request);

      if (!key) {
        return jsonResponse({ error: "active_key_not_found" }, 404);
      }

      await keyEventStore.append(keyEventForUserKey(key, "password_reencrypted"));

      return jsonResponse({
        address: key.address,
        primaryKeyId: key.primaryKeyId,
        keyVersion: key.keyVersion,
        status: key.status,
        mode: "reencrypted"
      });
    }

    if (request.method === "POST" && url.pathname === "/crypto/password/reset") {
      if (request.headers.get("content-type") !== "application/json") {
        return jsonResponse({ error: "json_required" }, 415);
      }

      const validation = validateUserKeyPayload((await request.json()) as Record<string, unknown>);

      if (!validation.ok) {
        return jsonResponse({ error: validation.error }, 422);
      }

      const key = await keyStore.resetUserKey(validation.key);
      await keyEventStore.append(keyEventForUserKey(key, "password_reset"));

      return jsonResponse({
        address: key.address,
        primaryKeyId: key.primaryKeyId,
        keyVersion: key.keyVersion,
        status: key.status,
        mode: "reset_new_identity",
        previousKeysReadable: false
      });
    }

    if (request.method === "GET" && url.pathname.startsWith("/keys/local/")) {
      const address = decodeURIComponent(url.pathname.slice("/keys/local/".length));
      const key = await keyStore.getActiveUserKey(address);

      if (!key) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      return jsonResponse({
        address: key.address,
        primaryKeyId: key.primaryKeyId,
        publicKeyArmored: key.publicKeyArmored,
        keyVersion: key.keyVersion
      });
    }

    if (request.method === "GET" && url.pathname.startsWith("/events/key/") && url.pathname.endsWith("/verify")) {
      const address = decodeURIComponent(url.pathname.slice("/events/key/".length, -"/verify".length)).toLowerCase();
      const events = await keyEventStore.list(address);

      return jsonResponse({
        address,
        verification: await verifyKeyEventChain(events)
      });
    }

    if (request.method === "GET" && url.pathname.startsWith("/events/key/")) {
      const address = decodeURIComponent(url.pathname.slice("/events/key/".length)).toLowerCase();
      const events = await keyEventStore.list(address);

      return jsonResponse({
        address,
        events
      });
    }

    if (request.method === "POST" && url.pathname === "/blob") {
      if (
        request.headers.get("content-type") !== "application/octet-stream" ||
        request.headers.get("x-zero-blob-kind") !== "ciphertext"
      ) {
        return jsonResponse({ error: "ciphertext_blob_required" }, 415);
      }

      const data = new Uint8Array(await request.arrayBuffer());

      if (data.byteLength === 0) {
        return jsonResponse({ error: "empty_blob" }, 400);
      }

      return jsonResponse(await blobStore.write(data), 201);
    }

    if (request.method === "GET" && url.pathname.startsWith("/blob/")) {
      const id = url.pathname.slice("/blob/".length);
      const data = await blobStore.read(id);

      if (!data) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      return new Response(data, {
        headers: {
          "content-type": "application/octet-stream",
          "cache-control": "no-store"
        }
      });
    }

    if (request.method === "POST" && url.pathname === "/mail/messages") {
      if (request.headers.get("content-type") !== "application/json") {
        return jsonResponse({ error: "json_required" }, 415);
      }

      const validation = validateMessagePayload((await request.json()) as Record<string, unknown>);

      if (!validation.ok) {
        return jsonResponse({ error: validation.error }, 422);
      }

      return jsonResponse(await messageStore.save(validation.message), 201);
    }

    if (request.method === "GET" && url.pathname.startsWith("/mail/messages/")) {
      const id = url.pathname.slice("/mail/messages/".length);
      const message = await messageStore.get(id);

      if (!message) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      return jsonResponse(message);
    }

    if (url.pathname.startsWith("/mail/") || url.pathname.startsWith("/crypto/")) {
      return jsonResponse({ error: "not_implemented" }, 501);
    }

    return jsonResponse({ error: "not_found" }, 404);
  };
}

export function startServer(env: Record<string, string | undefined> = process.env) {
  const config = readConfig(env);
  return Bun.serve({
    hostname: config.host,
    port: config.port,
    fetch: createHandlerWithDeps(config)
  });
}
