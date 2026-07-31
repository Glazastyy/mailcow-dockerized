import { readConfig, type ZeroApiConfig } from "./config";
import { arrayBufferFromBytes, createFileBlobStore, createMemoryBlobStore, type BlobStore } from "./blob-store";
import { createMemoryKeyStore, validatePasswordReencryptPayload, validateUserKeyPayload, type KeyStore } from "./key-store";
import { createFileKeyEventStore, createKeyEventCheckpoint, keyEventForUserKey, verifyKeyEventChain, type KeyEventStore } from "./key-event-store";
import { createFileMessageStore, validateMessagePayload, type MessageStore } from "./message-store";
import { createFileAttachmentStore, validateAttachmentPayload, type AttachmentStore } from "./attachment-store";
import { createFileRecoveryStore, recoveryMethods, validateRecoveryPayload, type RecoveryStore } from "./recovery-store";

type JsonValue = Record<string, unknown>;
type HandlerDeps = {
  blobStore?: BlobStore;
  blobs?: Map<string, Uint8Array>;
  keyStore?: KeyStore;
  keyEventStore?: KeyEventStore;
  messageStore?: MessageStore;
  attachmentStore?: AttachmentStore;
  recoveryStore?: RecoveryStore;
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

function ciphertextResponse(data: Uint8Array): Response {
  return new Response(arrayBufferFromBytes(data), {
    headers: {
      "content-type": "application/octet-stream",
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
  const attachmentStore = deps.attachmentStore ?? createFileAttachmentStore(config.blobDir);
  const recoveryStore = deps.recoveryStore ?? createFileRecoveryStore(config.blobDir);

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

    if (request.method === "GET" && url.pathname === "/crypto/bootstrap") {
      const address = url.searchParams.get("address");

      if (!address) {
        return jsonResponse({ error: "missing_address" }, 422);
      }

      const key = await keyStore.getActiveUserKey(address);

      if (!key) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      const recoveries = await recoveryStore.list(address);

      return jsonResponse({
        address: key.address,
        primaryKeyId: key.primaryKeyId,
        publicKeyArmored: key.publicKeyArmored,
        encryptedPrivateKey: key.encryptedPrivateKey,
        privateKeyKdf: key.privateKeyKdf,
        privateKeyKdfParams: key.privateKeyKdfParams,
        keyVersion: key.keyVersion,
        recoveryConfigured: recoveries.length > 0,
        recoveryMethods: recoveryMethods(recoveries)
      });
    }

    if (request.method === "POST" && url.pathname === "/crypto/recovery") {
      if (request.headers.get("content-type") !== "application/json") {
        return jsonResponse({ error: "json_required" }, 415);
      }

      const validation = validateRecoveryPayload((await request.json()) as Record<string, unknown>);

      if (!validation.ok) {
        return jsonResponse({ error: validation.error }, 422);
      }

      const key = await keyStore.getActiveUserKey(validation.recovery.address);

      if (!key) {
        return jsonResponse({ error: "active_key_not_found" }, 404);
      }

      const recovery = await recoveryStore.save(validation.recovery);

      return jsonResponse(
        {
          address: recovery.address,
          method: recovery.method,
          publicHint: recovery.publicHint,
          created: recovery.created
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

    if (request.method === "GET" && url.pathname.startsWith("/events/key/") && url.pathname.endsWith("/checkpoint")) {
      const address = decodeURIComponent(url.pathname.slice("/events/key/".length, -"/checkpoint".length)).toLowerCase();
      const events = await keyEventStore.list(address);

      return jsonResponse({
        address,
        checkpoint: await createKeyEventCheckpoint(address, events)
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

      return ciphertextResponse(data);
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

    if (request.method === "GET" && url.pathname === "/mail/messages") {
      const recipient = url.searchParams.get("recipient");

      if (!recipient) {
        return jsonResponse({ error: "missing_recipient" }, 422);
      }

      return jsonResponse(
        await messageStore.list({
          recipient,
          folder: url.searchParams.get("folder") ?? undefined,
          cursor: url.searchParams.get("cursor") ?? undefined,
          limit: Number(url.searchParams.get("limit") ?? undefined)
        })
      );
    }

    if (request.method === "GET" && url.pathname === "/mail/folders") {
      const recipient = url.searchParams.get("recipient");

      if (!recipient) {
        return jsonResponse({ error: "missing_recipient" }, 422);
      }

      return jsonResponse({ folders: await messageStore.folders(recipient) });
    }

    if (request.method === "POST" && url.pathname === "/mail/attachments") {
      if (request.headers.get("content-type") !== "application/json") {
        return jsonResponse({ error: "json_required" }, 415);
      }

      const validation = validateAttachmentPayload((await request.json()) as Record<string, unknown>);

      if (!validation.ok) {
        return jsonResponse({ error: validation.error }, 422);
      }

      return jsonResponse(await attachmentStore.save(validation.attachment), 201);
    }

    if (request.method === "GET" && url.pathname.startsWith("/mail/messages/") && url.pathname.endsWith("/attachments")) {
      const messageId = url.pathname.slice("/mail/messages/".length, -"/attachments".length);

      return jsonResponse({
        attachments: await attachmentStore.list(messageId)
      });
    }

    if (request.method === "GET" && url.pathname.startsWith("/mail/messages/") && url.pathname.endsWith("/blob")) {
      const messageId = url.pathname.slice("/mail/messages/".length, -"/blob".length);
      const message = await messageStore.get(messageId);

      if (!message) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      const data = await blobStore.read(message.ciphertextBlobId);

      if (!data) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      return ciphertextResponse(data);
    }

    if (request.method === "GET" && url.pathname.startsWith("/mail/attachments/") && url.pathname.endsWith("/blob")) {
      const id = url.pathname.slice("/mail/attachments/".length, -"/blob".length);
      const attachment = await attachmentStore.get(id);

      if (!attachment) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      const data = await blobStore.read(attachment.ciphertextBlobId);

      if (!data) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      return ciphertextResponse(data);
    }

    if (request.method === "GET" && url.pathname.startsWith("/mail/attachments/")) {
      const id = url.pathname.slice("/mail/attachments/".length);
      const attachment = await attachmentStore.get(id);

      if (!attachment) {
        return jsonResponse({ error: "not_found" }, 404);
      }

      return jsonResponse(attachment);
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
