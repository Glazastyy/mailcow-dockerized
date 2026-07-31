import { readConfig, type ZeroDeliveryConfig } from "./config";
import {
  createHttpMessageSink,
  createHttpCiphertextBlobSink,
  createHttpRecipientKeyResolver,
  decodeCiphertext,
  deliveryRecipients,
  hasCleartextFields,
  type CiphertextBlobSink,
  type DeliveryRequest,
  type MessageSink,
  type RecipientKeyResolver
} from "./delivery";

type HandlerDeps = {
  recipientKeyResolver?: RecipientKeyResolver;
  messageSink?: MessageSink;
  ciphertextBlobSink?: CiphertextBlobSink;
};

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function createHandler(config: ZeroDeliveryConfig, deps: HandlerDeps = {}) {
  const recipientKeyResolver = deps.recipientKeyResolver ?? createHttpRecipientKeyResolver(config.zeroApiBaseUrl);
  const messageSink = deps.messageSink ?? createHttpMessageSink(config.zeroApiBaseUrl);
  const ciphertextBlobSink = deps.ciphertextBlobSink ?? createHttpCiphertextBlobSink(config.zeroApiBaseUrl);

  return async function handler(request: Request): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && url.pathname === "/health") {
      return jsonResponse({
        ok: true,
        service: "zero-delivery",
        zeroAccessRequired: config.zeroAccessRequired
      });
    }

    if (request.method === "POST" && url.pathname === "/deliver") {
      let body = (await request.json()) as DeliveryRequest;

      if (hasCleartextFields(body)) {
        return jsonResponse({ ok: false, error: "cleartext_rejected" }, 422);
      }

      const recipients = deliveryRecipients(body);

      if (recipients.length === 0) {
        return jsonResponse({ ok: false, error: "recipient_key_required" }, 422);
      }

      const recipientKeys = [];

      for (const recipient of recipients) {
        const key = await recipientKeyResolver.resolve(recipient);

        if (!key) {
          return jsonResponse({ ok: false, error: "recipient_key_required", recipient }, 422);
        }

        recipientKeys.push(key);
      }

      const inlineCiphertext = body.ciphertext ? decodeCiphertext(body.ciphertext) : undefined;

      if (!body.ciphertextBlobId && !inlineCiphertext) {
        return jsonResponse({ ok: false, error: "ciphertext_required" }, 422);
      }

      if (!["local_e2ee", "openpgp", "password_portal"].includes(body.encryptionState)) {
        return jsonResponse({ ok: false, error: "unsupported_encryption_state" }, 422);
      }

      const deliveries = [];

      for (const key of recipientKeys) {
        let ciphertextBlobId = body.ciphertextBlobId;

        if (!ciphertextBlobId && inlineCiphertext) {
          const blob = await ciphertextBlobSink.store(inlineCiphertext);
          ciphertextBlobId = blob.id;
        }

        if (!ciphertextBlobId) {
          return jsonResponse({ ok: false, error: "ciphertext_required" }, 422);
        }

        const accepted = {
          recipient: key.address,
          ciphertextBlobId,
          recipientKeyId: key.primaryKeyId,
          encryptionState: body.encryptionState
        };
        await messageSink.store(accepted);
        deliveries.push({
          recipient: accepted.recipient,
          ciphertextBlobId: accepted.ciphertextBlobId
        });
      }

      if (deliveries.length === 1) {
        return jsonResponse({ ok: true, ...deliveries[0] }, 202);
      }

      return jsonResponse({ ok: true, deliveries }, 202);
    }

    return jsonResponse({ error: "not_found" }, 404);
  };
}

export function startServer(env: Record<string, string | undefined> = process.env) {
  const config = readConfig(env);

  return Bun.serve({
    hostname: config.host,
    port: config.port,
    fetch: createHandler(config)
  });
}
