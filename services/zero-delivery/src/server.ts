import { readConfig, type ZeroDeliveryConfig } from "./config";
import {
  createHttpMessageSink,
  createHttpCiphertextBlobSink,
  createHttpRecipientKeyResolver,
  decodeCiphertext,
  hasCleartextFields,
  validateResolvedDelivery,
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

      if (!body.ciphertextBlobId && body.ciphertext) {
        const ciphertext = decodeCiphertext(body.ciphertext);

        if (!ciphertext) {
          return jsonResponse({ ok: false, error: "ciphertext_required" }, 422);
        }

        const blob = await ciphertextBlobSink.store(ciphertext);
        body = {
          ...body,
          ciphertext: undefined,
          ciphertextBlobId: blob.id
        };
      }

      const result = await validateResolvedDelivery(body, recipientKeyResolver);

      if (!result.ok) {
        return jsonResponse(result, 422);
      }

      await messageSink.store(result.accepted);

      return jsonResponse(
        {
          ok: true,
          recipient: result.recipient,
          ciphertextBlobId: result.ciphertextBlobId
        },
        202
      );
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
