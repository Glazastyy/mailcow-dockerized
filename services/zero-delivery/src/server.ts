import { readConfig, type ZeroDeliveryConfig } from "./config";
import {
  createHttpMessageSink,
  createHttpRecipientKeyResolver,
  validateResolvedDelivery,
  type DeliveryRequest,
  type MessageSink,
  type RecipientKeyResolver
} from "./delivery";

type HandlerDeps = {
  recipientKeyResolver?: RecipientKeyResolver;
  messageSink?: MessageSink;
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
      const body = (await request.json()) as DeliveryRequest;
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
