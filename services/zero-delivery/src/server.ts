import { readConfig, type ZeroDeliveryConfig } from "./config";
import { validateDelivery, type DeliveryRequest } from "./delivery";

function jsonResponse(body: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function createHandler(config: ZeroDeliveryConfig) {
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
      const result = validateDelivery(body);

      return jsonResponse(result, result.ok ? 202 : 422);
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
