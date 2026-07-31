import { readConfig, type ZeroApiConfig } from "./config";

type JsonValue = Record<string, unknown>;

function jsonResponse(body: JsonValue, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export function createHandler(config: ZeroApiConfig) {
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
    fetch: createHandler(config)
  });
}
