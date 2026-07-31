import { readConfig, type ZeroApiConfig } from "./config";
import { createFileBlobStore, createMemoryBlobStore, type BlobStore } from "./blob-store";

type JsonValue = Record<string, unknown>;
type HandlerDeps = {
  blobStore?: BlobStore;
  blobs?: Map<string, Uint8Array>;
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
