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
});
