import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const composeEnv = {
  ...process.env,
  MAILCOW_HOSTNAME: "mail.example.test",
  DBROOT: "rootpass",
  DBNAME: "mailcow",
  DBUSER: "mailcow",
  DBPASS: "dbpass",
  REDISPASS: "redispass",
  TZ: "UTC",
  COMPOSE_PROJECT_NAME: "mailcowdockerized",
  IPV4_NETWORK: "172.22.1",
  IPV6_NETWORK: "fd4d:6169:6c63:6f77::/64",
  ENABLE_IPV6: "false",
  ZERO_ACCESS_REQUIRED: "y"
};

function read(path: string) {
  return readFileSync(path, "utf8");
}

function composeConfig() {
  const result = spawnSync("docker", ["compose", "config", "--format", "json"], {
    env: composeEnv,
    encoding: "utf8"
  });

  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout);
  }

  return JSON.parse(result.stdout);
}

describe("zero-access generated defaults", () => {
  test("generate_config.sh creates a zero-access configuration", () => {
    const config = read("generate_config.sh");

    expect(config).toContain("ZERO_ACCESS_REQUIRED=y");
    expect(config).toContain("SKIP_SOGO=y");
    expect(config).toContain("IMAP_PORT=127.0.0.1:143");
    expect(config).toContain("IMAPS_PORT=127.0.0.1:993");
    expect(config).toContain("POP_PORT=127.0.0.1:110");
    expect(config).toContain("POPS_PORT=127.0.0.1:995");
    expect(config).toContain("SIEVE_PORT=127.0.0.1:4190");
  });

  test("vendor reference repositories stay ignored", () => {
    const ignore = read(".gitignore");

    expect(ignore).toContain("vendor-reference/");
  });
});

describe("zero-access compose topology", () => {
  test("docker compose config is valid and includes zero-api", () => {
    const config = composeConfig();

    expect(config.services["zero-api-mailcow"]).toBeDefined();
    expect(config.services["zero-api-mailcow"].environment.ZERO_ACCESS_REQUIRED).toBe("y");
    expect(config.services["zero-api-mailcow"].environment.ZERO_BLOB_DIR).toBe("/var/lib/zero-api/blobs");
    expect(config.volumes["zero-blob-vol-1"]).toBeDefined();
  });

  test("zero-api stores blobs in the dedicated ciphertext volume", () => {
    const config = composeConfig();
    const volumes = config.services["zero-api-mailcow"].volumes;

    expect(volumes).toContainEqual(
      expect.objectContaining({
        source: "zero-blob-vol-1",
        target: "/var/lib/zero-api/blobs"
      })
    );
  });

  test("docker compose config includes internal zero-delivery", () => {
    const config = composeConfig();
    const service = config.services["zero-delivery-mailcow"];

    expect(service).toBeDefined();
    expect(service.environment.ZERO_ACCESS_REQUIRED).toBe("y");
    expect(service.expose).toContain("2525");
    expect(service.ports).toBeUndefined();
  });

  test("legacy mailbox protocols bind to localhost by default", () => {
    const config = composeConfig();
    const ports = config.services["dovecot-mailcow"].ports;
    const expected = new Map([
      [143, "127.0.0.1"],
      [993, "127.0.0.1"],
      [110, "127.0.0.1"],
      [995, "127.0.0.1"],
      [4190, "127.0.0.1"]
    ]);

    for (const port of ports) {
      if (expected.has(port.target)) {
        expect(port.host_ip).toBe(expected.get(port.target));
      }
    }
  });

  test("zero-access web and scheduler path do not hard-depend on legacy webmail", () => {
    const config = composeConfig();

    expect(config.services["nginx-mailcow"].depends_on?.["sogo-mailcow"]).toBeUndefined();
    expect(config.services["ofelia-mailcow"].depends_on?.["sogo-mailcow"]).toBeUndefined();
  });

  test("watchdog no longer blocks startup on legacy mailbox storage", () => {
    const config = composeConfig();

    expect(config.services["watchdog-mailcow"].depends_on?.["dovecot-mailcow"]).toBeUndefined();
    expect(config.services["watchdog-mailcow"].depends_on?.["sogo-mailcow"]).toBeUndefined();
  });
});
