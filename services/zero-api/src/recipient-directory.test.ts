import { describe, expect, test } from "bun:test";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createFileRecipientDirectory, createMemoryRecipientDirectory, validateRecipientRoutePayload } from "./recipient-directory";

describe("zero-api recipient directory validation", () => {
  test("requires a local route address and at least one recipient", () => {
    expect(validateRecipientRoutePayload({ address: "", recipients: ["alice@example.test"] })).toEqual({ ok: false, error: "missing_address" });
    expect(validateRecipientRoutePayload({ address: "team@example.test", recipients: [] })).toEqual({ ok: false, error: "missing_recipients" });
  });

  test("normalizes alias recipients without clear key material", () => {
    expect(
      validateRecipientRoutePayload({
        address: "Team@Example.Test",
        recipients: ["Alice@Example.Test", "alice@example.test", "Bob@Example.Test"],
        kind: "alias"
      })
    ).toEqual({
      ok: true,
      route: {
        address: "team@example.test",
        recipients: ["alice@example.test", "bob@example.test"],
        kind: "alias"
      }
    });
  });

  test("accepts catch-all routes as domain scoped routes", () => {
    expect(
      validateRecipientRoutePayload({
        address: "*@Example.Test",
        recipients: ["Catchall@Example.Test"],
        kind: "catch_all"
      })
    ).toEqual({
      ok: true,
      route: {
        address: "*@example.test",
        recipients: ["catchall@example.test"],
        kind: "catch_all"
      }
    });
  });
});

describe("zero-api recipient directory", () => {
  test("resolves exact aliases before catch-all routes", async () => {
    const directory = createMemoryRecipientDirectory();
    await directory.save({
      address: "*@example.test",
      recipients: ["catchall@example.test"],
      kind: "catch_all"
    });
    await directory.save({
      address: "team@example.test",
      recipients: ["alice@example.test", "bob@example.test"],
      kind: "alias"
    });

    await expect(directory.resolve("Team@Example.Test")).resolves.toEqual(["alice@example.test", "bob@example.test"]);
    await expect(directory.resolve("unknown@example.test")).resolves.toEqual(["catchall@example.test"]);
  });

  test("falls through to the original address when no route exists", async () => {
    const directory = createMemoryRecipientDirectory();

    await expect(directory.resolve("Alice@Example.Test")).resolves.toEqual(["alice@example.test"]);
  });

  test("persists recipient routes across file directory instances", async () => {
    const root = await mkdtemp(join(tmpdir(), "zero-api-recipient-directory-"));

    try {
      const firstDirectory = createFileRecipientDirectory(root);
      await firstDirectory.save({
        address: "team@example.test",
        recipients: ["alice@example.test", "bob@example.test"],
        kind: "alias"
      });

      const secondDirectory = createFileRecipientDirectory(root);

      await expect(secondDirectory.resolve("team@example.test")).resolves.toEqual(["alice@example.test", "bob@example.test"]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
