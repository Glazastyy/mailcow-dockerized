import { describe, expect, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileRecoveryStore, createMemoryRecoveryStore, recoveryMethods, validateRecoveryPayload } from "./recovery-store";

describe("zero-api recovery validation", () => {
  test("rejects clear recovery secrets", () => {
    expect(
      validateRecoveryPayload({
        address: "alice@example.test",
        method: "recovery_phrase",
        encryptedRecoveryPacket: "sealed",
        recoveryPhrase: "correct horse battery staple"
      })
    ).toEqual({ ok: false, error: "clear_recovery_secret_rejected" });
  });

  test("requires an encrypted recovery packet", () => {
    expect(
      validateRecoveryPayload({
        address: "alice@example.test",
        method: "recovery_phrase"
      })
    ).toEqual({ ok: false, error: "missing_encryptedRecoveryPacket" });
  });

  test("rejects unsupported recovery methods", () => {
    expect(
      validateRecoveryPayload({
        address: "alice@example.test",
        method: "plain_email",
        encryptedRecoveryPacket: "sealed"
      })
    ).toEqual({ ok: false, error: "unsupported_recovery_method" });
  });
});

describe("zero-api recovery store", () => {
  test("stores active recovery packets without exposing them in method summaries", async () => {
    const store = createMemoryRecoveryStore();
    const recovery = await store.save({
      address: "Alice@Example.Test",
      method: "recovery_phrase",
      encryptedRecoveryPacket: "sealed-recovery-packet",
      publicHint: "printed July 2026"
    });
    const records = await store.list("alice@example.test");

    expect(recovery).toEqual({
      id: expect.any(String),
      address: "alice@example.test",
      method: "recovery_phrase",
      encryptedRecoveryPacket: "sealed-recovery-packet",
      publicHint: "printed July 2026",
      created: expect.any(String)
    });
    expect(records).toEqual([recovery]);
    expect(recoveryMethods(records)).toEqual(["recovery_phrase"]);
    expect(JSON.stringify(recoveryMethods(records))).not.toContain("sealed-recovery-packet");
  });

  test("persists recovery records across file store instances", async () => {
    const root = await mkdtemp(join(tmpdir(), "zero-recovery-"));
    const firstStore = createFileRecoveryStore(root);
    const recovery = await firstStore.save({
      address: "alice@example.test",
      method: "printed_key",
      encryptedRecoveryPacket: "sealed-recovery-packet",
      publicHint: "paper safe"
    });
    const secondStore = createFileRecoveryStore(root);

    await expect(secondStore.list("alice@example.test")).resolves.toEqual([recovery]);
  });
});
