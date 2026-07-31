import { describe, expect, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileMessageStore, createMemoryMessageStore, validateMessagePayload, validateMessageUpdatePayload } from "./message-store";

describe("zero-api message validation", () => {
  test("rejects cleartext message fields", () => {
    expect(
      validateMessagePayload({
        recipient: "alice@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "alice-key",
        encryptionState: "local_e2ee",
        subject: "hello"
      })
    ).toEqual({ ok: false, error: "cleartext_rejected" });
  });

  test("rejects unsupported message flags", () => {
    expect(
      validateMessagePayload({
        recipient: "alice@example.test",
        ciphertextBlobId: "blob-id",
        recipientKeyId: "alice-key",
        encryptionState: "local_e2ee",
        flags: ["seen", "leaked"]
      })
    ).toEqual({ ok: false, error: "unsupported_flag" });
  });

  test("rejects cleartext update fields before folder validation", () => {
    expect(
      validateMessageUpdatePayload({
        folder: "wiretap",
        subject: "hello"
      })
    ).toEqual({ ok: false, error: "cleartext_rejected" });
  });
});

describe("zero-api message store", () => {
  test("updates folder and flags in memory", async () => {
    const store = createMemoryMessageStore();
    const message = await store.save({
      recipient: "Alice@Example.Test",
      folder: "inbox",
      ciphertextBlobId: "blob-id",
      recipientKeyId: "alice-key",
      encryptionState: "local_e2ee",
      flags: ["unread"]
    });
    const updated = await store.update(message.id, {
      folder: "archive",
      flags: ["seen", "starred"]
    });

    if (!updated) {
      throw new Error("Expected message update");
    }

    expect(updated).toEqual({
      ...message,
      folder: "archive",
      flags: ["seen", "starred"]
    });
    await expect(store.list({ recipient: "alice@example.test", folder: "inbox" })).resolves.toEqual({ messages: [] });
    await expect(store.list({ recipient: "alice@example.test", folder: "archive" })).resolves.toEqual({ messages: [updated] });
  });

  test("persists folder and flag updates in the file store", async () => {
    const root = await mkdtemp(join(tmpdir(), "zero-messages-"));
    const firstStore = createFileMessageStore(root);
    const message = await firstStore.save({
      recipient: "alice@example.test",
      folder: "inbox",
      ciphertextBlobId: "blob-id",
      recipientKeyId: "alice-key",
      encryptionState: "local_e2ee",
      flags: ["unread"]
    });
    const updated = await firstStore.update(message.id, {
      folder: "trash",
      flags: ["seen"]
    });
    const secondStore = createFileMessageStore(root);

    if (!updated) {
      throw new Error("Expected message update");
    }

    await expect(secondStore.get(message.id)).resolves.toEqual(updated);
    await expect(secondStore.list({ recipient: "alice@example.test", folder: "trash" })).resolves.toEqual({ messages: [updated] });
  });
});
