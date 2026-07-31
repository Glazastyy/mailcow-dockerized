import { describe, expect, test } from "bun:test";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createFileAttachmentStore, createMemoryAttachmentStore, validateAttachmentPayload } from "./attachment-store";

describe("zero-api attachment validation", () => {
  test("rejects clear attachment names", () => {
    expect(
      validateAttachmentPayload({
        messageId: "message-id",
        ciphertextBlobId: "blob-id",
        filename: "report.pdf",
        size: 10,
        sha256Ciphertext: "a".repeat(64)
      })
    ).toEqual({ ok: false, error: "cleartext_rejected" });
  });

  test("requires ciphertext integrity metadata", () => {
    expect(
      validateAttachmentPayload({
        messageId: "message-id",
        ciphertextBlobId: "blob-id",
        size: 10,
        sha256Ciphertext: "not-a-hash"
      })
    ).toEqual({ ok: false, error: "invalid_sha256Ciphertext" });
  });

  test("rejects negative attachment sizes", () => {
    expect(
      validateAttachmentPayload({
        messageId: "message-id",
        ciphertextBlobId: "blob-id",
        size: -1,
        sha256Ciphertext: "a".repeat(64)
      })
    ).toEqual({ ok: false, error: "invalid_size" });
  });
});

describe("zero-api attachment store", () => {
  test("stores encrypted attachment metadata by message", async () => {
    const store = createMemoryAttachmentStore();
    const attachment = await store.save({
      messageId: "message-id",
      ciphertextBlobId: "blob-id",
      encryptedName: "sealed-name",
      mimeType: "application/octet-stream",
      size: 10,
      sha256Ciphertext: "a".repeat(64)
    });

    await expect(store.get(attachment.id)).resolves.toEqual(attachment);
    await expect(store.list("message-id")).resolves.toEqual([attachment]);
    await expect(store.list("other-message")).resolves.toEqual([]);
    expect(JSON.stringify(attachment)).not.toContain("report.pdf");
  });

  test("persists encrypted attachment metadata across file store instances", async () => {
    const root = await mkdtemp(join(tmpdir(), "zero-attachments-"));
    const firstStore = createFileAttachmentStore(root);
    const attachment = await firstStore.save({
      messageId: "message-id",
      ciphertextBlobId: "blob-id",
      encryptedName: "sealed-name",
      mimeType: "application/octet-stream",
      size: 10,
      sha256Ciphertext: "a".repeat(64)
    });
    const secondStore = createFileAttachmentStore(root);

    await expect(secondStore.get(attachment.id)).resolves.toEqual(attachment);
    await expect(secondStore.list("message-id")).resolves.toEqual([attachment]);
  });
});
