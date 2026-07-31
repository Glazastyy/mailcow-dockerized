import { describe, expect, test } from "bun:test";
import { createMemoryKeyStore, validateUserKeyPayload } from "./key-store";

describe("zero-api key validation", () => {
  test("rejects clear private key field names", () => {
    expect(
      validateUserKeyPayload({
        address: "alice@example.test",
        primaryKeyId: "key",
        publicKeyArmored: "public",
        encryptedPrivateKey: "encrypted",
        privateKey: "clear",
        privateKeyKdf: "argon2id",
        privateKeyKdfParams: {}
      })
    ).toEqual({ ok: false, error: "clear_private_key_rejected" });
  });

  test("requires encrypted private key material", () => {
    expect(
      validateUserKeyPayload({
        address: "alice@example.test",
        primaryKeyId: "key",
        publicKeyArmored: "public",
        privateKeyKdf: "argon2id",
        privateKeyKdfParams: {}
      })
    ).toEqual({ ok: false, error: "missing_encryptedPrivateKey" });
  });
});

describe("zero-api key store", () => {
  test("normalizes addresses and returns only active keys", async () => {
    const store = createMemoryKeyStore();
    await store.saveUserKey({
      address: "Alice@Example.Test",
      primaryKeyId: "key",
      publicKeyArmored: "public",
      encryptedPrivateKey: "encrypted",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: {},
      keyVersion: 1,
      status: "active"
    });

    expect(await store.getActiveUserKey("alice@example.test")).toEqual(
      expect.objectContaining({
        address: "alice@example.test",
        publicKeyArmored: "public"
      })
    );
  });
});
