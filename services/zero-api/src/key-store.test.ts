import { describe, expect, test } from "bun:test";
import { createMemoryKeyStore, validatePasswordReencryptPayload, validateUserKeyPayload } from "./key-store";

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

  test("rejects raw passwords during private key re-encryption", () => {
    expect(
      validatePasswordReencryptPayload({
        address: "alice@example.test",
        currentPrimaryKeyId: "key",
        reencryptedPrivateKey: "new-envelope",
        privateKeyKdf: "argon2id",
        privateKeyKdfParams: {},
        currentPrivateKeyProof: "signature",
        currentPassword: "old-password"
      })
    ).toEqual({ ok: false, error: "clear_password_rejected" });
  });

  test("requires proof of the current unlocked private key for re-encryption", () => {
    expect(
      validatePasswordReencryptPayload({
        address: "alice@example.test",
        currentPrimaryKeyId: "key",
        reencryptedPrivateKey: "new-envelope",
        privateKeyKdf: "argon2id",
        privateKeyKdfParams: {}
      })
    ).toEqual({ ok: false, error: "missing_currentPrivateKeyProof" });
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
      status: "active",
      rotationMode: "initial"
    });

    expect(await store.getActiveUserKey("alice@example.test")).toEqual(
      expect.objectContaining({
        address: "alice@example.test",
        publicKeyArmored: "public"
      })
    );
  });

  test("re-encrypts the private key with a new password envelope without changing the public key", async () => {
    const store = createMemoryKeyStore();
    await store.saveUserKey({
      address: "alice@example.test",
      primaryKeyId: "key",
      publicKeyArmored: "public",
      encryptedPrivateKey: "old-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: { salt: "old" },
      keyVersion: 1,
      status: "active",
      rotationMode: "initial"
    });

    const updated = await store.reencryptUserKey({
      address: "alice@example.test",
      currentPrimaryKeyId: "key",
      reencryptedPrivateKey: "new-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: { salt: "new" },
      currentPrivateKeyProof: "signature"
    });

    expect(updated).toEqual({
      id: expect.any(String),
      address: "alice@example.test",
      primaryKeyId: "key",
      publicKeyArmored: "public",
      encryptedPrivateKey: "new-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: { salt: "new" },
      keyVersion: 2,
      status: "active",
      rotationMode: "password_reencrypt",
      previousKeyId: expect.any(String)
    });
    expect(await store.getActiveUserKey("alice@example.test")).toEqual(updated);
  });

  test("resets the account cryptographic identity when the current password is unavailable", async () => {
    const store = createMemoryKeyStore();
    await store.saveUserKey({
      address: "alice@example.test",
      primaryKeyId: "old-key",
      publicKeyArmored: "old-public",
      encryptedPrivateKey: "old-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: {},
      keyVersion: 1,
      status: "active",
      rotationMode: "initial"
    });

    const reset = await store.resetUserKey({
      address: "alice@example.test",
      primaryKeyId: "new-key",
      publicKeyArmored: "new-public",
      encryptedPrivateKey: "new-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: { salt: "new" },
      keyVersion: 1,
      status: "active",
      rotationMode: "initial"
    });

    expect(reset).toEqual({
      id: expect.any(String),
      address: "alice@example.test",
      primaryKeyId: "new-key",
      publicKeyArmored: "new-public",
      encryptedPrivateKey: "new-envelope",
      privateKeyKdf: "argon2id",
      privateKeyKdfParams: { salt: "new" },
      keyVersion: 2,
      status: "active",
      rotationMode: "password_reset",
      previousKeyId: expect.any(String)
    });
    expect(await store.getActiveUserKey("alice@example.test")).toEqual(reset);
  });
});
