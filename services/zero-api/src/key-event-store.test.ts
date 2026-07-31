import { describe, expect, test } from "bun:test";
import { createMemoryKeyEventStore, keyEventForUserKey } from "./key-event-store";

describe("zero-api key events", () => {
  test("stores normalized key events without private key envelopes", async () => {
    const events: unknown[] = [];
    const store = createMemoryKeyEventStore(events as never);
    const event = await store.append(
      keyEventForUserKey(
        {
          id: "key-row",
          address: "Alice@Example.Test",
          primaryKeyId: "alice-key",
          publicKeyArmored: "public",
          encryptedPrivateKey: "private-envelope",
          privateKeyKdf: "argon2id",
          privateKeyKdfParams: { salt: "secret-salt" },
          keyVersion: 2,
          status: "active",
          rotationMode: "password_reencrypt",
          previousKeyId: "previous-row"
        },
        "password_reencrypted"
      )
    );

    expect(event).toEqual({
      address: "alice@example.test",
      eventType: "password_reencrypted",
      primaryKeyId: "alice-key",
      keyVersion: 2,
      rotationMode: "password_reencrypt",
      previousKeyId: "previous-row",
      created: expect.any(String)
    });
    expect(JSON.stringify(events)).not.toContain("private-envelope");
    expect(JSON.stringify(events)).not.toContain("secret-salt");
  });
});
