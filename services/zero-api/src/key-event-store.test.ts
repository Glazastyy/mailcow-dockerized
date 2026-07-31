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
      previousEventHash: undefined,
      eventHash: expect.stringMatching(/^[a-f0-9]{64}$/),
      created: expect.any(String)
    });
    expect(JSON.stringify(events)).not.toContain("private-envelope");
    expect(JSON.stringify(events)).not.toContain("secret-salt");
  });

  test("chains events by address with deterministic hashes", async () => {
    const store = createMemoryKeyEventStore();
    const first = await store.append({
      address: "alice@example.test",
      eventType: "created",
      primaryKeyId: "alice-key",
      keyVersion: 1,
      rotationMode: "initial"
    });
    const second = await store.append({
      address: "alice@example.test",
      eventType: "password_reencrypted",
      primaryKeyId: "alice-key",
      keyVersion: 2,
      rotationMode: "password_reencrypt",
      previousKeyId: "previous-key-row"
    });

    expect(first.previousEventHash).toBeUndefined();
    expect(first.eventHash).toMatch(/^[a-f0-9]{64}$/);
    expect(second.previousEventHash).toBe(first.eventHash);
    expect(second.eventHash).toMatch(/^[a-f0-9]{64}$/);
    expect(second.eventHash).not.toBe(first.eventHash);
  });

  test("keeps independent event chains for different addresses", async () => {
    const store = createMemoryKeyEventStore();
    const alice = await store.append({
      address: "alice@example.test",
      eventType: "created",
      primaryKeyId: "alice-key",
      keyVersion: 1,
      rotationMode: "initial"
    });
    const bob = await store.append({
      address: "bob@example.test",
      eventType: "created",
      primaryKeyId: "bob-key",
      keyVersion: 1,
      rotationMode: "initial"
    });

    expect(alice.eventHash).toMatch(/^[a-f0-9]{64}$/);
    expect(bob.eventHash).toMatch(/^[a-f0-9]{64}$/);
    expect(bob.previousEventHash).toBeUndefined();
  });
});
