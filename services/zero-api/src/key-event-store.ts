import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { UserKey } from "./key-store";

export type KeyEventType = "created" | "rotated" | "revoked" | "recovered" | "verified" | "password_reencrypted" | "password_reset";

export type KeyEvent = {
  address: string;
  eventType: KeyEventType;
  primaryKeyId: string;
  keyVersion: number;
  rotationMode: UserKey["rotationMode"];
  previousKeyId?: string;
  previousEventHash?: string;
  eventHash: string;
  created: string;
};

export type KeyEventStore = {
  append(event: KeyEventInput): Promise<KeyEvent>;
};

type KeyEventInput = Omit<KeyEvent, "created" | "previousEventHash" | "eventHash">;

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function canonicalEventPayload(event: KeyEventInput, created: string, previousEventHash?: string) {
  return JSON.stringify({
    address: event.address.toLowerCase(),
    eventType: event.eventType,
    primaryKeyId: event.primaryKeyId,
    keyVersion: event.keyVersion,
    rotationMode: event.rotationMode,
    previousKeyId: event.previousKeyId,
    previousEventHash,
    created
  });
}

async function buildStoredEvent(event: KeyEventInput, previousEventHash?: string): Promise<KeyEvent> {
  const created = new Date().toISOString();
  const normalized = {
    ...event,
    address: event.address.toLowerCase()
  };
  const eventHash = await sha256(canonicalEventPayload(normalized, created, previousEventHash));

  return {
    ...normalized,
    previousEventHash,
    eventHash,
    created
  };
}

export function createMemoryKeyEventStore(events: KeyEvent[] = []): KeyEventStore {
  return {
    async append(event) {
      const previousEventHash = events.findLast((storedEvent) => storedEvent.address === event.address.toLowerCase())?.eventHash;
      const stored = await buildStoredEvent(event, previousEventHash);
      events.push(stored);
      return stored;
    }
  };
}

export function createFileKeyEventStore(root: string): KeyEventStore {
  const directory = join(root, "key-events");
  const eventsPath = join(directory, "records.jsonl");

  return {
    async append(event) {
      const previousEventHash = await readLastEventHashForAddress(eventsPath, event.address);
      const stored = await buildStoredEvent(event, previousEventHash);
      await mkdir(directory, { recursive: true });
      await appendFile(eventsPath, `${JSON.stringify(stored)}\n`, { encoding: "utf8" });
      return stored;
    }
  };
}

async function readLastEventHashForAddress(path: string, address: string) {
  let data: string;

  try {
    data = await readFile(path, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return undefined;
    }

    throw error;
  }

  const normalizedAddress = address.toLowerCase();
  let previousEventHash: string | undefined;

  for (const line of data.trimEnd().split("\n")) {
    if (!line) {
      continue;
    }

    const parsed = JSON.parse(line) as Partial<KeyEvent>;

    if (parsed.address === normalizedAddress && typeof parsed.eventHash === "string") {
      previousEventHash = parsed.eventHash;
    }
  }

  return previousEventHash;
}

export function keyEventForUserKey(key: UserKey, eventType: KeyEventType): KeyEventInput {
  return {
    address: key.address,
    eventType,
    primaryKeyId: key.primaryKeyId,
    keyVersion: key.keyVersion,
    rotationMode: key.rotationMode,
    previousKeyId: key.previousKeyId
  };
}
