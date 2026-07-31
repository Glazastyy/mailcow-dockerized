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
  list(address: string): Promise<KeyEvent[]>;
};

type KeyEventInput = Omit<KeyEvent, "created" | "previousEventHash" | "eventHash">;

export type KeyEventChainVerification =
  | { ok: true; eventCount: number; headEventHash?: string }
  | { ok: false; eventCount: number; error: "event_hash_mismatch" | "previous_event_hash_mismatch"; failedAt: number };

export type KeyEventCheckpoint =
  | { address: string; ok: true; eventCount: number; headEventHash?: string; checkpointHash: string }
  | { address: string; ok: false; eventCount: number; error: "event_hash_mismatch" | "previous_event_hash_mismatch"; failedAt: number };

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

function eventInputFromStored(event: KeyEvent): KeyEventInput {
  return {
    address: event.address,
    eventType: event.eventType,
    primaryKeyId: event.primaryKeyId,
    keyVersion: event.keyVersion,
    rotationMode: event.rotationMode,
    previousKeyId: event.previousKeyId
  };
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
    },
    async list(address) {
      const normalizedAddress = address.toLowerCase();
      return events.filter((event) => event.address === normalizedAddress);
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
    },
    async list(address) {
      return readEventsForAddress(eventsPath, address);
    }
  };
}

async function readEventsForAddress(path: string, address: string) {
  const events = await readAllEvents(path);
  const normalizedAddress = address.toLowerCase();
  return events.filter((event) => event.address === normalizedAddress);
}

async function readLastEventHashForAddress(path: string, address: string) {
  const events = await readEventsForAddress(path, address);
  return events.at(-1)?.eventHash;
}

async function readAllEvents(path: string) {
  let data: string;

  try {
    data = await readFile(path, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return undefined;
    }

    throw error;
  }

  const events: KeyEvent[] = [];

  for (const line of data.trimEnd().split("\n")) {
    if (!line) {
      continue;
    }

    const parsed = JSON.parse(line) as Partial<KeyEvent>;

    if (isKeyEvent(parsed)) {
      events.push(parsed);
    }
  }

  return events;
}

function isKeyEvent(value: Partial<KeyEvent>): value is KeyEvent {
  return (
    typeof value.address === "string" &&
    typeof value.eventType === "string" &&
    typeof value.primaryKeyId === "string" &&
    typeof value.keyVersion === "number" &&
    typeof value.rotationMode === "string" &&
    typeof value.eventHash === "string" &&
    typeof value.created === "string"
  );
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

export async function verifyKeyEventChain(events: KeyEvent[]): Promise<KeyEventChainVerification> {
  let previousEventHash: string | undefined;

  for (const [index, event] of events.entries()) {
    if (event.previousEventHash !== previousEventHash) {
      return {
        ok: false,
        eventCount: events.length,
        error: "previous_event_hash_mismatch",
        failedAt: index
      };
    }

    const expectedHash = await sha256(canonicalEventPayload(eventInputFromStored(event), event.created, event.previousEventHash));

    if (event.eventHash !== expectedHash) {
      return {
        ok: false,
        eventCount: events.length,
        error: "event_hash_mismatch",
        failedAt: index
      };
    }

    previousEventHash = event.eventHash;
  }

  return {
    ok: true,
    eventCount: events.length,
    headEventHash: previousEventHash
  };
}

export async function createKeyEventCheckpoint(address: string, events: KeyEvent[]): Promise<KeyEventCheckpoint> {
  const normalizedAddress = address.toLowerCase();
  const verification = await verifyKeyEventChain(events);

  if (!verification.ok) {
    return {
      address: normalizedAddress,
      ...verification
    };
  }

  const checkpointHash = await sha256(
    JSON.stringify({
      address: normalizedAddress,
      eventCount: verification.eventCount,
      headEventHash: verification.headEventHash
    })
  );

  return {
    address: normalizedAddress,
    ...verification,
    checkpointHash
  };
}
