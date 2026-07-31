import { appendFile, mkdir } from "node:fs/promises";
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
  created: string;
};

export type KeyEventStore = {
  append(event: Omit<KeyEvent, "created">): Promise<KeyEvent>;
};

export function createMemoryKeyEventStore(events: KeyEvent[] = []): KeyEventStore {
  return {
    async append(event) {
      const stored = {
        ...event,
        address: event.address.toLowerCase(),
        created: new Date().toISOString()
      };
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
      const stored = {
        ...event,
        address: event.address.toLowerCase(),
        created: new Date().toISOString()
      };
      await mkdir(directory, { recursive: true });
      await appendFile(eventsPath, `${JSON.stringify(stored)}\n`, { encoding: "utf8" });
      return stored;
    }
  };
}

export function keyEventForUserKey(key: UserKey, eventType: KeyEventType): Omit<KeyEvent, "created"> {
  return {
    address: key.address,
    eventType,
    primaryKeyId: key.primaryKeyId,
    keyVersion: key.keyVersion,
    rotationMode: key.rotationMode,
    previousKeyId: key.previousKeyId
  };
}
