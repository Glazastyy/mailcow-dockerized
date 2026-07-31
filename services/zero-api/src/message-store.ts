import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

export type MessageRecord = {
  id: string;
  recipient: string;
  ciphertextBlobId: string;
  recipientKeyId: string;
  encryptionState: "local_e2ee" | "openpgp" | "password_portal";
};

export type MessageStore = {
  save(message: Omit<MessageRecord, "id">): Promise<MessageRecord>;
  get(id: string): Promise<MessageRecord | undefined>;
};

const cleartextFields = ["body", "msg", "html", "text"] as const;
const supportedEncryptionStates = ["local_e2ee", "openpgp", "password_portal"] as const;

function createRecord(message: Omit<MessageRecord, "id">): MessageRecord {
  return {
    ...message,
    id: crypto.randomUUID(),
    recipient: message.recipient.toLowerCase()
  };
}

function isMessageRecord(value: unknown): value is MessageRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;

  return (
    typeof record.id === "string" &&
    typeof record.recipient === "string" &&
    typeof record.ciphertextBlobId === "string" &&
    typeof record.recipientKeyId === "string" &&
    supportedEncryptionStates.includes(record.encryptionState as MessageRecord["encryptionState"])
  );
}

export function createMemoryMessageStore(messages = new Map<string, MessageRecord>()): MessageStore {
  return {
    async save(message) {
      const record = createRecord(message);
      messages.set(record.id, record);
      return record;
    },
    async get(id) {
      return messages.get(id);
    }
  };
}

export function createFileMessageStore(root: string): MessageStore {
  const directory = join(root, "messages");
  const recordsPath = join(directory, "records.jsonl");

  return {
    async save(message) {
      const record = createRecord(message);
      await mkdir(directory, { recursive: true });
      await appendFile(recordsPath, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
      return record;
    },
    async get(id) {
      if (!/^[a-f0-9-]{36}$/.test(id)) {
        return undefined;
      }

      let data: string;

      try {
        data = await readFile(recordsPath, "utf8");
      } catch (error) {
        if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
          return undefined;
        }

        throw error;
      }

      for (const line of data.trimEnd().split("\n")) {
        if (!line) {
          continue;
        }

        const parsed = JSON.parse(line) as unknown;

        if (isMessageRecord(parsed) && parsed.id === id) {
          return parsed;
        }
      }

      return undefined;
    }
  };
}

export function validateMessagePayload(payload: Record<string, unknown>): { ok: true; message: Omit<MessageRecord, "id"> } | { ok: false; error: string } {
  for (const field of cleartextFields) {
    if (field in payload && payload[field] !== undefined) {
      return { ok: false, error: "cleartext_rejected" };
    }
  }

  for (const field of ["recipient", "ciphertextBlobId", "recipientKeyId", "encryptionState"] as const) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      return { ok: false, error: `missing_${field}` };
    }
  }

  if (!supportedEncryptionStates.includes(payload.encryptionState as MessageRecord["encryptionState"])) {
    return { ok: false, error: "unsupported_encryption_state" };
  }

  return {
    ok: true,
    message: {
      recipient: String(payload.recipient),
      ciphertextBlobId: String(payload.ciphertextBlobId),
      recipientKeyId: String(payload.recipientKeyId),
      encryptionState: payload.encryptionState as MessageRecord["encryptionState"]
    }
  };
}
