import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

export type MessageRecord = {
  id: string;
  recipient: string;
  folder: string;
  ciphertextBlobId: string;
  recipientKeyId: string;
  encryptionState: "local_e2ee" | "openpgp" | "password_portal";
  created: string;
};

export type MessageInput = Omit<MessageRecord, "id" | "created"> & { folder?: string };

export type MessageListQuery = {
  recipient: string;
  folder?: string;
  cursor?: string;
  limit?: number;
};

export type MessageListPage = {
  messages: MessageRecord[];
  nextCursor?: string;
};

export type MessageStore = {
  save(message: MessageInput): Promise<MessageRecord>;
  get(id: string): Promise<MessageRecord | undefined>;
  list(query: MessageListQuery): Promise<MessageListPage>;
};

const cleartextFields = ["body", "msg", "html", "text", "subject"] as const;
const supportedEncryptionStates = ["local_e2ee", "openpgp", "password_portal"] as const;
const supportedFolders = ["inbox", "sent", "archive", "trash", "spam"] as const;
const defaultPageLimit = 50;
const maxPageLimit = 100;

function createRecord(message: MessageInput): MessageRecord {
  return {
    ...message,
    id: crypto.randomUUID(),
    recipient: message.recipient.toLowerCase(),
    folder: message.folder ?? "inbox",
    created: new Date().toISOString()
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
    typeof record.folder === "string" &&
    typeof record.ciphertextBlobId === "string" &&
    typeof record.recipientKeyId === "string" &&
    typeof record.created === "string" &&
    supportedEncryptionStates.includes(record.encryptionState as MessageRecord["encryptionState"])
  );
}

function normalizeLimit(limit: number | undefined) {
  if (!Number.isInteger(limit) || !limit || limit < 1) {
    return defaultPageLimit;
  }

  return Math.min(limit, maxPageLimit);
}

function listRecords(records: MessageRecord[], query: MessageListQuery): MessageListPage {
  const recipient = query.recipient.toLowerCase();
  const folder = query.folder ?? "inbox";
  const filtered = records.filter((message) => message.recipient === recipient && message.folder === folder);
  const start = query.cursor ? filtered.findIndex((message) => message.id === query.cursor) + 1 : 0;
  const safeStart = start > 0 ? start : 0;
  const limit = normalizeLimit(query.limit);
  const messages = filtered.slice(safeStart, safeStart + limit);
  const nextMessage = filtered[safeStart + limit - 1];

  if (safeStart + limit >= filtered.length || !nextMessage) {
    return { messages };
  }

  return {
    messages,
    nextCursor: nextMessage.id
  };
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
    },
    async list(query) {
      return listRecords(Array.from(messages.values()), query);
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
    },
    async list(query) {
      return listRecords(await readAllRecords(recordsPath), query);
    }
  };
}

async function readAllRecords(path: string) {
  let data: string;

  try {
    data = await readFile(path, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return [];
    }

    throw error;
  }

  const records: MessageRecord[] = [];

  for (const line of data.trimEnd().split("\n")) {
    if (!line) {
      continue;
    }

    const parsed = JSON.parse(line) as unknown;

    if (isMessageRecord(parsed)) {
      records.push(parsed);
    }
  }

  return records;
}

export function validateMessagePayload(payload: Record<string, unknown>): { ok: true; message: MessageInput } | { ok: false; error: string } {
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

  if (
    payload.folder !== undefined &&
    (typeof payload.folder !== "string" || !supportedFolders.includes(payload.folder as (typeof supportedFolders)[number]))
  ) {
    return { ok: false, error: "unsupported_folder" };
  }

  return {
    ok: true,
    message: {
      recipient: String(payload.recipient),
      folder: typeof payload.folder === "string" ? payload.folder : "inbox",
      ciphertextBlobId: String(payload.ciphertextBlobId),
      recipientKeyId: String(payload.recipientKeyId),
      encryptionState: payload.encryptionState as MessageRecord["encryptionState"]
    }
  };
}
