import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

export type MessageRecord = {
  id: string;
  recipient: string;
  folder: string;
  ciphertextBlobId: string;
  recipientKeyId: string;
  encryptionState: "local_e2ee" | "openpgp" | "password_portal";
  flags: MessageFlag[];
  created: string;
};

export type MessageFlag = "unread" | "seen" | "starred" | "answered" | "forwarded";

export type MessageInput = Omit<MessageRecord, "id" | "created" | "folder" | "flags"> & { folder?: string; flags?: MessageFlag[] };

export type MessageUpdate = {
  folder?: string;
  flags?: MessageFlag[];
};

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

export type FolderSummary = {
  folder: string;
  total: number;
};

export type MessageStore = {
  save(message: MessageInput): Promise<MessageRecord>;
  get(id: string): Promise<MessageRecord | undefined>;
  list(query: MessageListQuery): Promise<MessageListPage>;
  folders(recipient: string): Promise<FolderSummary[]>;
  update(id: string, update: MessageUpdate): Promise<MessageRecord | undefined>;
};

const cleartextFields = ["body", "msg", "html", "text", "subject"] as const;
const supportedEncryptionStates = ["local_e2ee", "openpgp", "password_portal"] as const;
const supportedFolders = ["inbox", "sent", "archive", "trash", "spam"] as const;
const supportedFlags = ["unread", "seen", "starred", "answered", "forwarded"] as const;
const defaultPageLimit = 50;
const maxPageLimit = 100;

function createRecord(message: MessageInput): MessageRecord {
  return {
    ...message,
    id: crypto.randomUUID(),
    recipient: message.recipient.toLowerCase(),
    folder: message.folder ?? "inbox",
    flags: message.flags ?? [],
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
    Array.isArray(record.flags) &&
    record.flags.every((flag) => supportedFlags.includes(flag as MessageFlag)) &&
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

function folderSummaries(records: MessageRecord[], recipient: string): FolderSummary[] {
  const normalizedRecipient = recipient.toLowerCase();

  return supportedFolders.map((folder) => ({
    folder,
    total: records.filter((message) => message.recipient === normalizedRecipient && message.folder === folder).length
  }));
}

function updateRecord(record: MessageRecord, update: MessageUpdate): MessageRecord {
  return {
    ...record,
    folder: update.folder ?? record.folder,
    flags: update.flags ?? record.flags
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
    },
    async folders(recipient) {
      return folderSummaries(Array.from(messages.values()), recipient);
    },
    async update(id, update) {
      const record = messages.get(id);

      if (!record) {
        return undefined;
      }

      const updated = updateRecord(record, update);
      messages.set(id, updated);
      return updated;
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
    },
    async folders(recipient) {
      return folderSummaries(await readAllRecords(recordsPath), recipient);
    },
    async update(id, update) {
      if (!/^[a-f0-9-]{36}$/.test(id)) {
        return undefined;
      }

      const records = await readAllRecords(recordsPath);
      const index = records.findIndex((record) => record.id === id);

      if (index === -1) {
        return undefined;
      }

      const updated = updateRecord(records[index], update);
      records[index] = updated;
      await mkdir(directory, { recursive: true });
      await writeFile(recordsPath, records.map((record) => JSON.stringify(record)).join("\n") + "\n", { encoding: "utf8" });
      return updated;
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

  if (payload.flags !== undefined) {
    if (!Array.isArray(payload.flags) || !payload.flags.every((flag) => supportedFlags.includes(flag as MessageFlag))) {
      return { ok: false, error: "unsupported_flag" };
    }
  }

  return {
    ok: true,
    message: {
      recipient: String(payload.recipient),
      folder: typeof payload.folder === "string" ? payload.folder : "inbox",
      ciphertextBlobId: String(payload.ciphertextBlobId),
      recipientKeyId: String(payload.recipientKeyId),
      encryptionState: payload.encryptionState as MessageRecord["encryptionState"],
      flags: Array.isArray(payload.flags) ? (payload.flags as MessageFlag[]) : []
    }
  };
}

export function validateMessageUpdatePayload(payload: Record<string, unknown>): { ok: true; update: MessageUpdate } | { ok: false; error: string } {
  for (const field of cleartextFields) {
    if (field in payload && payload[field] !== undefined) {
      return { ok: false, error: "cleartext_rejected" };
    }
  }

  if (payload.folder !== undefined && (typeof payload.folder !== "string" || !supportedFolders.includes(payload.folder as (typeof supportedFolders)[number]))) {
    return { ok: false, error: "unsupported_folder" };
  }

  if (payload.flags !== undefined) {
    if (!Array.isArray(payload.flags) || !payload.flags.every((flag) => supportedFlags.includes(flag as MessageFlag))) {
      return { ok: false, error: "unsupported_flag" };
    }
  }

  return {
    ok: true,
    update: {
      folder: typeof payload.folder === "string" ? payload.folder : undefined,
      flags: Array.isArray(payload.flags) ? Array.from(new Set(payload.flags as MessageFlag[])) : undefined
    }
  };
}
