import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

export type AttachmentRecord = {
  id: string;
  messageId: string;
  ciphertextBlobId: string;
  encryptedName?: string;
  mimeType?: string;
  size: number;
  sha256Ciphertext: string;
};

export type AttachmentInput = Omit<AttachmentRecord, "id">;

export type AttachmentStore = {
  save(attachment: AttachmentInput): Promise<AttachmentRecord>;
  get(id: string): Promise<AttachmentRecord | undefined>;
  list(messageId: string): Promise<AttachmentRecord[]>;
};

const cleartextFields = ["filename", "fileName", "name", "body", "content", "text", "html"] as const;

function createRecord(attachment: AttachmentInput): AttachmentRecord {
  return {
    ...attachment,
    id: crypto.randomUUID()
  };
}

function isAttachmentRecord(value: unknown): value is AttachmentRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;

  return (
    typeof record.id === "string" &&
    typeof record.messageId === "string" &&
    typeof record.ciphertextBlobId === "string" &&
    typeof record.size === "number" &&
    typeof record.sha256Ciphertext === "string" &&
    (record.encryptedName === undefined || typeof record.encryptedName === "string") &&
    (record.mimeType === undefined || typeof record.mimeType === "string")
  );
}

export function createMemoryAttachmentStore(attachments = new Map<string, AttachmentRecord>()): AttachmentStore {
  return {
    async save(attachment) {
      const record = createRecord(attachment);
      attachments.set(record.id, record);
      return record;
    },
    async get(id) {
      return attachments.get(id);
    },
    async list(messageId) {
      return Array.from(attachments.values()).filter((attachment) => attachment.messageId === messageId);
    }
  };
}

export function createFileAttachmentStore(root: string): AttachmentStore {
  const directory = join(root, "attachments");
  const recordsPath = join(directory, "records.jsonl");

  return {
    async save(attachment) {
      const record = createRecord(attachment);
      await mkdir(directory, { recursive: true });
      await appendFile(recordsPath, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
      return record;
    },
    async get(id) {
      if (!/^[a-f0-9-]{36}$/.test(id)) {
        return undefined;
      }

      return (await readAllRecords(recordsPath)).find((attachment) => attachment.id === id);
    },
    async list(messageId) {
      return (await readAllRecords(recordsPath)).filter((attachment) => attachment.messageId === messageId);
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

  const records: AttachmentRecord[] = [];

  for (const line of data.trimEnd().split("\n")) {
    if (!line) {
      continue;
    }

    const parsed = JSON.parse(line) as unknown;

    if (isAttachmentRecord(parsed)) {
      records.push(parsed);
    }
  }

  return records;
}

export function validateAttachmentPayload(payload: Record<string, unknown>): { ok: true; attachment: AttachmentInput } | { ok: false; error: string } {
  for (const field of cleartextFields) {
    if (field in payload && payload[field] !== undefined) {
      return { ok: false, error: "cleartext_rejected" };
    }
  }

  for (const field of ["messageId", "ciphertextBlobId", "sha256Ciphertext"] as const) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      return { ok: false, error: `missing_${field}` };
    }
  }

  if (typeof payload.size !== "number" || !Number.isInteger(payload.size) || payload.size < 0) {
    return { ok: false, error: "invalid_size" };
  }

  if (!/^[a-f0-9]{64}$/.test(String(payload.sha256Ciphertext))) {
    return { ok: false, error: "invalid_sha256Ciphertext" };
  }

  if (payload.encryptedName !== undefined && typeof payload.encryptedName !== "string") {
    return { ok: false, error: "invalid_encryptedName" };
  }

  if (payload.mimeType !== undefined && typeof payload.mimeType !== "string") {
    return { ok: false, error: "invalid_mimeType" };
  }

  return {
    ok: true,
    attachment: {
      messageId: String(payload.messageId),
      ciphertextBlobId: String(payload.ciphertextBlobId),
      encryptedName: typeof payload.encryptedName === "string" ? payload.encryptedName : undefined,
      mimeType: typeof payload.mimeType === "string" ? payload.mimeType : undefined,
      size: payload.size,
      sha256Ciphertext: String(payload.sha256Ciphertext)
    }
  };
}
