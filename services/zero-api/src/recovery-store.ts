import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

export type RecoveryMethod = "recovery_phrase" | "printed_key" | "guardian_split" | "authorized_device";

export type RecoveryRecord = {
  id: string;
  address: string;
  method: RecoveryMethod;
  encryptedRecoveryPacket: string;
  publicHint?: string;
  created: string;
  used?: string;
  revoked?: string;
};

export type RecoveryInput = Omit<RecoveryRecord, "id" | "created" | "used" | "revoked">;

export type RecoveryStore = {
  save(recovery: RecoveryInput): Promise<RecoveryRecord>;
  list(address: string): Promise<RecoveryRecord[]>;
};

const supportedMethods = ["recovery_phrase", "printed_key", "guardian_split", "authorized_device"] as const;
const clearRecoverySecretFields = ["recoveryPhrase", "recoveryKey", "secret", "privateKey", "password"] as const;

function createRecord(recovery: RecoveryInput): RecoveryRecord {
  return {
    ...recovery,
    id: crypto.randomUUID(),
    address: recovery.address.toLowerCase(),
    created: new Date().toISOString()
  };
}

function isRecoveryRecord(value: unknown): value is RecoveryRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }

  const record = value as Record<string, unknown>;

  return (
    typeof record.id === "string" &&
    typeof record.address === "string" &&
    supportedMethods.includes(record.method as RecoveryMethod) &&
    typeof record.encryptedRecoveryPacket === "string" &&
    typeof record.created === "string" &&
    (record.publicHint === undefined || typeof record.publicHint === "string") &&
    (record.used === undefined || typeof record.used === "string") &&
    (record.revoked === undefined || typeof record.revoked === "string")
  );
}

function activeRecovery(records: RecoveryRecord[], address: string) {
  const normalizedAddress = address.toLowerCase();
  return records.filter((record) => record.address === normalizedAddress && !record.used && !record.revoked);
}

export function createMemoryRecoveryStore(records: RecoveryRecord[] = []): RecoveryStore {
  return {
    async save(recovery) {
      const record = createRecord(recovery);
      records.push(record);
      return record;
    },
    async list(address) {
      return activeRecovery(records, address);
    }
  };
}

export function createFileRecoveryStore(root: string): RecoveryStore {
  const directory = join(root, "recovery");
  const recordsPath = join(directory, "records.jsonl");

  return {
    async save(recovery) {
      const record = createRecord(recovery);
      await mkdir(directory, { recursive: true });
      await appendFile(recordsPath, `${JSON.stringify(record)}\n`, { encoding: "utf8" });
      return record;
    },
    async list(address) {
      return activeRecovery(await readAllRecords(recordsPath), address);
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

  const records: RecoveryRecord[] = [];

  for (const line of data.trimEnd().split("\n")) {
    if (!line) {
      continue;
    }

    const parsed = JSON.parse(line) as unknown;

    if (isRecoveryRecord(parsed)) {
      records.push(parsed);
    }
  }

  return records;
}

export function validateRecoveryPayload(payload: Record<string, unknown>): { ok: true; recovery: RecoveryInput } | { ok: false; error: string } {
  for (const field of clearRecoverySecretFields) {
    if (field in payload && payload[field] !== undefined) {
      return { ok: false, error: "clear_recovery_secret_rejected" };
    }
  }

  for (const field of ["address", "method", "encryptedRecoveryPacket"] as const) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      return { ok: false, error: `missing_${field}` };
    }
  }

  if (!supportedMethods.includes(payload.method as RecoveryMethod)) {
    return { ok: false, error: "unsupported_recovery_method" };
  }

  if (payload.publicHint !== undefined && typeof payload.publicHint !== "string") {
    return { ok: false, error: "invalid_publicHint" };
  }

  return {
    ok: true,
    recovery: {
      address: String(payload.address),
      method: payload.method as RecoveryMethod,
      encryptedRecoveryPacket: String(payload.encryptedRecoveryPacket),
      publicHint: typeof payload.publicHint === "string" ? payload.publicHint : undefined
    }
  };
}

export function recoveryMethods(records: RecoveryRecord[]): RecoveryMethod[] {
  return Array.from(new Set(records.map((record) => record.method)));
}
