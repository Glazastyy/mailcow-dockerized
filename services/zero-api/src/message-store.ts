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

export function createMemoryMessageStore(messages = new Map<string, MessageRecord>()): MessageStore {
  return {
    async save(message) {
      const record = {
        ...message,
        id: crypto.randomUUID(),
        recipient: message.recipient.toLowerCase()
      };
      messages.set(record.id, record);
      return record;
    },
    async get(id) {
      return messages.get(id);
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
