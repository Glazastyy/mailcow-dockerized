export type UserKey = {
  address: string;
  primaryKeyId: string;
  publicKeyArmored: string;
  encryptedPrivateKey: string;
  privateKeyKdf: "argon2id" | "pbkdf2";
  privateKeyKdfParams: Record<string, unknown>;
  keyVersion: number;
  status: "active" | "rotated" | "revoked";
};

export type KeyStore = {
  saveUserKey(key: UserKey): Promise<UserKey>;
  getActiveUserKey(address: string): Promise<UserKey | undefined>;
};

export function createMemoryKeyStore(keys = new Map<string, UserKey>()): KeyStore {
  return {
    async saveUserKey(key) {
      const normalized = {
        ...key,
        address: key.address.toLowerCase(),
        keyVersion: key.keyVersion || 1,
        status: key.status || "active"
      };
      keys.set(normalized.address, normalized);
      return normalized;
    },
    async getActiveUserKey(address) {
      const key = keys.get(address.toLowerCase());

      if (key?.status !== "active") {
        return undefined;
      }

      return key;
    }
  };
}

export function validateUserKeyPayload(payload: Record<string, unknown>): { ok: true; key: UserKey } | { ok: false; error: string } {
  if ("privateKey" in payload || "secretKey" in payload) {
    return { ok: false, error: "clear_private_key_rejected" };
  }

  for (const field of ["address", "primaryKeyId", "publicKeyArmored", "encryptedPrivateKey"] as const) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      return { ok: false, error: `missing_${field}` };
    }
  }

  if (!["argon2id", "pbkdf2"].includes(String(payload.privateKeyKdf))) {
    return { ok: false, error: "invalid_privateKeyKdf" };
  }

  if (!payload.privateKeyKdfParams || typeof payload.privateKeyKdfParams !== "object" || Array.isArray(payload.privateKeyKdfParams)) {
    return { ok: false, error: "invalid_privateKeyKdfParams" };
  }

  return {
    ok: true,
    key: {
      address: String(payload.address),
      primaryKeyId: String(payload.primaryKeyId),
      publicKeyArmored: String(payload.publicKeyArmored),
      encryptedPrivateKey: String(payload.encryptedPrivateKey),
      privateKeyKdf: payload.privateKeyKdf as UserKey["privateKeyKdf"],
      privateKeyKdfParams: payload.privateKeyKdfParams as Record<string, unknown>,
      keyVersion: Number(payload.keyVersion ?? 1),
      status: (payload.status as UserKey["status"]) ?? "active"
    }
  };
}
