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

export type PasswordReencryptRequest = {
  address: string;
  currentPrimaryKeyId: string;
  reencryptedPrivateKey: string;
  privateKeyKdf: UserKey["privateKeyKdf"];
  privateKeyKdfParams: Record<string, unknown>;
  currentPrivateKeyProof: string;
};

export type KeyStore = {
  saveUserKey(key: UserKey): Promise<UserKey>;
  getActiveUserKey(address: string): Promise<UserKey | undefined>;
  reencryptUserKey(request: PasswordReencryptRequest): Promise<UserKey | undefined>;
  resetUserKey(key: UserKey): Promise<UserKey>;
};

const clearPasswordFields = ["password", "currentPassword", "newPassword", "passwordHash"] as const;
const clearPrivateKeyFields = ["privateKey", "secretKey"] as const;

function normalizeKey(key: UserKey, keyVersion: number, status: UserKey["status"]): UserKey {
  return {
    ...key,
    address: key.address.toLowerCase(),
    keyVersion,
    status
  };
}

function validateKdfPayload(payload: Record<string, unknown>): { ok: true } | { ok: false; error: string } {
  if (!["argon2id", "pbkdf2"].includes(String(payload.privateKeyKdf))) {
    return { ok: false, error: "invalid_privateKeyKdf" };
  }

  if (!payload.privateKeyKdfParams || typeof payload.privateKeyKdfParams !== "object" || Array.isArray(payload.privateKeyKdfParams)) {
    return { ok: false, error: "invalid_privateKeyKdfParams" };
  }

  return { ok: true };
}

function rejectClearSecrets(payload: Record<string, unknown>): { ok: true } | { ok: false; error: string } {
  for (const field of clearPrivateKeyFields) {
    if (field in payload) {
      return { ok: false, error: "clear_private_key_rejected" };
    }
  }

  for (const field of clearPasswordFields) {
    if (field in payload) {
      return { ok: false, error: "clear_password_rejected" };
    }
  }

  return { ok: true };
}

export function createMemoryKeyStore(keys = new Map<string, UserKey[]>()): KeyStore {
  return {
    async saveUserKey(key) {
      const normalized = normalizeKey(key, key.keyVersion || 1, key.status || "active");
      const existing = keys.get(normalized.address) ?? [];

      if (normalized.status === "active") {
        for (const stored of existing) {
          if (stored.status === "active") {
            stored.status = "rotated";
          }
        }
      }

      existing.push(normalized);
      keys.set(normalized.address, existing);
      return normalized;
    },
    async getActiveUserKey(address) {
      const key = keys.get(address.toLowerCase())?.findLast((stored) => stored.status === "active");

      if (!key) {
        return undefined;
      }

      return key;
    },
    async reencryptUserKey(request) {
      const existing = keys.get(request.address.toLowerCase()) ?? [];
      const active = existing.findLast((stored) => stored.status === "active");

      if (!active || active.primaryKeyId !== request.currentPrimaryKeyId) {
        return undefined;
      }

      active.status = "rotated";

      const updated = normalizeKey(
        {
          ...active,
          encryptedPrivateKey: request.reencryptedPrivateKey,
          privateKeyKdf: request.privateKeyKdf,
          privateKeyKdfParams: request.privateKeyKdfParams
        },
        active.keyVersion + 1,
        "active"
      );
      existing.push(updated);
      keys.set(updated.address, existing);
      return updated;
    },
    async resetUserKey(key) {
      const address = key.address.toLowerCase();
      const existing = keys.get(address) ?? [];
      const nextVersion = Math.max(0, ...existing.map((stored) => stored.keyVersion)) + 1;

      for (const stored of existing) {
        stored.status = "revoked";
      }

      const reset = normalizeKey(key, nextVersion, "active");
      existing.push(reset);
      keys.set(address, existing);
      return reset;
    }
  };
}

export function validateUserKeyPayload(payload: Record<string, unknown>): { ok: true; key: UserKey } | { ok: false; error: string } {
  const secretValidation = rejectClearSecrets(payload);

  if (!secretValidation.ok) {
    return secretValidation;
  }

  for (const field of ["address", "primaryKeyId", "publicKeyArmored", "encryptedPrivateKey"] as const) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      return { ok: false, error: `missing_${field}` };
    }
  }

  const kdfValidation = validateKdfPayload(payload);

  if (!kdfValidation.ok) {
    return kdfValidation;
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

export function validatePasswordReencryptPayload(
  payload: Record<string, unknown>
): { ok: true; request: PasswordReencryptRequest } | { ok: false; error: string } {
  const secretValidation = rejectClearSecrets(payload);

  if (!secretValidation.ok) {
    return secretValidation;
  }

  for (const field of ["address", "currentPrimaryKeyId", "reencryptedPrivateKey", "currentPrivateKeyProof"] as const) {
    if (typeof payload[field] !== "string" || payload[field].length === 0) {
      return { ok: false, error: `missing_${field}` };
    }
  }

  const kdfValidation = validateKdfPayload(payload);

  if (!kdfValidation.ok) {
    return kdfValidation;
  }

  return {
    ok: true,
    request: {
      address: String(payload.address),
      currentPrimaryKeyId: String(payload.currentPrimaryKeyId),
      reencryptedPrivateKey: String(payload.reencryptedPrivateKey),
      privateKeyKdf: payload.privateKeyKdf as UserKey["privateKeyKdf"],
      privateKeyKdfParams: payload.privateKeyKdfParams as Record<string, unknown>,
      currentPrivateKeyProof: String(payload.currentPrivateKeyProof)
    }
  };
}
