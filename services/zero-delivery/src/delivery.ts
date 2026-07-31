export type DeliveryRequest = {
  recipient: string;
  ciphertextBlobId: string;
  recipientKeyId?: string;
  encryptionState: string;
};

export type RecipientKey = {
  address: string;
  primaryKeyId: string;
};

export type RecipientKeyResolver = {
  resolve(address: string): Promise<RecipientKey | undefined>;
};

export type DeliveryResult =
  | { ok: true; recipient: string; ciphertextBlobId: string }
  | { ok: false; error: "recipient_key_required" | "ciphertext_required" | "unsupported_encryption_state" };

export function validateDelivery(request: DeliveryRequest): DeliveryResult {
  if (!request.recipientKeyId) {
    return { ok: false, error: "recipient_key_required" };
  }

  if (!request.ciphertextBlobId) {
    return { ok: false, error: "ciphertext_required" };
  }

  if (!["local_e2ee", "openpgp", "password_portal"].includes(request.encryptionState)) {
    return { ok: false, error: "unsupported_encryption_state" };
  }

  return {
    ok: true,
    recipient: request.recipient,
    ciphertextBlobId: request.ciphertextBlobId
  };
}

export async function validateResolvedDelivery(request: DeliveryRequest, resolver: RecipientKeyResolver): Promise<DeliveryResult> {
  const key = await resolver.resolve(request.recipient);

  return validateDelivery({
    ...request,
    recipientKeyId: key?.primaryKeyId
  });
}

export function createHttpRecipientKeyResolver(baseUrl: string): RecipientKeyResolver {
  return {
    async resolve(address) {
      const response = await fetch(`${baseUrl}/keys/local/${encodeURIComponent(address)}`);

      if (response.status === 404) {
        return undefined;
      }

      if (!response.ok) {
        throw new Error(`Key lookup failed with status ${response.status}`);
      }

      return (await response.json()) as RecipientKey;
    }
  };
}
