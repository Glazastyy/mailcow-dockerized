export type DeliveryRequest = {
  recipient: string;
  ciphertextBlobId: string;
  recipientKeyId?: string;
  encryptionState: string;
};

export type AcceptedDelivery = {
  recipient: string;
  ciphertextBlobId: string;
  recipientKeyId: string;
  encryptionState: string;
};

export type RecipientKey = {
  address: string;
  primaryKeyId: string;
};

export type RecipientKeyResolver = {
  resolve(address: string): Promise<RecipientKey | undefined>;
};

export type MessageSink = {
  store(message: AcceptedDelivery): Promise<void>;
};

export type DeliveryResult =
  | { ok: true; recipient: string; ciphertextBlobId: string; accepted: AcceptedDelivery }
  | { ok: false; error: "recipient_key_required" | "ciphertext_required" | "unsupported_encryption_state" | "cleartext_rejected" };

const cleartextFields = ["body", "msg", "html", "text"] as const;

export function validateDelivery(request: DeliveryRequest): DeliveryResult {
  const payload = request as unknown as Record<string, unknown>;

  for (const field of cleartextFields) {
    if (field in payload && payload[field] !== undefined) {
      return { ok: false, error: "cleartext_rejected" };
    }
  }

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
    ciphertextBlobId: request.ciphertextBlobId,
    accepted: {
      recipient: request.recipient,
      ciphertextBlobId: request.ciphertextBlobId,
      recipientKeyId: request.recipientKeyId,
      encryptionState: request.encryptionState
    }
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

export function createHttpMessageSink(baseUrl: string): MessageSink {
  return {
    async store(message) {
      const response = await fetch(`${baseUrl}/mail/messages`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(message)
      });

      if (!response.ok) {
        throw new Error(`Message store failed with status ${response.status}`);
      }
    }
  };
}
