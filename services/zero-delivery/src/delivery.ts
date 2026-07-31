import { Buffer } from "node:buffer";

export type DeliveryRequest = {
  recipient?: string;
  recipients?: string[];
  ciphertextBlobId?: string;
  ciphertext?: string;
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

export type RecipientResolver = {
  resolve(address: string): Promise<string[] | undefined>;
};

export type MessageSink = {
  store(message: AcceptedDelivery): Promise<void>;
};

export type CiphertextBlobSink = {
  store(ciphertext: Uint8Array): Promise<{ id: string }>;
};

type FetchRequest = (request: Request) => Promise<Response>;

export type DeliveryResult =
  | { ok: true; recipient: string; ciphertextBlobId: string; accepted: AcceptedDelivery }
  | {
      ok: false;
      error: "recipient_key_required" | "ciphertext_required" | "unsupported_encryption_state" | "cleartext_rejected" | "recipient_unresolved";
      recipient?: string;
    };

const cleartextFields = ["body", "msg", "html", "text"] as const;

export function validateDelivery(request: DeliveryRequest): DeliveryResult {
  const payload = request as unknown as Record<string, unknown>;

  for (const field of cleartextFields) {
    if (field in payload && payload[field] !== undefined) {
      return { ok: false, error: "cleartext_rejected" };
    }
  }

  if (!request.recipient) {
    return { ok: false, error: "recipient_key_required" };
  }

  if (!request.recipientKeyId) {
    return { ok: false, error: "recipient_key_required" };
  }

  if (!request.ciphertextBlobId && !request.ciphertext) {
    return { ok: false, error: "ciphertext_required" };
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
  if (!request.recipient) {
    return { ok: false, error: "recipient_key_required" };
  }

  const key = await resolver.resolve(request.recipient);

  return validateDelivery({
    ...request,
    recipientKeyId: key?.primaryKeyId
  });
}

export function deliveryRecipients(request: DeliveryRequest): string[] {
  if (Array.isArray(request.recipients)) {
    return Array.from(new Set(request.recipients.filter((recipient) => typeof recipient === "string" && recipient.length > 0).map((recipient) => recipient.toLowerCase())));
  }

  if (typeof request.recipient === "string" && request.recipient.length > 0) {
    return [request.recipient.toLowerCase()];
  }

  return [];
}

export async function resolveDeliveryRecipients(
  recipients: string[],
  resolver: RecipientResolver
): Promise<string[] | { ok: false; error: "recipient_unresolved"; recipient: string }> {
  const resolved = [];

  for (const recipient of recipients) {
    const normalizedRecipient = recipient.toLowerCase();
    const expanded = await resolver.resolve(normalizedRecipient);

    if (!expanded || expanded.length === 0) {
      return {
        ok: false,
        error: "recipient_unresolved",
        recipient: normalizedRecipient
      };
    }

    for (const address of expanded) {
      resolved.push(address.toLowerCase());
    }
  }

  return Array.from(new Set(resolved));
}

export function createPassthroughRecipientResolver(): RecipientResolver {
  return {
    async resolve(address) {
      return [address.toLowerCase()];
    }
  };
}

export function createStaticRecipientResolver(aliases: Record<string, string[]>): RecipientResolver {
  return {
    async resolve(address) {
      const normalizedAddress = address.toLowerCase();
      return aliases[normalizedAddress] ?? [normalizedAddress];
    }
  };
}

export function hasCleartextFields(request: DeliveryRequest): boolean {
  const payload = request as unknown as Record<string, unknown>;
  return cleartextFields.some((field) => field in payload && payload[field] !== undefined);
}

export function decodeCiphertext(ciphertext: string): Uint8Array | undefined {
  try {
    const decoded = Buffer.from(ciphertext, "base64");

    if (decoded.byteLength === 0) {
      return undefined;
    }

    return new Uint8Array(decoded);
  } catch {
    return undefined;
  }
}

function arrayBufferFromBytes(data: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(data.byteLength);
  new Uint8Array(buffer).set(data);
  return buffer;
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

export function createHttpCiphertextBlobSink(baseUrl: string, fetchFn: FetchRequest = fetch): CiphertextBlobSink {
  return {
    async store(ciphertext) {
      const response = await fetchFn(
        new Request(`${baseUrl}/blob`, {
          method: "POST",
          headers: {
            "content-type": "application/octet-stream",
            "x-zero-blob-kind": "ciphertext"
          },
          body: arrayBufferFromBytes(ciphertext)
        })
      );

      if (!response.ok) {
        throw new Error(`Ciphertext blob store failed with status ${response.status}`);
      }

      const body = (await response.json()) as { id?: unknown };

      if (typeof body.id !== "string" || body.id.length === 0) {
        throw new Error("Ciphertext blob store response did not include an id");
      }

      return { id: body.id };
    }
  };
}
