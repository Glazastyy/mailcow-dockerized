export type DeliveryRequest = {
  recipient: string;
  ciphertextBlobId: string;
  recipientKeyId?: string;
  encryptionState: string;
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
