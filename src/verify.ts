import { base64 } from "@scure/base";
import { createNEP413Payload, hashPayload, verifySignature, verifyPublicKeyOwner } from "./crypto.ts";
import { validateNonce, parseAuthToken } from "./utils.ts";
import type { VerifyOptions, VerificationResult, NearAuthData, SignedPayload } from "./types.ts";

export async function verify(authTokenString: string, options?: VerifyOptions): Promise<VerificationResult> {
  let authData: NearAuthData;
  try {
    authData = parseAuthToken(authTokenString);
  } catch (e: any) {
    throw new Error(`Failed to parse auth token: ${e.message}`);
  }

  const {
    accountId,
    publicKey,
    signature: signatureB64,
    message: messageString,
    nonce: nonceFromAuthData,
    recipient: recipientFromAuthData,
    callbackUrl,
    state,
  } = authData;

  const nonce = new Uint8Array(nonceFromAuthData);

  // Validate nonce
  if (options?.validateNonce) {
    if (!options.validateNonce(nonce)) {
      throw new Error("Custom nonce validation failed.");
    }
  } else {
    try {
      validateNonce(nonce, options?.maxAge);
    } catch (error) {
      throw new Error(
        `Nonce validation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      );
    }
  }

  // Validate recipient
  if (options?.validateRecipient) {
    if (!options.validateRecipient(recipientFromAuthData)) {
      throw new Error("Custom recipient validation failed.");
    }
  } else if (options?.recipient) {
    if (recipientFromAuthData !== options.recipient) {
      throw new Error(
        `Recipient mismatch: expected '${options.recipient}', but recipient is '${recipientFromAuthData}'.`,
      );
    }
  }

  // Validate state
  if (options?.validateState) {
    if (!options.validateState(state!)) {
      throw new Error("Custom state validation failed.");
    }
  } else if (options?.state !== undefined) {
    if (state !== options.state) {
      throw new Error(
        `State mismatch: expected '${options.state}', got '${state?.toString() || "undefined"}'.`,
      );
    }
  }

  // Validate message
  if (options?.validateMessage) {
    if (!options.validateMessage(messageString)) {
      throw new Error("Custom message validation failed.");
    }
  } else if (options?.message) {
    if (messageString !== options.message) {
      throw new Error(
        `Message mismatch: expected '${options.message}', got '${messageString}'.`,
      );
    }
  }

  // Verify public key ownership
  await verifyPublicKeyOwner(accountId, publicKey, options?.requireFullAccessKey ?? true);

  // Verify cryptographic signature
  const nep413PayloadToVerify: SignedPayload = {
    message: messageString,
    nonce: Array.from(nonce),
    recipient: recipientFromAuthData,
    callbackUrl,
  };

  const dataThatWasHashed = createNEP413Payload(nep413PayloadToVerify);
  const payloadHash = hashPayload(dataThatWasHashed);
  const signatureBytes = base64.decode(signatureB64);

  try {
    await verifySignature(payloadHash, signatureBytes, publicKey);
  } catch (error) {
    throw new Error(
      `Cryptographic signature verification failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  return {
    accountId,
    message: messageString,
    publicKey,
    callbackUrl: callbackUrl || undefined,
    state: state || undefined,
  };
}