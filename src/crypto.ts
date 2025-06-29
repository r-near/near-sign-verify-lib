import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha2";
import { base58, base64 } from "@scure/base";
import { b } from "@zorsh/zorsh";
import type { SignedPayload } from "./types.js";

export const ED25519_PREFIX = "ed25519:";
export const NEP413_TAG = 2147484061;

// Zorsh schemas
export const SignedPayloadSchema = b.struct({
  message: b.string(),
  nonce: b.array(b.u8(), 32),
  recipient: b.string(),
  callbackUrl: b.option(b.string()),
});

export const NearAuthDataSchema = b.struct({
  accountId: b.string(),
  publicKey: b.string(),
  signature: b.string(),
  message: b.string(),
  nonce: b.array(b.u8(), 32),
  recipient: b.string(),
  callbackUrl: b.option(b.string()),
  state: b.option(b.string()),
});

export function createNEP413Payload(payload: SignedPayload): Uint8Array {
  const serializedTag = b.u32().serialize(NEP413_TAG);
  const serializablePayload = {
    ...payload,
    nonce: Array.from(payload.nonce),
    callbackUrl: payload.callbackUrl || null,
  };
  const serializedPayload = SignedPayloadSchema.serialize(serializablePayload);

  const dataToHash = new Uint8Array(serializedTag.length + serializedPayload.length);
  dataToHash.set(serializedTag, 0);
  dataToHash.set(serializedPayload, serializedTag.length);

  return dataToHash;
}

export function hashPayload(payload: Uint8Array): Uint8Array {
  return sha256(payload);
}

export async function verifySignature(
  payloadHash: Uint8Array,
  signatureBytes: Uint8Array,
  publicKeyString: string,
): Promise<void> {
  if (!publicKeyString.startsWith(ED25519_PREFIX)) {
    throw new Error(`Unsupported public key type: "${publicKeyString}". Must start with "${ED25519_PREFIX}".`);
  }

  const isValid = ed25519.verify(
    signatureBytes,
    payloadHash,
    base58.decode(publicKeyString.split(":")[1]),
  );
  
  if (!isValid) {
    throw new Error("Ed25519 signature verification failed.");
  }
}

export async function verifyPublicKeyOwner(
  accountId: string,
  publicKey: string,
  requireFullAccessKey: boolean,
): Promise<void> {
  const isTestnet = accountId.endsWith(".testnet");
  const baseUrl = isTestnet ? "https://test.api.fastnear.com" : "https://api.fastnear.com";
  const pathSuffix = requireFullAccessKey ? "" : "/all";
  const url = `${baseUrl}/v0/public_key/${publicKey}${pathSuffix}`;

  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("API error or unexpected response");
    }
    
    const data = await response.json();
    if (!data || !Array.isArray(data.account_ids) || !data.account_ids.includes(accountId)) {
      throw new Error("public key not associated with the account or does not meet access key requirements");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "API error or unexpected response";
    throw new Error(`Public key ownership verification failed: ${message}`);
  }
}