import { base64 } from "@scure/base";
import { NearAuthDataSchema } from "./crypto.js";
import type { NearAuthData } from "./types.js";

export function generateNonce(): Uint8Array {
  const timestamp = Date.now().toString();
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = new Uint8Array(32);
  
  // First 16 bytes: padded timestamp
  const timestampBytes = new TextEncoder().encode(timestamp.padStart(16, "0"));
  nonce.set(timestampBytes.slice(0, 16));
  
  // Last 16 bytes: random data
  nonce.set(randomBytes, 16);
  
  return nonce;
}

export function validateNonce(nonce: Uint8Array, maxAge: number = 24 * 60 * 60 * 1000): void {
  if (nonce.length !== 32) {
    throw new Error("Invalid nonce length");
  }

  // Extract timestamp from first 16 bytes
  const timestampStr = new TextDecoder()
    .decode(nonce.slice(0, 16))
    .replace(/^0+/, "");
  const timestamp = parseInt(timestampStr, 10);

  if (isNaN(timestamp)) {
    throw new Error("Invalid timestamp in nonce");
  }

  const age = Date.now() - timestamp;
  if (age < 0) {
    throw new Error("Nonce timestamp is in the future");
  }
  if (age > maxAge) {
    throw new Error("Nonce has expired");
  }
}

export function createAuthToken(authData: NearAuthData): string {
  const serialized = NearAuthDataSchema.serialize(authData);
  return base64.encode(serialized);
}

export function parseAuthToken(authToken: string): NearAuthData {
  try {
    const serialized = base64.decode(authToken);
    const deserialized = NearAuthDataSchema.deserialize(serialized);

    if (!deserialized) {
      throw new Error("Deserialization failed: null result");
    }

    return deserialized;
  } catch (error) {
    if (error instanceof Error) {
      throw new Error(`Invalid auth token: ${error.message.replace(/^Error: /, "")}`);
    }
    throw new Error(`Invalid auth token: ${String(error)}`);
  }
}