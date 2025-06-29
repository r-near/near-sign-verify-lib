import { ed25519 } from "@noble/curves/ed25519";
import { base58, base64 } from "@scure/base";
import { ED25519_PREFIX, createNEP413Payload, hashPayload } from "./crypto.ts";
import { generateNonce, createAuthToken } from "./utils.ts";
import type { SignOptions, SignedPayload, NearAuthData, WalletInterface } from "./types.ts";

async function signWithKeyPair(
  keyPair: string,
  accountId: string,
  message: string,
  recipient: string,
  nonce: Uint8Array,
  callbackUrl?: string,
  state?: string,
): Promise<string> {
  if (!keyPair.startsWith(ED25519_PREFIX)) {
    throw new Error("Invalid KeyPair format: missing ed25519 prefix.");
  }

  const payload: SignedPayload = {
    message,
    nonce: Array.from(nonce),
    recipient,
    callbackUrl: callbackUrl || null,
  };

  const dataToHash = createNEP413Payload(payload);
  const payloadHash = hashPayload(dataToHash);

  const privateKeyBase58 = keyPair.substring(ED25519_PREFIX.length);
  const privateKeyBytes = base58.decode(privateKeyBase58);

  if (privateKeyBytes.length !== 64) {
    throw new Error(`Expected decoded private key to be 64 bytes for Ed25519, got ${privateKeyBytes.length}`);
  }

  const seed = privateKeyBytes.slice(0, 32);
  const signedResult = ed25519.sign(payloadHash, seed);
  const signature = base64.encode(signedResult);

  const publicKeyBytes = ed25519.getPublicKey(seed);
  const publicKey = ED25519_PREFIX + base58.encode(publicKeyBytes);

  const authData: NearAuthData = {
    accountId,
    publicKey,
    signature,
    message,
    nonce: Array.from(nonce),
    recipient,
    callbackUrl: callbackUrl || null,
    state: state || null,
  };

  return createAuthToken(authData);
}

async function signWithWallet(
  wallet: WalletInterface,
  message: string,
  recipient: string,
  nonce: Uint8Array,
  callbackUrl?: string,
  state?: string,
): Promise<string> {
  const walletResult = await wallet.signMessage({
    message,
    nonce,
    recipient,
  });

  const sigParts = walletResult.signature.split(":");
  if (sigParts.length !== 2 || sigParts[0]?.toLowerCase() !== "ed25519") {
    throw new Error(
      `Unsupported signature format from wallet: ${walletResult.signature}. Expected "ed25519:<base58_signature>"`,
    );
  }

  const signaturePart = sigParts[1];
  if (!signaturePart) {
    throw new Error(`Invalid signature format: ${walletResult.signature}`);
  }
  const rawSignatureBytes = base58.decode(signaturePart);
  const signature = base64.encode(rawSignatureBytes);

  const authData: NearAuthData = {
    accountId: walletResult.accountId,
    publicKey: walletResult.publicKey,
    signature,
    message,
    nonce: Array.from(nonce),
    recipient,
    callbackUrl: callbackUrl || null,
    state: walletResult.state || state || null,
  };

  return createAuthToken(authData);
}

export async function sign(message: string, options: SignOptions): Promise<string> {
  const { signer, accountId, recipient, callbackUrl, nonce, state } = options;
  const currentNonce = nonce || generateNonce();

  // Detect signer type
  if (typeof (signer as WalletInterface).signMessage === "function") {
    return signWithWallet(signer as WalletInterface, message, recipient, currentNonce, callbackUrl, state);
  }
  
  if (typeof signer === "string" && signer.startsWith(ED25519_PREFIX)) {
    if (!accountId) {
      throw new Error("accountId is required when using a KeyPair signer.");
    }
    return signWithKeyPair(signer, accountId, message, recipient, currentNonce, callbackUrl, state);
  }

  throw new Error("Invalid signer: must be KeyPair or a wallet object with a signMessage method.");
}