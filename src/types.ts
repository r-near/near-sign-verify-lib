// Core data structures
export interface NearAuthData {
    accountId: string;
    publicKey: string;
    signature: string;
    message: string;
    nonce: number[];
    recipient: string;
    callbackUrl: string | null;
    state?: string | null;
  }
  
  export interface SignedPayload {
    message: string;
    nonce: number[];
    recipient: string;
    callbackUrl: string | null;
  }
  
  // Wallet interface (NEP-413 compatible)
  export interface SignMessageParams {
    message: string;
    recipient: string;
    nonce: Uint8Array | Buffer;
    callbackUrl?: string;
    state?: string;
  }
  
  export interface SignedMessage {
    accountId: string;
    publicKey: string;
    signature: string;
    state?: string;
  }
  
  export interface WalletInterface {
    signMessage: (params: SignMessageParams) => Promise<SignedMessage>;
  }
  
  // Sign options
  export interface SignOptions {
    signer: string | WalletInterface;
    accountId?: string; // Required for KeyPair, ignored for wallet
    recipient: string;
    nonce?: Uint8Array;
    state?: string;
    callbackUrl?: string;
  }
  
  // Verify options (simplified)
  export interface VerifyOptions {
    // Simple validation options
    recipient?: string;
    message?: string;
    state?: string;
    maxAge?: number; // Nonce max age in milliseconds
    requireFullAccessKey?: boolean;
    
    // Advanced custom validators
    validateNonce?: (nonce: Uint8Array) => boolean;
    validateRecipient?: (recipient: string) => boolean;
    validateMessage?: (message: string) => boolean;
    validateState?: (state?: string) => boolean;
  }
  
  // Verification result
  export interface VerificationResult {
    accountId: string;
    message: string;
    publicKey: string;
    callbackUrl?: string;
    state?: string;
  }