// Core functionality
export { sign } from "./sign.ts";
export { verify } from "./verify.ts";
export { parseAuthToken, generateNonce } from "./utils.ts";

// Essential types
export type {
  SignOptions,
  VerifyOptions,
  VerificationResult,
  NearAuthData,
  WalletInterface,
} from "./types.ts";