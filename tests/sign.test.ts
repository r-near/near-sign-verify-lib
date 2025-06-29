import { describe, it, expect, spyOn } from "bun:test";
import { sign } from "../src/sign.js";
import { parseAuthToken } from "../src/auth.js";
import type { WalletInterface, SignOptions } from "../src/types.js";

describe("sign", () => {
  describe("signer type detection", () => {
    it("should throw error when accountId is missing for KeyPair signer", async () => {
      const keyPair = "ed25519:somevalidkeyhere";

      await expect(
        sign("hello", {
          signer: keyPair,
          recipient: "recipient.near",
        })
      ).rejects.toThrow("accountId is required when using a KeyPair signer");
    });

    it("should throw error for invalid signer type", async () => {
      const invalidSigner = {
        someOtherMethod: () => {},
      } as any;

      await expect(
        sign("hello", {
          signer: invalidSigner,
          accountId: "test.near",
          recipient: "recipient.near",
        })
      ).rejects.toThrow(
        "Invalid signer: must be KeyPair or a wallet object with a signMessage method"
      );
    });

    it("should throw error for object with only partial WalletInterface", async () => {
      const partialWallet = {
        someMethod: () => {},
      } as any;

      await expect(
        sign("hello", {
          signer: partialWallet,
          accountId: "test.near",
          recipient: "recipient.near",
        })
      ).rejects.toThrow(
        "Invalid signer: must be KeyPair or a wallet object with a signMessage method"
      );
    });
  });

  describe("wallet signing", () => {
    it("should handle wallet signing errors", async () => {
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => {
          throw new Error("Wallet signing failed");
        }),
      };

      await expect(
        sign("hello", {
          signer: mockWallet,
          recipient: "recipient.near",
        })
      ).rejects.toThrow("Wallet signing failed");
    });

    it("should work with wallet that provides accountId", async () => {
      // Create a mock 64-byte signature
      const rawSignature = new Uint8Array(64).fill(1);
      
      // Convert to base58 for the wallet response format
      const { base58 } = await import("@scure/base");
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => ({
          signature: `ed25519:${base58Signature}`,
          publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
          accountId: "wallet-provided.near",
        })),
      };

      const result = await sign("hello", {
        signer: mockWallet,
        recipient: "recipient.near",
      });

      expect(typeof result).toBe("string");
      expect(mockWallet.signMessage).toHaveBeenCalled();

      // Verify the token can be parsed
      const parsed = parseAuthToken(result);
      expect(parsed.accountId).toBe("wallet-provided.near");
      expect(parsed.message).toBe("hello");
      expect(parsed.recipient).toBe("recipient.near");
    });

    it("should handle unsupported signature format from wallet", async () => {
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => ({
          signature: "rsa:someinvalidsignature",
          publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
          accountId: "test.near",
        })),
      };

      await expect(
        sign("hello", {
          signer: mockWallet,
          recipient: "recipient.near",
        })
      ).rejects.toThrow("Unsupported signature format from wallet");
    });

    it("should include state from wallet response", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(1);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => ({
          signature: `ed25519:${base58Signature}`,
          publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
          accountId: "test.near",
          state: "wallet-state-123",
        })),
      };

      const result = await sign("hello", {
        signer: mockWallet,
        recipient: "recipient.near",
        state: "options-state-456",
      });

      const parsed = parseAuthToken(result);
      // Wallet state should take precedence
      expect(parsed.state).toBe("wallet-state-123");
    });
  });

  describe("keypair signing", () => {
    it("should throw error for invalid KeyPair format", async () => {
      const invalidKeyPair = "invalid:keypairformat";

      await expect(
        sign("hello", {
          signer: invalidKeyPair,
          accountId: "test.near",
          recipient: "recipient.near",
        })
      ).rejects.toThrow("Invalid KeyPair format: missing ed25519 prefix");
    });

    it("should throw error for malformed key string", async () => {
      const malformedKeyPair = "ed25519:ThisIsNotValidBase58AndWillCauseAnErrorDuringDecoding!!!";
      
      await expect(
        sign("hello", {
          signer: malformedKeyPair,
          accountId: "test.near",
          recipient: "recipient.near",
        })
      ).rejects.toThrow();
    });

    it("should throw error for wrong key length", async () => {
      // Create a valid base58 string but wrong length
      const { base58 } = await import("@scure/base");
      const shortKey = base58.encode(new Uint8Array(32)); // Should be 64 bytes
      const invalidKeyPair = `ed25519:${shortKey}`;

      await expect(
        sign("hello", {
          signer: invalidKeyPair,
          accountId: "test.near",
          recipient: "recipient.near",
        })
      ).rejects.toThrow("Expected decoded private key to be 64 bytes");
    });
  });

  describe("options handling", () => {
    it("should use provided nonce", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(1);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => ({
          signature: `ed25519:${base58Signature}`,
          publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
          accountId: "test.near",
        })),
      };

      const specificNonce = new Uint8Array(32).fill(42);
      
      const result = await sign("hello", {
        signer: mockWallet,
        recipient: "recipient.near",
        nonce: specificNonce,
      });

      const parsed = parseAuthToken(result);
      expect(new Uint8Array(parsed.nonce)).toEqual(specificNonce);
    });

    it("should include callbackUrl when provided", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(1);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => ({
          signature: `ed25519:${base58Signature}`,
          publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
          accountId: "test.near",
        })),
      };

      const result = await sign("hello", {
        signer: mockWallet,
        recipient: "recipient.near",
        callbackUrl: "https://example.com/callback",
      });

      const parsed = parseAuthToken(result);
      expect(parsed.callbackUrl).toBe("https://example.com/callback");
    });

    it("should include state when provided", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(1);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet: WalletInterface = {
        signMessage: spyOn(async () => ({
          signature: `ed25519:${base58Signature}`,
          publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
          accountId: "test.near",
        })),
      };

      const result = await sign("hello", {
        signer: mockWallet,
        recipient: "recipient.near",
        state: "test-state-123",
      });

      const parsed = parseAuthToken(result);
      expect(parsed.state).toBe("test-state-123");
    });
  });
});