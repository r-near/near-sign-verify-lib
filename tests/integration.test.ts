import { describe, it, expect, beforeAll } from "bun:test";
import { sign, verify, parseAuthToken } from "../src/index.js";
import type { SignOptions, VerificationResult, NearAuthData, WalletInterface } from "../src/index.js";

describe("integration tests", () => {
  // Mock wallet for testing
  class MockWallet implements WalletInterface {
    constructor(
      private accountId: string,
      private publicKey: string,
      private mockSignature: string = "ed25519:mockSignatureBase58"
    ) {}

    async signMessage(params: any) {
      return {
        accountId: this.accountId,
        publicKey: this.publicKey,
        signature: this.mockSignature,
        state: params.state,
      };
    }
  }

  describe("sign-verify flow", () => {
    it("should create a token that can be parsed", async () => {
      // Create a mock signature that's properly formatted
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(42);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet = new MockWallet(
        "test.testnet",
        "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
        `ed25519:${base58Signature}`
      );

      const signOptions: SignOptions = {
        signer: mockWallet,
        recipient: "app.near",
        state: "test-state-123",
        callbackUrl: "https://example.com/callback",
      };

      const authToken = await sign("Test message", signOptions);
      
      // Verify the token can be parsed
      expect(typeof authToken).toBe("string");
      
      const parsed: NearAuthData = parseAuthToken(authToken);
      expect(parsed.accountId).toBe("test.testnet");
      expect(parsed.message).toBe("Test message");
      expect(parsed.recipient).toBe("app.near");
      expect(parsed.state).toBe("test-state-123");
      expect(parsed.callbackUrl).toBe("https://example.com/callback");
      expect(parsed.publicKey).toBe("ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T");
    });

    it("should handle different message types", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(1);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet = new MockWallet(
        "test.testnet",
        "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
        `ed25519:${base58Signature}`
      );

      // Test with JSON message
      const jsonMessage = JSON.stringify({ action: "login", userId: 123 });
      const authToken = await sign(jsonMessage, {
        signer: mockWallet,
        recipient: "app.near",
      });

      const parsed = parseAuthToken(authToken);
      expect(parsed.message).toBe(jsonMessage);
      expect(() => JSON.parse(parsed.message)).not.toThrow();
    });

    it("should preserve nonce across sign-parse flow", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(7);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet = new MockWallet(
        "test.testnet",
        "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
        `ed25519:${base58Signature}`
      );

      const customNonce = new Uint8Array(32).fill(99);
      
      const authToken = await sign("Test with custom nonce", {
        signer: mockWallet,
        recipient: "app.near",
        nonce: customNonce,
      });

      const parsed = parseAuthToken(authToken);
      expect(new Uint8Array(parsed.nonce)).toEqual(customNonce);
    });
  });

  describe("validation workflows", () => {
    it("should demonstrate simple validation pattern", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(3);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet = new MockWallet(
        "user.testnet",
        "ed25519:validPublicKey",
        `ed25519:${base58Signature}`
      );

      // Sign a message
      const authToken = await sign("Login request", {
        signer: mockWallet,
        recipient: "myapp.near",
        state: "csrf-protection-123",
      });

      // Parse without validation (for debugging)
      const parsed = parseAuthToken(authToken);
      expect(parsed.accountId).toBe("user.testnet");
      expect(parsed.recipient).toBe("myapp.near");
      expect(parsed.state).toBe("csrf-protection-123");

      // This would normally call the actual verify function, but we can't
      // in tests without mocking the FastNEAR API and crypto verification
      // The verify function would do:
      // 1. Parse the token (✓ tested above)
      // 2. Validate nonce timestamp
      // 3. Check recipient matches
      // 4. Verify public key ownership via FastNEAR API
      // 5. Verify cryptographic signature
    });

    it("should demonstrate custom validation pattern", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(5);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet = new MockWallet(
        "premium-user.testnet",
        "ed25519:validPublicKey",
        `ed25519:${base58Signature}`
      );

      const authToken = await sign("Premium feature access", {
        signer: mockWallet,
        recipient: "premium-app.near",
        state: "premium-session-456",
      });

      const parsed = parseAuthToken(authToken);
      
      // Custom validation examples that would be used in verify()
      const isValidRecipient = (recipient: string) => {
        return ["premium-app.near", "app.near"].includes(recipient);
      };

      const isValidMessage = (message: string) => {
        return message.includes("Premium") || message.includes("Standard");
      };

      const isValidState = (state?: string) => {
        return state?.startsWith("premium-session-") || state?.startsWith("standard-session-");
      };

      // These would be passed to verify() as custom validators
      expect(isValidRecipient(parsed.recipient)).toBe(true);
      expect(isValidMessage(parsed.message)).toBe(true);
      expect(isValidState(parsed.state)).toBe(true);
    });
  });

  describe("error scenarios", () => {
    it("should handle corrupted token gracefully", () => {
      const corruptedToken = "this-is-not-a-valid-base64-token!@#$";
      
      expect(() => parseAuthToken(corruptedToken)).toThrow("Invalid auth token:");
    });

    it("should handle empty token", () => {
      expect(() => parseAuthToken("")).toThrow("Invalid auth token:");
    });

    it("should handle wallet signing failures", async () => {
      const failingWallet: WalletInterface = {
        signMessage: async () => {
          throw new Error("User rejected signing");
        },
      };

      await expect(
        sign("Test message", {
          signer: failingWallet,
          recipient: "app.near",
        })
      ).rejects.toThrow("User rejected signing");
    });
  });

  describe("backwards compatibility", () => {
    it("should maintain the same public API", () => {
      // Verify that our main exports are still available
      expect(typeof sign).toBe("function");
      expect(typeof verify).toBe("function");
      expect(typeof parseAuthToken).toBe("function");
    });

    it("should accept the same SignOptions interface", async () => {
      const { base58 } = await import("@scure/base");
      const rawSignature = new Uint8Array(64).fill(8);
      const base58Signature = base58.encode(rawSignature);
      
      const mockWallet = new MockWallet(
        "test.testnet",
        "ed25519:validKey",
        `ed25519:${base58Signature}`
      );

      // All optional fields should still work
      const fullOptions: SignOptions = {
        signer: mockWallet,
        recipient: "app.near",
        accountId: "ignored-for-wallet", // Should be ignored for wallet
        nonce: new Uint8Array(32).fill(1),
        state: "test-state",
        callbackUrl: "https://example.com/callback",
      };

      const authToken = await sign("Compatibility test", fullOptions);
      const parsed = parseAuthToken(authToken);
      
      expect(parsed.accountId).toBe("test.testnet"); // From wallet, not options
      expect(parsed.recipient).toBe("app.near");
      expect(parsed.state).toBe("test-state");
      expect(parsed.callbackUrl).toBe("https://example.com/callback");
    });
  });
});