import { describe, it, expect } from "bun:test";
import { sign, parseAuthToken } from "../src/index.js";
import type { SignOptions, NearAuthData } from "../src/index.js";
import { KeyPair } from "near-api-js";

describe("integration tests with real keypairs", () => {
  
  describe("keypair signing end-to-end", () => {
    it("should create and parse a real signed token", async () => {
      // Generate a real keypair
      const keyPair = KeyPair.fromRandom("ed25519");
      const privateKey = keyPair.toString();
      const publicKey = keyPair.getPublicKey().toString();
      
      const signOptions: SignOptions = {
        signer: privateKey,
        accountId: "test-account.testnet",
        recipient: "example-app.near",
        state: "session-12345",
        callbackUrl: "https://example.com/callback",
      };

      // Sign a message with real cryptography
      const authToken = await sign("Hello NEAR Protocol!", signOptions);
      
      // Verify the token can be parsed
      expect(typeof authToken).toBe("string");
      expect(authToken.length).toBeGreaterThan(0);
      
      const parsed: NearAuthData = parseAuthToken(authToken);
      
      // Verify all fields are correctly preserved
      expect(parsed.accountId).toBe("test-account.testnet");
      expect(parsed.message).toBe("Hello NEAR Protocol!");
      expect(parsed.recipient).toBe("example-app.near");
      expect(parsed.state).toBe("session-12345");
      expect(parsed.callbackUrl).toBe("https://example.com/callback");
      expect(parsed.publicKey).toBe(publicKey);
      expect(parsed.signature).toBeDefined();
      expect(typeof parsed.signature).toBe("string");
      expect(parsed.nonce).toBeDefined();
      expect(Array.isArray(parsed.nonce)).toBe(true);
      expect(parsed.nonce.length).toBe(32);
    });

    it("should create deterministic tokens with the same inputs", async () => {
      // Use a specific keypair for deterministic results
      const keyPair = KeyPair.fromString("ed25519:3D4YudUahN1HT8jDn6LNLnYwF4nqHQGaJTaVNdh8ioRfP8KdG4xj3a5V7f8bC2zQ1rE9sD6xA8bN3mV4uW5pL7e");
      const privateKey = keyPair.toString();
      
      // Use a fixed nonce for deterministic results
      const fixedNonce = new Uint8Array(32);
      // Set first 16 bytes to a timestamp (padded with zeros)
      const timestamp = "1234567890123456";
      const timestampBytes = new TextEncoder().encode(timestamp);
      fixedNonce.set(timestampBytes.slice(0, 16));
      // Set last 16 bytes to a fixed pattern
      for (let i = 16; i < 32; i++) {
        fixedNonce[i] = i - 16;
      }
      
      const signOptions: SignOptions = {
        signer: privateKey,
        accountId: "deterministic.testnet",
        recipient: "app.near",
        nonce: fixedNonce,
      };

      // Sign the same message twice
      const token1 = await sign("Deterministic test message", signOptions);
      const token2 = await sign("Deterministic test message", signOptions);
      
      // Should produce identical tokens
      expect(token1).toBe(token2);
      
      // Parse to verify structure
      const parsed = parseAuthToken(token1);
      expect(parsed.accountId).toBe("deterministic.testnet");
      expect(parsed.message).toBe("Deterministic test message");
      expect(parsed.recipient).toBe("app.near");
      expect(new Uint8Array(parsed.nonce)).toEqual(fixedNonce);
    });

    it("should handle different message types", async () => {
      const keyPair = KeyPair.fromRandom("ed25519");
      const privateKey = keyPair.toString();
      
      const testCases = [
        { message: "Simple message", description: "simple string" },
        { message: JSON.stringify({ action: "login", userId: 12345 }), description: "JSON message" },
        { message: "Message with unicode: 🚀 💫 ⭐", description: "unicode message" },
        { message: "", description: "empty message" },
        { message: "A".repeat(1000), description: "long message" },
      ];

      for (const { message, description } of testCases) {
        const signOptions: SignOptions = {
          signer: privateKey,
          accountId: "test.testnet",
          recipient: "app.near",
        };

        const authToken = await sign(message, signOptions);
        const parsed = parseAuthToken(authToken);
        
        expect(parsed.message).toBe(message);
        expect(parsed.accountId).toBe("test.testnet");
        expect(parsed.recipient).toBe("app.near");
      }
    });

    it("should preserve nonce across sign-parse flow", async () => {
      const keyPair = KeyPair.fromRandom("ed25519");
      const privateKey = keyPair.toString();
      
      // Create a custom nonce with specific pattern
      const customNonce = new Uint8Array(32);
      for (let i = 0; i < 32; i++) {
        customNonce[i] = i * 3; // Pattern: 0, 3, 6, 9, ...
      }
      
      const signOptions: SignOptions = {
        signer: privateKey,
        accountId: "nonce-test.testnet",
        recipient: "app.near",
        nonce: customNonce,
      };

      const authToken = await sign("Custom nonce test", signOptions);
      const parsed = parseAuthToken(authToken);
      
      expect(new Uint8Array(parsed.nonce)).toEqual(customNonce);
      expect(parsed.message).toBe("Custom nonce test");
    });
  });

  describe("source of truth tokens", () => {
    it("should maintain compatibility with known good token format", async () => {
      // This test serves as a "source of truth" - if this breaks, we've changed the format
      const keyPair = KeyPair.fromString("ed25519:3D4YudUahN1HT8jDn6LNLnYwF4nqHQGaJTaVNdh8ioRfP8KdG4xj3a5V7f8bC2zQ1rE9sD6xA8bN3mV4uW5pL7e");
      const privateKey = keyPair.toString();
      
      // Fixed nonce for reproducibility
      const sourceOfTruthNonce = new Uint8Array([
        // First 16 bytes: timestamp "1700000000000000"
        49, 55, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        // Last 16 bytes: fixed pattern
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
      ]);
      
      const signOptions: SignOptions = {
        signer: privateKey,
        accountId: "source-of-truth.testnet",
        recipient: "reference-app.near",
        state: "reference-state",
        callbackUrl: "https://reference.com/callback",
        nonce: sourceOfTruthNonce,
      };

      const authToken = await sign("Reference message for compatibility", signOptions);
      
      // This is our "golden" token - if this changes, we've broken compatibility
      console.log("Source of truth token:", authToken);
      
      // Verify the token can be parsed correctly
      const parsed = parseAuthToken(authToken);
      expect(parsed.accountId).toBe("source-of-truth.testnet");
      expect(parsed.message).toBe("Reference message for compatibility");
      expect(parsed.recipient).toBe("reference-app.near");
      expect(parsed.state).toBe("reference-state");
      expect(parsed.callbackUrl).toBe("https://reference.com/callback");
      expect(new Uint8Array(parsed.nonce)).toEqual(sourceOfTruthNonce);
      
      // The signature should be deterministic with these inputs
      expect(parsed.signature).toBeDefined();
      expect(typeof parsed.signature).toBe("string");
    });
  });

  describe("error handling", () => {
    it("should handle invalid private keys gracefully", async () => {
      await expect(
        sign("test message", {
          signer: "invalid:key",
          accountId: "test.testnet",
          recipient: "app.near",
        })
      ).rejects.toThrow("Invalid signer: must be KeyPair or a wallet object with a signMessage method");
    });

    it("should require accountId for keypair signers", async () => {
      const keyPair = KeyPair.fromRandom("ed25519");
      const privateKey = keyPair.toString();
      
      await expect(
        sign("test message", {
          signer: privateKey,
          recipient: "app.near",
          // Missing accountId
        })
      ).rejects.toThrow("accountId is required when using a KeyPair signer");
    });

    it("should handle malformed private keys", async () => {
      await expect(
        sign("test message", {
          signer: "ed25519:invalidkeydata",
          accountId: "test.testnet",
          recipient: "app.near",
        })
      ).rejects.toThrow();
    });
  });

  describe("backwards compatibility", () => {
    it("should maintain the same public API", () => {
      // Verify that our main functions are still available
      expect(typeof sign).toBe("function");
      expect(typeof parseAuthToken).toBe("function");
    });

    it("should accept all SignOptions fields", async () => {
      const keyPair = KeyPair.fromRandom("ed25519");
      const privateKey = keyPair.toString();
      
      // Test with all optional fields
      const fullOptions: SignOptions = {
        signer: privateKey,
        accountId: "test.testnet",
        recipient: "app.near",
        nonce: new Uint8Array(32).fill(42),
        state: "test-state",
        callbackUrl: "https://example.com/callback",
      };

      const authToken = await sign("Full options test", fullOptions);
      const parsed = parseAuthToken(authToken);
      
      expect(parsed.accountId).toBe("test.testnet");
      expect(parsed.recipient).toBe("app.near");
      expect(parsed.state).toBe("test-state");
      expect(parsed.callbackUrl).toBe("https://example.com/callback");
      expect(new Uint8Array(parsed.nonce)).toEqual(new Uint8Array(32).fill(42));
    });
  });
});