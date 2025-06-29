import { describe, it, expect, beforeEach, afterEach, spyOn } from "bun:test";
import { generateNonce, validateNonce, createAuthToken, parseAuthToken } from "../src/utils.ts";
import type { NearAuthData } from "../src/types.ts";

describe("auth utilities", () => {
  describe("generateNonce", () => {
    it("should generate a 32-byte nonce", () => {
      const nonce = generateNonce();
      expect(nonce).toBeInstanceOf(Uint8Array);
      expect(nonce.length).toBe(32);
    });

    it("should generate different nonces on subsequent calls", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1).not.toEqual(nonce2);
    });

    it("should include timestamp in the first 16 bytes", () => {
      const mockTime = 1234567890123;
      const spy = spyOn(Date, "now").mockReturnValue(mockTime);

      const nonce = generateNonce();
      const decoder = new TextDecoder();
      const timestampBytes = nonce.slice(0, 16);
      const timestampStr = decoder.decode(timestampBytes).replace(/^0+/, "");
      const extractedTime = parseInt(timestampStr, 10);

      expect(extractedTime).toBe(mockTime);
      spy.mockRestore();
    });
  });

  describe("validateNonce", () => {
    afterEach(() => {
      // Clean up any spies
      spyOn(Date, "now").mockRestore();
    });

    it("should validate a fresh nonce", () => {
      const nonce = generateNonce();
      expect(() => validateNonce(nonce)).not.toThrow();
    });

    it("should reject an expired nonce", () => {
      const oldTime = Date.now() - 2 * 60 * 60 * 1000; // 2 hours ago
      const oldTimeStr = oldTime.toString().padStart(16, "0");
      const encoder = new TextEncoder();
      const nonce = new Uint8Array(32);
      const timestampBytes = encoder.encode(oldTimeStr);
      nonce.set(timestampBytes.slice(0, 16), 0);

      expect(() => validateNonce(nonce, 60 * 60 * 1000)).toThrow("expired");
    });

    it("should accept a nonce within maxAge", () => {
      const recentTime = Date.now() - 60 * 60 * 1000; // 1 hour ago
      const recentTimeStr = recentTime.toString().padStart(16, "0");
      const encoder = new TextEncoder();
      const nonce = new Uint8Array(32);
      const timestampBytes = encoder.encode(recentTimeStr);
      nonce.set(timestampBytes.slice(0, 16), 0);

      expect(() => validateNonce(nonce, 2 * 60 * 60 * 1000)).not.toThrow();
    });

    it("should reject a nonce with invalid length", () => {
      const shortNonce = new Uint8Array(16);
      expect(() => validateNonce(shortNonce)).toThrow("Invalid nonce length");
    });

    it("should reject a nonce from the future", () => {
      const currentTime = 1000000000000;
      spyOn(Date, "now").mockReturnValue(currentTime);

      const futureTime = currentTime + 60000; // 1 minute in future
      const futureTimeStr = futureTime.toString().padStart(16, "0");
      const encoder = new TextEncoder();
      const futureNonce = new Uint8Array(32);
      const timestampBytes = encoder.encode(futureTimeStr);
      futureNonce.set(timestampBytes.slice(0, 16), 0);

      expect(() => validateNonce(futureNonce)).toThrow("future");
    });

    it("should handle nonce with invalid timestamp", () => {
      const nonce = new Uint8Array(32);
      const encoder = new TextEncoder();
      const invalidBytes = encoder.encode("abcdefghijklmnop");
      nonce.set(invalidBytes, 0);

      expect(() => validateNonce(nonce)).toThrow("Invalid timestamp in nonce");
    });
  });

  describe("createAuthToken and parseAuthToken", () => {
    const sampleAuthData: NearAuthData = {
      accountId: "test.near",
      publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
      signature: "base64signature",
      message: "Hello, world!",
      nonce: Array(32).fill(0),
      recipient: "recipient.near",
      callbackUrl: null,
      state: "test-state",
    };

    it("should create and parse auth token correctly", () => {
      const token = createAuthToken(sampleAuthData);
      expect(typeof token).toBe("string");

      const parsed = parseAuthToken(token);
      expect(parsed.accountId).toBe(sampleAuthData.accountId);
      expect(parsed.publicKey).toBe(sampleAuthData.publicKey);
      expect(parsed.signature).toBe(sampleAuthData.signature);
      expect(parsed.message).toBe(sampleAuthData.message);
      expect(parsed.nonce).toEqual(sampleAuthData.nonce);
      expect(parsed.recipient).toBe(sampleAuthData.recipient);
      expect(parsed.state).toBe(sampleAuthData.state);
    });

    it("should handle callbackUrl when provided", () => {
      const authDataWithCallback = {
        ...sampleAuthData,
        callbackUrl: "https://example.com/callback",
      };

      const token = createAuthToken(authDataWithCallback);
      const parsed = parseAuthToken(token);
      expect(parsed.callbackUrl).toBe("https://example.com/callback");
    });

    it("should throw error for invalid token format", () => {
      const invalidToken = "invalid-base64-data";
      expect(() => parseAuthToken(invalidToken)).toThrow("Invalid auth token:");
    });

    it("should handle empty token", () => {
      expect(() => parseAuthToken("")).toThrow("Invalid auth token:");
    });

    it("should handle malformed base64", () => {
      const malformedBase64 = "SGVsbG8gV29ybGQ!"; // Invalid base64 character
      expect(() => parseAuthToken(malformedBase64)).toThrow("Invalid auth token:");
    });
  });
});