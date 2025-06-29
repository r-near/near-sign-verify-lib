import { describe, it, expect, spyOn, afterEach } from "bun:test";
import { 
  createNEP413Payload, 
  hashPayload, 
  verifySignature, 
  verifyPublicKeyOwner,
  ED25519_PREFIX 
} from "../src/crypto.ts";
import type { SignedPayload } from "../src/types.ts";

// Mock fetch globally
const fetchMock = spyOn(global, "fetch") as any;

describe("crypto utilities", () => {
  afterEach(() => {
    fetchMock.mockClear();
  });

  describe("createNEP413Payload", () => {
    it("should create a valid NEP-413 payload", () => {
      const payload: SignedPayload = {
        message: "test message",
        nonce: new Array(32).fill(1),
        recipient: "test.near",
        callbackUrl: "https://example.com/callback",
      };

      const serialized = createNEP413Payload(payload);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

    it("should handle payload without callbackUrl", () => {
      const payload: SignedPayload = {
        message: "test message",
        nonce: new Array(32).fill(1),
        recipient: "test.near",
        callbackUrl: null,
      };

      const serialized = createNEP413Payload(payload);
      expect(serialized).toBeInstanceOf(Uint8Array);
      expect(serialized.length).toBeGreaterThan(0);
    });

    it("should produce consistent results for same payload", () => {
      const payload: SignedPayload = {
        message: "consistent test",
        nonce: new Array(32).fill(42),
        recipient: "test.near",
        callbackUrl: null,
      };

      const serialized1 = createNEP413Payload(payload);
      const serialized2 = createNEP413Payload(payload);
      expect(serialized1).toEqual(serialized2);
    });
  });

  describe("hashPayload", () => {
    it("should hash a payload correctly", () => {
      const payload = new Uint8Array([1, 2, 3, 4, 5]);
      const hash = hashPayload(payload);
      
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBe(32); // SHA-256 produces 32-byte hash
    });

    it("should produce the same hash for the same payload", () => {
      const payload = new Uint8Array(Array.from({ length: 100 }, (_, i) => i));
      const hash1 = hashPayload(payload);
      const hash2 = hashPayload(payload);
      expect(hash1).toEqual(hash2);
    });

    it("should produce different hashes for different payloads", () => {
      const payload1 = new Uint8Array([1, 2, 3]);
      const payload2 = new Uint8Array([4, 5, 6]);
      const hash1 = hashPayload(payload1);
      const hash2 = hashPayload(payload2);
      expect(hash1).not.toEqual(hash2);
    });
  });

  describe("verifySignature", () => {
    it("should throw for unsupported public key types", async () => {
      const invalidKey = "rsa:somekeydata";
      const mockHash = new Uint8Array(32);
      const mockSignature = new Uint8Array(64);

      await expect(
        verifySignature(mockHash, mockSignature, invalidKey)
      ).rejects.toThrow('Unsupported public key type: "rsa:somekeydata". Must start with "ed25519:".');
    });

    it("should throw if Ed25519 public key is malformed", async () => {
      const malformedKey = ED25519_PREFIX + "invalidKeyData"; // "l" is invalid base58
      const mockHash = new Uint8Array(32);
      const mockSignature = new Uint8Array(64);

      await expect(
        verifySignature(mockHash, mockSignature, malformedKey)
      ).rejects.toThrow();
    });

    it("should throw for invalid Ed25519 signature", async () => {
      // Create a valid key but invalid signature
      const validKey = "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T";
      const mockHash = new Uint8Array(32);
      const invalidSignature = new Uint8Array(64).fill(255); // Invalid signature

      await expect(
        verifySignature(mockHash, invalidSignature, validKey)
      ).rejects.toThrow("Ed25519 signature verification failed.");
    });
  });

  describe("verifyPublicKeyOwner", () => {
    it("should verify public key ownership successfully", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ account_ids: ["test.testnet"] }),
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await expect(
        verifyPublicKeyOwner("test.testnet", "ed25519:somekey", true)
      ).resolves.toBeUndefined();

      expect(global.fetch).toHaveBeenCalledWith(
        "https://test.api.fastnear.com/v0/public_key/ed25519:somekey"
      );
    });

    it("should use mainnet API for mainnet accounts", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ account_ids: ["test.near"] }),
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await verifyPublicKeyOwner("test.near", "ed25519:somekey", true);

      expect(global.fetch).toHaveBeenCalledWith(
        "https://api.fastnear.com/v0/public_key/ed25519:somekey"
      );
    });

    it("should use /all endpoint when requireFullAccessKey is false", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ account_ids: ["test.testnet"] }),
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await verifyPublicKeyOwner("test.testnet", "ed25519:somekey", false);

      expect(global.fetch).toHaveBeenCalledWith(
        "https://test.api.fastnear.com/v0/public_key/ed25519:somekey/all"
      );
    });

    it("should throw when API returns non-ok response", async () => {
      const mockResponse = {
        ok: false,
        status: 500,
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await expect(
        verifyPublicKeyOwner("test.testnet", "ed25519:somekey", true)
      ).rejects.toThrow("Public key ownership verification failed");
    });

    it("should throw when account ID is not found", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ account_ids: ["other.testnet"] }),
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await expect(
        verifyPublicKeyOwner("test.testnet", "ed25519:somekey", true)
      ).rejects.toThrow("Public key ownership verification failed");
    });

    it("should handle API returning unexpected format", async () => {
      const mockResponse = {
        ok: true,
        json: async () => ({ unexpected: "format" }),
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await expect(
        verifyPublicKeyOwner("test.testnet", "ed25519:somekey", true)
      ).rejects.toThrow("Public key ownership verification failed");
    });

    it("should handle network errors", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network error"));

      await expect(
        verifyPublicKeyOwner("test.testnet", "ed25519:somekey", true)
      ).rejects.toThrow("Public key ownership verification failed");
    });

    it("should handle JSON parsing errors", async () => {
      const mockResponse = {
        ok: true,
        json: async () => {
          throw new Error("Invalid JSON");
        },
      } as any;
      fetchMock.mockResolvedValueOnce(mockResponse);

      await expect(
        verifyPublicKeyOwner("test.testnet", "ed25519:somekey", true)
      ).rejects.toThrow("Public key ownership verification failed");
    });
  });
});