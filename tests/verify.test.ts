import { describe, it, expect, spyOn, afterEach, beforeEach, mock } from "bun:test";
import { verify } from "../src/verify.ts";
import { createAuthToken } from "../src/utils.ts";
import * as cryptoModule from "../src/crypto.ts";
import * as authModule from "../src/utils.ts";
import type { NearAuthData } from "../src/types.ts";

// Mock dependencies
const fetchMock = spyOn(global, "fetch") as any;

describe("verify", () => {
  // Create a valid test nonce with proper timestamp format
  const createTestNonce = () => {
    const timestamp = Date.now().toString();
    const nonce = new Uint8Array(32);
    const timestampBytes = new TextEncoder().encode(timestamp.padStart(16, "0"));
    nonce.set(timestampBytes.slice(0, 16));
    nonce.set(new Uint8Array(16).fill(1), 16); // Fill with 1s for consistency
    return nonce;
  };
  const testNonce = createTestNonce();

  const baseAuthData: NearAuthData = {
    accountId: "testuser.testnet",
    publicKey: "ed25519:8hSHprDq2StXwMtNd43wDTXQYsjXcD4MJxUTvwtnmM4T",
    signature: "YN7xw5bhbD2VzrOlyyGwKKEaCBsuCVO9vu1AY1GkqQRRfOL2JNTjUUxJXp9KfC2nmA2xvytDdUzel0vmr/VDuA==",
    message: "test message",
    nonce: Array.from(testNonce),
    recipient: "recipient.near",
    callbackUrl: null,
    state: "test-state-123",
  };

  let authTokenString: string;

  beforeEach(() => {
    authTokenString = createAuthToken(baseAuthData);
  });

  afterEach(() => {
    fetchMock.mockClear();
  });

  describe("basic verification", () => {
    it("should validate a valid signature", async () => {
      // Mock successful responses
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString);

      expect(result.accountId).toBe(baseAuthData.accountId);
      expect(result.publicKey).toBe(baseAuthData.publicKey);
      expect(result.message).toBe("test message");
      expect(result.state).toBe("test-state-123");
      
      expect(global.fetch).toHaveBeenCalledWith(
        `https://test.api.fastnear.com/v0/public_key/${baseAuthData.publicKey}`
      );
      expect(verifySpy).toHaveBeenCalled();
      expect(nonceSpy).toHaveBeenCalledWith(new Uint8Array(baseAuthData.nonce), undefined);

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should use mainnet API for mainnet accounts", async () => {
      const mainnetAuthData = {
        ...baseAuthData,
        accountId: "user.near",
      };
      const mainnetToken = createAuthToken(mainnetAuthData);

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [mainnetAuthData.accountId] }),
      });
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(mainnetToken);

      expect(result.accountId).toBe(mainnetAuthData.accountId);
      expect(global.fetch).toHaveBeenCalledWith(
        `https://api.fastnear.com/v0/public_key/${mainnetAuthData.publicKey}`
      );

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should use /all endpoint when requireFullAccessKey is false", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        requireFullAccessKey: false,
      });

      expect(result.accountId).toBe(baseAuthData.accountId);
      expect(global.fetch).toHaveBeenCalledWith(
        `https://test.api.fastnear.com/v0/public_key/${baseAuthData.publicKey}/all`
      );

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should handle malformed auth token", async () => {
      await expect(verify("invalid-token")).rejects.toThrow("Failed to parse auth token");
    });
  });

  describe("validation options", () => {
    it("should validate recipient match", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        recipient: "recipient.near",
      });

      expect(result.accountId).toBe(baseAuthData.accountId);

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should reject recipient mismatch", async () => {
      await expect(
        verify(authTokenString, {
          recipient: "different-recipient.near",
        })
      ).rejects.toThrow("Recipient mismatch: expected 'different-recipient.near', but recipient is 'recipient.near'.");
    });

    it("should validate message match", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        message: "test message",
      });

      expect(result.message).toBe("test message");

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should reject message mismatch", async () => {
      await expect(
        verify(authTokenString, {
          message: "different message",
        })
      ).rejects.toThrow("Message mismatch: expected 'different message', got 'test message'.");
    });

    it("should validate state match", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        state: "test-state-123",
      });

      expect(result.state).toBe("test-state-123");

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should reject state mismatch", async () => {
      await expect(
        verify(authTokenString, {
          state: "different-state",
        })
      ).rejects.toThrow("State mismatch: expected 'different-state', got 'test-state-123'.");
    });

    it("should handle null state correctly", async () => {
      const authDataWithNullState = {
        ...baseAuthData,
        state: null,
      };
      const tokenWithNullState = createAuthToken(authDataWithNullState);

      await expect(
        verify(tokenWithNullState, {
          state: "expected-state",
        })
      ).rejects.toThrow("State mismatch: expected 'expected-state', got 'undefined'");
    });

    it("should pass custom nonce maxAge to validateNonce", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const customMaxAge = 5 * 60 * 1000; // 5 minutes
      await verify(authTokenString, { maxAge: customMaxAge });

      expect(nonceSpy).toHaveBeenCalledWith(new Uint8Array(baseAuthData.nonce), customMaxAge);

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });
  });

  describe("custom validators", () => {
    it("should use custom nonce validator", async () => {
      const customValidateNonce = mock((nonce: Uint8Array) => true);

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);

      const result = await verify(authTokenString, {
        validateNonce: customValidateNonce,
      });

      expect(result.accountId).toBe(baseAuthData.accountId);
      expect(customValidateNonce).toHaveBeenCalledWith(new Uint8Array(baseAuthData.nonce));

      verifySpy.mockRestore();
    });

    it("should reject when custom nonce validator returns false", async () => {
      const customValidateNonce = mock(() => false);

      await expect(
        verify(authTokenString, {
          validateNonce: customValidateNonce,
        })
      ).rejects.toThrow("Custom nonce validation failed");

      expect(customValidateNonce).toHaveBeenCalled();
    });

    it("should use custom recipient validator", async () => {
      const customValidateRecipient = mock((recipient: string) => true);

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        validateRecipient: customValidateRecipient,
      });

      expect(result.accountId).toBe(baseAuthData.accountId);
      expect(customValidateRecipient).toHaveBeenCalledWith("recipient.near");

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should reject when custom recipient validator returns false", async () => {
      const customValidateRecipient = mock(() => false);

      await expect(
        verify(authTokenString, {
          validateRecipient: customValidateRecipient,
        })
      ).rejects.toThrow("Custom recipient validation failed");

      expect(customValidateRecipient).toHaveBeenCalled();
    });

    it("should use custom message validator", async () => {
      const customValidateMessage = mock((message: string) => true);

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        validateMessage: customValidateMessage,
      });

      expect(result.accountId).toBe(baseAuthData.accountId);
      expect(customValidateMessage).toHaveBeenCalledWith("test message");

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should reject when custom message validator returns false", async () => {
      const customValidateMessage = mock(() => false);

      await expect(
        verify(authTokenString, {
          validateMessage: customValidateMessage,
        })
      ).rejects.toThrow("Custom message validation failed");

      expect(customValidateMessage).toHaveBeenCalled();
    });

    it("should use custom state validator", async () => {
      const customValidateState = mock((state?: string) => true);

      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockResolvedValue(undefined);
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      const result = await verify(authTokenString, {
        validateState: customValidateState,
      });

      expect(result.accountId).toBe(baseAuthData.accountId);
      expect(customValidateState).toHaveBeenCalledWith("test-state-123");

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should reject when custom state validator returns false", async () => {
      const customValidateState = mock(() => false);

      await expect(
        verify(authTokenString, {
          validateState: customValidateState,
        })
      ).rejects.toThrow("Custom state validation failed");

      expect(customValidateState).toHaveBeenCalled();
    });
  });

  describe("error handling", () => {
    it("should reject if public key ownership verification fails", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: ["different.testnet"] }),
      });
      
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      await expect(verify(authTokenString)).rejects.toThrow(
        "Public key ownership verification failed"
      );

      nonceSpy.mockRestore();
    });

    it("should reject if nonce validation fails", async () => {
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {
        throw new Error("Nonce expired");
      });

      await expect(verify(authTokenString)).rejects.toThrow(
        "Nonce validation failed: Nonce expired"
      );

      expect(global.fetch).not.toHaveBeenCalled();

      nonceSpy.mockRestore();
    });

    it("should reject if cryptographic signature verification fails", async () => {
      fetchMock.mockResolvedValueOnce({
        ok: true,
        json: async () => ({ account_ids: [baseAuthData.accountId] }),
      } as any);
      
      const verifySpy = spyOn(cryptoModule, "verifySignature").mockRejectedValue(
        new Error("Signature verification failed")
      );
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      await expect(verify(authTokenString)).rejects.toThrow(
        "Cryptographic signature verification failed: Signature verification failed"
      );

      verifySpy.mockRestore();
      nonceSpy.mockRestore();
    });

    it("should handle API network errors", async () => {
      (global.fetch as any).mockRejectedValueOnce(new Error("Network error"));
      
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {});

      await expect(verify(authTokenString)).rejects.toThrow(
        "Public key ownership verification failed"
      );

      nonceSpy.mockRestore();
    });

    it("should handle non-Error exceptions in nonce validation", async () => {
      const nonceSpy = spyOn(authModule, "validateNonce").mockImplementation(() => {
        throw new Error("Unknown error");
      });

      await expect(verify(authTokenString)).rejects.toThrow(
        "Nonce validation failed: Unknown error"
      );

      nonceSpy.mockRestore();
    });
  });
});