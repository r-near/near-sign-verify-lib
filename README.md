# NEAR Sign & Verify

A TypeScript library for **NEP-413 compliant** message signing and verification in the NEAR ecosystem. Perfect for implementing secure authentication flows with NEAR accounts.

## Features

- 🔐 **NEP-413 Compliant** - Follows NEAR's official authentication standard
- 🔑 **Flexible Signing** - Support for both KeyPair and Wallet-based signing
- ✅ **Robust Verification** - Cryptographic signature validation + public key ownership verification
- 🛡️ **Security First** - Built-in nonce validation, replay attack protection
- 📦 **Zero Config** - Works out of the box with sensible defaults

## Quick Start

```bash
npm install near-sign-verify
# or
bun add near-sign-verify
```

## Basic Usage

### Signing with a KeyPair

```typescript
import { sign } from 'near-sign-verify';

const authToken = await sign('Login to MyApp', {
  signer: 'ed25519:your-private-key-here',
  accountId: 'user.near',
  recipient: 'myapp.near'
});

console.log('Auth token:', authToken);
// Returns a base64-encoded NEP-413 compliant token
```

### Signing with a Wallet

```typescript
import { sign } from 'near-sign-verify';

// Your wallet object implementing NEP-413 signMessage
const wallet = {
  async signMessage({ message, recipient, nonce }) {
    // Wallet handles the signing
    return {
      accountId: 'user.near',
      publicKey: 'ed25519:...',
      signature: 'ed25519:...'
    };
  }
};

const authToken = await sign('Login to MyApp', {
  signer: wallet,
  recipient: 'myapp.near',
  state: 'csrf-token-123'
});
```

### Verifying Tokens

```typescript
import { verify } from 'near-sign-verify';

try {
  const result = await verify(authToken, {
    recipient: 'myapp.near',        // Must match
    message: 'Login to MyApp',      // Must match
    maxAge: 5 * 60 * 1000          // 5 minutes
  });
  
  console.log('✅ Valid signature from:', result.accountId);
  console.log('Message:', result.message);
  console.log('State:', result.state);
} catch (error) {
  console.log('❌ Invalid signature:', error.message);
}
```

## Real-World Example: Login Flow

Here's a complete authentication flow:

```typescript
import { sign, verify, parseAuthToken } from 'near-sign-verify';

// 1. Frontend: User clicks "Login with NEAR"
async function initiateLogin(wallet) {
  const authToken = await sign('Login to MyDApp', {
    signer: wallet,
    recipient: 'mydapp.near',
    state: generateCSRFToken(),
    callbackUrl: 'https://mydapp.com/auth/callback'
  });
  
  // Send token to your backend
  return fetch('/api/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authToken })
  });
}

// 2. Backend: Verify the token
async function handleAuthVerification(authToken) {
  try {
    const result = await verify(authToken, {
      recipient: 'mydapp.near',
      message: 'Login to MyDApp',
      maxAge: 10 * 60 * 1000, // 10 minutes
      
      // Custom validation
      validateState: (state) => isValidCSRFToken(state)
    });
    
    // Create user session
    const user = await findOrCreateUser(result.accountId);
    return createJWTToken(user);
    
  } catch (error) {
    throw new Error(`Authentication failed: ${error.message}`);
  }
}
```

## Advanced Usage

### Custom Nonce Handling

```typescript
import { generateNonce, sign, verify } from 'near-sign-verify';

// Generate a nonce for one-time use
const customNonce = generateNonce();

const authToken = await sign('One-time action', {
  signer: wallet,
  recipient: 'app.near',
  nonce: customNonce
});

// Verify with custom nonce validation
await verify(authToken, {
  validateNonce: (nonce) => {
    // Your custom nonce validation logic
    return isNonceValid(nonce) && !isNonceUsed(nonce);
  }
});
```

### Parsing Tokens Without Verification

```typescript
import { parseAuthToken } from 'near-sign-verify';

// Parse token to inspect contents (without cryptographic verification)
const authData = parseAuthToken(authToken);
console.log('Account:', authData.accountId);
console.log('Message:', authData.message);
console.log('Recipient:', authData.recipient);
console.log('State:', authData.state);
```

## Security Best Practices

1. **Always verify tokens server-side** - Never trust client-side validation alone
2. **Use appropriate maxAge** - Tokens should expire quickly (5-15 minutes)
3. **Validate recipients** - Ensure tokens are intended for your application
4. **Implement nonce tracking** - Prevent replay attacks in sensitive operations
5. **Validate state parameters** - Use for CSRF protection

```typescript
// ✅ Good: Comprehensive verification
await verify(authToken, {
  recipient: 'your-app.near',
  message: 'Expected message',
  maxAge: 5 * 60 * 1000,
  validateState: (state) => isValidCSRFToken(state)
});

// ❌ Bad: Minimal verification
await verify(authToken); // Missing recipient and other validations
```

## API Reference

### `sign(message, options)`
Creates a NEP-413 compliant authentication token.

### `verify(authToken, options?)`
Verifies an authentication token's cryptographic signature and public key ownership.

### `parseAuthToken(authToken)`
Parses a token without verification (useful for debugging).

### `generateNonce()`
Generates a secure nonce with timestamp for replay protection.

For detailed API documentation, see the TypeScript definitions.

## Requirements

- Node.js 18+ or Bun
- NEAR account for production verification

## License

MIT

---

Built for the NEAR ecosystem with ❤️