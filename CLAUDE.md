# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a TypeScript library for NEP-413 compliant signing and verification of messages in the NEAR ecosystem. The library provides cryptographic signing and verification functionality for NEAR account authentication.

## Development Commands

- **Install dependencies**: `bun install`
- **Run main entry point**: `bun run index.ts`
- **Type checking**: `bun run typecheck` or `tsc --noEmit`
- **Run tests**: `bun test` (uses Bun's built-in test runner)
- **Run specific test file**: `bun test tests/crypto.test.ts`

## Architecture

The library is structured around three core operations:

1. **Signing** (`src/sign.ts`): Creates NEP-413 compliant auth tokens
   - Supports both KeyPair and Wallet interface signing
   - Generates or accepts custom nonces
   - Creates base64-encoded auth tokens

2. **Verification** (`src/verify.ts`): Validates auth tokens
   - Verifies cryptographic signatures using Ed25519
   - Validates public key ownership via FastNear API
   - Supports custom validation functions for all fields

3. **Crypto Operations** (`src/crypto.ts`): Core cryptographic functions
   - NEP-413 payload creation and hashing
   - Ed25519 signature verification
   - Public key ownership verification via FastNear API

## Key Components

- **Types** (`src/types.ts`): Core interfaces including `NearAuthData`, `SignOptions`, `VerifyOptions`
- **Utils** (`src/utils.ts`): Nonce generation/validation, auth token serialization using Zorsh
- **Crypto** (`src/crypto.ts`): Uses `@noble/curves` for Ed25519, `@scure/base` for encoding, `@zorsh/zorsh` for serialization

## Testing

The test suite uses Bun's built-in test runner with files in the `tests/` directory:
- Unit tests for each module with proper mocking of external dependencies
- Integration tests using real NEAR keypairs for end-to-end workflows
- Source-of-truth compatibility tests for regression detection
- Real cryptographic signing with deterministic test cases

## Git Workflow

- **ALWAYS commit your work**: Use `git commit` frequently to save progress
- **Use semantic commits**: Follow conventional commit format (feat:, fix:, docs:, etc.)
- **Commit early and often**: Save work at logical checkpoints throughout development

## External Dependencies

- Verifies public key ownership against FastNear API (mainnet: `api.fastnear.com`, testnet: `test.api.fastnear.com`)
- Automatically detects testnet accounts by `.testnet` suffix
- Supports both full access keys and function call keys based on `requireFullAccessKey` option
- Integration tests use `@near-js/account` for wallet functionality instead of FastNEAR