# @getmaapp/signal-wasm

> Signal Protocol compiled to WebAssembly for browser-based E2EE messaging

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![WASM](https://img.shields.io/badge/WASM-Ready-green)](https://webassembly.org/)
[![Version](https://img.shields.io/badge/Version-0.2.0-blue)](Cargo.toml)

## Features

- 🔐 **End-to-End Encryption** — Signal Protocol (X3DH + Double Ratchet)
- 🛡️ **Post-Quantum Ready** — Kyber1024 (PQXDH) support
- 👥 **Group Messaging** — Sender Keys and Private Groups (GV2)
- 🆔 **Flexible Identities** — Any string identifier (Firebase UIDs, usernames, UUIDs)
- 🔢 **Safety Numbers** — Identity verification fingerprints
- 💾 **Serialisation** — Export/import for IndexedDB persistence
- 🌐 **Browser-First** — Uses Web Crypto API for randomness

## Installation

```bash
npm install @getmaapp/signal-wasm
```

## Quick Start

```typescript
import init, {
  PrivateKey,
  IdentityKeyPair,
  ProtocolAddress,
  InMemIdentityKeyStore,
  InMemSessionStore,
  InMemPreKeyStore,
  InMemSignedPreKeyStore,
  InMemKyberPreKeyStore,
  generateRegistrationId,
  generatePreKeys,
  generateSignedPreKey,
  generateKyberPreKey,
  processPreKeyBundle,
  encryptMessage,
  decryptMessage,
} from "@getmaapp/signal-wasm";

// 1. Initialise the WASM module
await init();

// 2. Generate an identity (no device ID required)
const privateKey = PrivateKey.generate();
const publicKey = privateKey.getPublicKey();
const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
const registrationId = generateRegistrationId();

// 3. Create stores
const identityStore = new InMemIdentityKeyStore(identityKeyPair, registrationId);
const sessionStore = new InMemSessionStore();
const prekeyStore = new InMemPreKeyStore();
const signedPrekeyStore = new InMemSignedPreKeyStore();
const kyberPrekeyStore = new InMemKyberPreKeyStore();

// 4. Generate keys for registration
const prekeys = await generatePreKeys(1, 100, prekeyStore);
const signedPreKey = await generateSignedPreKey(1, identityKeyPair, signedPrekeyStore);
const kyberPreKey = await generateKyberPreKey(1, identityKeyPair, kyberPrekeyStore);

// 5. Addressing (device ID is only used here)
const localAddress = new ProtocolAddress("alice-firebase-uid", 1);
const bobAddress = new ProtocolAddress("bob-firebase-uid", 1);

// 6. Establish a session (Alice processes Bob's PreKey bundle)
await processPreKeyBundle(
  bobAddress,
  localAddress,
  bobRegistrationId,
  bobIdentityKey,
  bobSignedPreKey.id,
  bobSignedPreKeyPublic,
  bobSignedPreKey.signature,
  bobPreKey.id,
  bobPreKey.public_key,
  bobKyberPreKey.id,
  bobKyberPreKey.public_key,
  bobKyberPreKey.signature,
  sessionStore,
  identityStore,
);

// 7. Encrypt a message
const plaintext = new TextEncoder().encode("Hello Bob! 🔒");
const ciphertext = await encryptMessage(
  plaintext,
  bobAddress,
  localAddress,
  sessionStore,
  identityStore,
);

// 8. Decrypt a message
const decrypted = await decryptMessage(
  ciphertext.body,
  ciphertext.message_type,
  aliceAddress,
  bobAddress,
  sessionStore,
  identityStore,
  prekeyStore,
  signedPrekeyStore,
  kyberPrekeyStore,
);
```

## API Reference

### Crypto Primitives

| Class | Methods |
|-------|---------|
| `PrivateKey` | `generate()`, `getPublicKey()`, `serialize()`, `deserialize(data)` |
| `PublicKey` | `serialize()`, `deserialize(data)` |
| `IdentityKeyPair` | `constructor(publicKey, privateKey)`, `serialize()`, `deserialize(data)` |

### Protocol Address

| Class | Description |
|-------|-------------|
| `ProtocolAddress` | `constructor(name, deviceId)` — `name` can be any string (Firebase UID, UUID, etc.) |

### Stores (In-Memory)

All stores support import/export for IndexedDB persistence.

| Store | Constructor | Import/Export Methods |
|-------|-------------|----------------------|
| `InMemIdentityKeyStore` | `new(identityKeyPair, registrationId)` | — |
| `InMemSessionStore` | `new()` | `export_session(address)`, `import_session(address, bytes)`, `has_session(address)`, `archive_session(address)` |
| `InMemPreKeyStore` | `new()` | `export_pre_key(id)`, `import_pre_key(id, bytes)` |
| `InMemSignedPreKeyStore` | `new()` | `export_signed_pre_key(id)`, `import_signed_pre_key(id, bytes)` |
| `InMemKyberPreKeyStore` | `new()` | `export_kyber_pre_key(id)`, `import_kyber_pre_key(id, bytes)` |
| `InMemSenderKeyStore` | `new()` | `export_sender_key(address, distributionId)`, `import_sender_key(address, distributionId, bytes)` |

### Key Generation

| Function | Returns | Description |
|----------|---------|-------------|
| `generatePreKeys(startId, count, store)` | `Promise<WasmPreKey[]>` | Batch-generate one-time PreKeys |
| `generateSignedPreKey(id, identityKeyPair, store)` | `Promise<WasmSignedPreKey>` | Generate a signed PreKey |
| `generateKyberPreKey(id, identityKeyPair, store)` | `Promise<WasmKyberPreKey>` | Generate a Kyber PreKey (PQXDH) |
| `generateRegistrationId()` | `number` | Generate unbiased registration ID (1–16380) |

### Protocol Operations

| Function | Returns | Description |
|----------|---------|-------------|
| `processPreKeyBundle(...)` | `Promise<void>` | Establish a session from a PreKey bundle |
| `encryptMessage(plaintext, recipient, localAddress, sessionStore, identityStore)` | `Promise<WasmCiphertext>` | Encrypt a 1:1 message |
| `decryptMessage(ciphertext, type, sender, localAddress, sessionStore, identityStore, prekeyStore, signedPrekeyStore, kyberPrekeyStore)` | `Promise<Uint8Array>` | Decrypt a 1:1 message |
| `createSenderKeyDistribution(localAddress, distributionId, senderKeyStore)` | `Promise<Uint8Array>` | Create a sender key distribution message |
| `processSenderKeyDistribution(senderAddress, distMessage, senderKeyStore)` | `Promise<void>` | Process a sender key distribution message |
| `encryptGroupMessage(localAddress, distributionId, plaintext, senderKeyStore)` | `Promise<Uint8Array>` | Encrypt a group message |
| `decryptGroupMessage(senderAddress, ciphertext, senderKeyStore)` | `Promise<Uint8Array>` | Decrypt a group message |

### Safety Numbers

| Function | Returns | Description |
|----------|---------|-------------|
| `generateSafetyNumber(localUuid, localIdentityKey, contactUuid, contactIdentityKey)` | `WasmSafetyNumber` | Generate a safety number fingerprint |
| `verifySafetyNumber(scanned, localUuid, localIdentityKey, contactUuid, contactIdentityKey)` | `boolean` | Verify a scanned safety number |

### GV2 (Private Groups)

| Class | Methods |
|-------|---------|
| `WasmGroupMasterKey` | `generate()`, `from_bytes(bytes)`, `derive_identifier()`, `derive_secret_params()` |
| `WasmGroupIdentifier` | `serialize` |
| `WasmGroupSecretParams` | `serialize`, `get_identifier()` |

### Data Structures

| Struct | Properties |
|--------|------------|
| `WasmPreKey` | `id`, `public_key`, `record` |
| `WasmSignedPreKey` | `id`, `public_key`, `signature`, `timestamp`, `record` |
| `WasmKyberPreKey` | `id`, `public_key`, `signature`, `timestamp`, `record` |
| `WasmCiphertext` | `message_type`, `body` |
| `WasmSafetyNumber` | `displayable` (string), `scannable` (Uint8Array) |

### Utility Functions

| Function | Description |
|----------|-------------|
| `generate_random_bytes(length)` | Generate CSPRNG random bytes (max 1 MiB) |
| `generate_uuid()` | Generate a UUID v4 (returns 16 bytes) |
| `uuid_to_string(bytes)` | Convert 16 bytes to UUID string |
| `uuid_from_string(str)` | Convert UUID string to 16 bytes |
| `message_type_signal()` | Normal Signal message type constant |
| `message_type_pre_key()` | PreKey message type constant |
| `message_type_sender_key()` | Sender key message type constant |

## Vite Configuration

```typescript
// vite.config.ts
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
});
```

## Testing

We use `wasm-bindgen-test` for headless browser integration testing.

```bash
# Run tests in Headless Chrome
wasm-pack test --headless --chrome

# Run tests in Headless Firefox
wasm-pack test --headless --firefox
```

## Build from Source

```bash
# Prerequisites
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build
wasm-pack build --target web --scope getmaapp
```

## Security

- ✅ `#![deny(unsafe_code)]` — No unsafe Rust
- ✅ Input validation on all WASM-bound parameters
- ✅ Bounded allocations (`generate_random_bytes` limited to 1 MiB)
- ✅ PreKey batch generation limited to 500 keys
- ✅ 24-bit PreKey ID wrapping (matches Signal behaviour)
- ✅ CSPRNG via Web Crypto API
- ✅ Generic error messages in production builds

### ⚠️ Memory Safety Caveat

While this library uses `Zeroizing` to clear secrets from WASM memory when they are dropped, **keys exported to JavaScript are subject to the browser's garbage collector**. We cannot guarantee that secrets moved into JS memory (e.g., via `identityKeyPair.private_key.serialize()`) are securely erased. Treat exported keys with extreme care.

## Licence

AGPL-3.0 — See [LICENSE](LICENSE)

This package is built on [libsignal](https://github.com/signalapp/libsignal) by Signal Technology Foundation.

## Disclaimer

This package is not affiliated with or endorsed by Signal Technology Foundation. Signal and the Signal Protocol are trademarks of Signal Technology Foundation.
