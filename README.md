# @thecannabisapp/libsignal-wasm

> Signal Protocol compiled to WebAssembly for browser-based E2EE messaging

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![WASM](https://img.shields.io/badge/WASM-Ready-green)](https://webassembly.org/)

## Features

- 🔐 **End-to-End Encryption** - Signal Protocol (X3DH + Double Ratchet)
- 🛡️ **Post-Quantum Ready** - Kyber1024 (PQXDH) support
- 👥 **Group Messaging** - Sender Keys for efficient group chats
- 🔢 **Safety Numbers** - Identity verification
- 💾 **Serialisation** - Export/import for IndexedDB persistence
- 🌐 **Browser-First** - Uses Web Crypto API for randomness

## Installation

```bash
npm install @thecannabisapp/libsignal-wasm
```

## Quick Start

```typescript
import init, { SignalClient } from '@thecannabisapp/libsignal-wasm';

// Initialise WASM module
await init();

// Create a new client
const client = new SignalClient('your-uuid', 1);

// Generate keys for registration
const prekeys = client.generate_prekeys(100);
const signedPrekey = client.generate_signed_prekey();
const kyberPrekey = client.generate_kyber_prekey();

// Get identity key for server upload
const identityKey = client.get_identity_public_key();
```

## API Reference

### SignalClient

| Method | Description |
|--------|-------------|
| `new(uuid, deviceId)` | Create a new client with a fresh identity |
| `restore(...)` | Restore from saved state |
| `generate_prekeys(count)` | Generate one-time PreKeys |
| `generate_signed_prekey()` | Generate signed PreKey |
| `generate_kyber_prekey()` | Generate Kyber PreKey (PQXDH) |
| `process_prekey_bundle(...)` | Establish session from bundle |
| `encrypt_message(uuid, deviceId, plaintext)` | Encrypt 1:1 message |
| `decrypt_message(uuid, deviceId, ciphertext, type)` | Decrypt 1:1 message |
| `create_sender_key_distribution(distributionId)` | Create group key |
| `encrypt_group_message(distributionId, plaintext)` | Encrypt group message |
| `decrypt_group_message(uuid, deviceId, ciphertext)` | Decrypt group message |
| `generate_safety_number(contactUuid, contactKey)` | Generate safety number |

### Utility Functions

| Function | Description |
|----------|-------------|
| `generate_random_bytes(length)` | Generate CSPRNG random bytes |
| `generate_uuid()` | Generate a UUID v4 |
| `uuid_to_string(bytes)` | Convert UUID bytes to string |
| `message_type_signal()` | Normal message type (2) |
| `message_type_prekey()` | PreKey message type (3) |

## Security

- ✅ `#![deny(unsafe_code)]` - No unsafe Rust
- ✅ `Zeroizing` - Private keys cleared on drop
- ✅ Input validation on all parameters
- ✅ Overflow protection on ID counters
- ✅ CSPRNG via Web Crypto API
- ✅ Generic error messages in production

### ⚠️ Memory Safety Caveat
While this library uses `Zeroizing` to clear secrets from WASM memory when they are dropped, **keys exported to JavaScript are subject to the browser's garbage collector**. We cannot guarantee that secrets moved into JS memory (e.g., via `get_identity_key_pair()`) are securely erased. Treat exported keys with extreme care.

## Build from Source

```bash
# Prerequisites
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

# Build
wasm-pack build --target web --release
```

## Vite Configuration

```typescript
// vite.config.ts
import wasm from 'vite-plugin-wasm';
import topLevelAwait from 'vite-plugin-top-level-await';

export default defineConfig({
  plugins: [wasm(), topLevelAwait()],
});
```

## License

AGPL-3.0 - See [LICENSE](LICENSE)

This package is built on [libsignal](https://github.com/signalapp/libsignal) by Signal Technology Foundation.

## Disclaimer

This package is not affiliated with or endorsed by Signal Technology Foundation. Signal and the Signal Protocol are trademarks of Signal Technology Foundation.
