# @thecannabisapp/libsignal-wasm

> Signal Protocol compiled to WebAssembly for browser-based E2EE messaging

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![WASM](https://img.shields.io/badge/WASM-Ready-green)](https://webassembly.org/)
[![Version](https://img.shields.io/badge/Version-0.1.0-blue)](Cargo.toml)

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
const prekeys = client.generate_pre_keys(100);
const signedPreKey = client.generate_signed_pre_key();
const kyberPreKey = client.generate_kyber_pre_key();

// Get identity key for server upload
const identityKey = client.get_identity_public_key();
```

## API Reference

### SignalClient

| Method | Description |
|--------|-------------|
| `new(uuid, deviceId)` | Create a new client with a fresh identity |
| `restore(...)` | Restore client identity from saved data |
| `generate_pre_keys(count)` | Generate one-time PreKeys |
| `generate_signed_pre_key()` | Generate signed PreKey |
| `generate_kyber_pre_key()` | Generate Kyber PreKey (PQXDH) |
| `process_pre_key_bundle(...)` | Establish session from bundle |
| `encrypt_message(...)` | Encrypt 1:1 message |
| `decrypt_message(...)` | Decrypt 1:1 message |
| `create_sender_key_dist(...)` | Create group key distribution message |
| `encrypt_group_message(...)` | Encrypt group message |
| `decrypt_group_message(...)` | Decrypt group message |
| `generate_safety_number(...)` | Generate safety number for verification |
| `verify_safety_number(...)` | Verify a scanned safety number |
| `get_next_pre_key_id()` | Get next PreKey ID |
| `get_next_signed_pre_key_id()` | Get next Signed PreKey ID |
| `get_next_kyber_pre_key_id()` | Get next Kyber PreKey ID |

### State Persistence (IndexedDB)

Methods to export and import serialised records for persistence:

| Method | Description |
|--------|-------------|
| `export_session(uuid, devId)` | Export encrypted session record |
| `import_session(uuid, devId, bytes)` | Import encrypted session record |
| `export_pre_key(id)` | Export full PreKey record (with private key) |
| `import_pre_key(id, bytes)` | Import full PreKey record |
| `export_signed_pre_key(id)` | Export full Signed PreKey record |
| `import_signed_pre_key(id, bytes)` | Import full Signed PreKey record |
| `export_kyber_pre_key(id)` | Export full Kyber PreKey record |
| `import_kyber_pre_key(id, bytes)` | Import full Kyber PreKey record |
| `export_sender_key(...)` | Export Group Sender Key record |
| `import_sender_key(...)` | Import Group Sender Key record |

### Data Structures

| Struct | Properties |
|--------|------------|
| `WasmPreKey` | `id`, `public_key`, `record` (serialised full record) |
| `WasmSignedPreKey` | `id`, `public_key`, `signature`, `timestamp`, `record` (serialised full record) |
| `WasmKyberPreKey` | `id`, `public_key`, `signature`, `timestamp`, `record` (serialised full record) |
| `WasmCiphertext` | `message_type`, `body` |
| `WasmSafetyNumber` | `displayable` (string), `scannable` (bytes) |

### Utility Functions

| Function | Description |
|----------|-------------|
| `generate_random_bytes(length)` | Generate CSPRNG random bytes |
| `generate_uuid()` | Generate a UUID v4 |
| `uuid_to_string(bytes)` | Convert UUID bytes to string |
| `message_type_signal()` | Normal message type (2) |
| `message_type_pre_key()` | PreKey message type (3) |

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

## Testing

We use `wasm-bindgen-test` for headless browser integration testing.

```bash
# Run tests in Headless Chrome
wasm-pack test --headless --chrome

# Run tests in Headless Firefox
wasm-pack test --headless --firefox
```

## Licence

AGPL-3.0 - See [LICENSE](LICENSE)

This package is built on [libsignal](https://github.com/signalapp/libsignal) by Signal Technology Foundation.

## Disclaimer

This package is not affiliated with or endorsed by Signal Technology Foundation. Signal and the Signal Protocol are trademarks of Signal Technology Foundation.
