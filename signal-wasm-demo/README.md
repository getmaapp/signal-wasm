# Signal WASM Demo App

A React 19 / Vite application demonstrating the capabilities of `@thecannabisapp/libsignal-wasm`.

## Features Demonstrated

- 🔑 **Identity Management**: Generation and persistence of Signal identity keys.
- 📦 **Key Generation**: 1:1 PreKeys, Signed PreKeys, and Post-Quantum Kyber PreKeys.
- 🤝 **Session Establishment**: Full X3DH/PQXDH handshake (simulated).
- 💬 **1:1 Messaging**: Encrypting and decrypting messages using the Signal Double Ratchet.
- 👨‍👩‍👧‍👦 **Group Messaging**: Sender Key based group encryption.
- 🛡️ **Post-Quantum Crypto**: Integration of Kyber1024 for quantum-resistant handshakes.
- 💾 **Persistence**: full state restoration from IndexedDB via `SignalClient.restore()`.
- 🚥 **Activity Log**: Real-time visualisation of internal cryptographic operations.

## Architecture

- **React 19**: Modern UI with `useEffect` and `useState` for state management.
- **WASM Bridge**: Direct integration with the `@thecannabisapp/libsignal-wasm` package.
- **IndexedDB**: Persistent storage via the `idb` library with automated schema migrations.
- **Vite**: Ultra-fast build tool with WASM support.

## Getting Started

### Prerequisites

- Node.js (v18+)
- Local build of `libsignal-wasm` (run `wasm-pack build` in the parent directory)

### Installation

```bash
npm install
```

### Running the Demo

```bash
npm run dev
```

The app will be available at `http://localhost:5173`.
 
 ## Testing (E2E)
 
 We use **Playwright** to verify the full application lifecycle, from bundle loading to message decryption.
 
 ```bash
 # Run E2E tests (headless)
 npx playwright test
 
 # Open interactive test UI
 npx playwright test --ui
 ```

## How it Works

1. **Initialisation**: Load the WASM module and initialise/upgrade the IndexedDB.
2. **Client Creation**: Alice and Bob clients are restored from IDB (or created fresh).
3. **Key Generation**: Clients generate cryptographic "bundles" (PreKeys) for server upload.
4. **Messaging**: Alice fetches Bob's bundle, establishes a session, and sends encrypted payloads.

---

*Note: This is a demonstration app. In a production environment, you would use a server (e.g., via tRPC or WebSockets) to synchronise key bundles and exchange ciphertext messages between clients.*
