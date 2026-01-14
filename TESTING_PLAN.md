# Testing Plan for libsignal-wasm

This document outlines the testing strategy for the `libsignal-wasm` project. The primary focus is on validating the Rust-to-WASM bridge, ensuring that the Signal Protocol implementation is correctly exposed to and usable by JavaScript environments.

## 1. Testing Strategy

Since this library acts as a bridge between Rust and the Browser's JavaScript runtime, standard `cargo test` (which runs on the host OS) is insufficient. We primarily use **WASM Integration Tests**.

### 1.1 WASM Integration Tests (`wasm-bindgen-test`)
These tests run in a headless browser (Chrome or Firefox) via the `wasm-pack test` command. They simulate a real browser environment, allowing us to:
*   Access the Web Crypto API (`window.crypto.subtle`) for `getrandom`.
*   Verify the exact JS API exposed by `wasm-bindgen`.
*   Ensure memory safety across the WASM boundary.

## 2. Test Coverage

We will implement a suite of tests in `tests/web.rs` covering the following core functionalities:

### 2.1 Initialisation & Identity
*   **`client_creation`**: distinct UUIDs and device IDs.
*   **`identity_keys`**: validation of generated public/private key pairs.

### 2.2 Key Generation
*   **`pre_keys`**: Generation of batch PreKeys and validation of their structure.
*   **`signed_pre_keys`**: Generation and signature verification.
*   **`kyber_pre_keys`**: Generation of PQXDH keys and signature verification.

### 2.3 Session Establishment
*   **`x3dh_handshake`**: Complete flow of Alice building a session from Bob's bundle.
*   **`session_persistence`**: Exporting a session, re-importing it into a fresh client, and verifying connectivity.

### 2.4 Messaging
*   **`encrypt_decrypt`**: 1:1 message round-trip between Alice and Bob.
*   **`invalid_inputs`**: Handling of corrupt ciphertext or wrong IDs (expecting graceful JS errors, not panics).

### 2.5 Group Messaging
*   **`sender_keys`**: Distribution of Sender Keys and group encryption/decryption round-trip.

## 3. Running Tests

### Prerequisites
*   `wasm-pack`: `cargo install wasm-pack`
*   Browser Drivers:
    *   **Chrome**: `chromedriver` (for `--chrome`)
    *   **Firefox**: `geckodriver` (for `--firefox`)

### Command
Execute the test suite using `wasm-pack`:

```bash
# Run in Headless Chrome (Recommended)
wasm-pack test --headless --chrome

# Run in Headless Firefox
wasm-pack test --headless --firefox
```

## 4. Implementation Steps

1.  **Configure `Cargo.toml`**: Ensure `wasm-bindgen-test` is a dev-dependency.
2.  **Create `tests/web.rs`**: The main test file configured for WASM.
3.  **Implement Test Modules**:
    *   `test_identity()`
    *   `test_keys()`
    *   `test_session_and_messaging()`
    *   `test_group_messaging()`

## 5. CI Integration (Future)

For Continuous Integration, ensure the runner has:
1.  Rust toolchain (`rustup target add wasm32-unknown-unknown`).
2.  `wasm-pack`.
3.  Chrome/Firefox browsers installed.

```yaml
# Example GitHub Actions Step
- name: Run WASM Tests
  run: wasm-pack test --headless --chrome
```
