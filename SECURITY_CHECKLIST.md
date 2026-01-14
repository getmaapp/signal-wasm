# Security Audit Checklist

## 1. Rust & WebAssembly (WASM)

### Memory Safety & `unsafe`
- [ ] **No `unsafe` code**: Verify `#![deny(unsafe_code)]` is enabled in `lib.rs`.
- [ ] **Panic Handling**: Ensure `panic = "abort"` is set in `[profile.release]` to minimise binary size and stack trace leakage.
- [ ] **Panic Hooks**: Verify `console_error_panic_hook` is ONLY enabled in `#[cfg(debug_assertions)]` blocks to prevent leaking internal state to the console in production.
- [ ] **Integer Overflow**: Ensure `checked_add`, `checked_mul` etc. are used for all counter increments (e.g., `next_pre_key_id`).
- [ ] **Zeroize Memory**: Confirm `Zeroizing<T>` is used for all structs containing private keys or sensitive key material (e.g., `WasmIdentityKeyPair`).
    - *Note*: `Zeroizing` in WASM is "best effort" and does not guarantee clearing memory in the browser's JS engine once data crosses the boundary.

### WASM Boundary & Interop
- [ ] **Serialisation**: Validate all data deserialised from JavaScript (via `Vec<u8>`) using strictly typed parsers (e.g., `protobuf`).
- [ ] **ID Validation**: Verify all IDs (device IDs, pre-key IDs) passed from JS are within valid ranges (e.g., `u32::MAX`).
- [ ] **Error Leaks**: Ensure `to_js_error` returns generic error messages ("Operation failed") in release builds, rather than specific cryptographic failure details (to prevent oracle attacks).

## 2. Cryptography

### Randomness (CSPRNG)
- [ ] **Backend**: Confirm `getrandom` is compiled with the `js` feature to use the browser's `crypto.getRandomValues()`.
- [ ] **No User Input**: Ensure randomness is NEVER derived from user input or `Math.random()`.
- [ ] **Reseeding**: If using userspace RNGs (like `ChaCha20Rng`), ensure they are seeded from `OsRng` (Web Crypto) and not reused across long sessions without reseeding.

### Key Management
- [ ] **Ephemeral Keys**: Ensure One-Time PreKeys are deleted from storage immediately after use.
- [ ] **Storage Encryption**: While IndexedDB is per-origin, sensitive keys should ideally be wrapped/encrypted before storage if possible (though limited by browser capabilities without a separate enclave).
- [ ] **Key Rotation**: Verify Signed PreKeys are rotated periodically (recommended every 2 days - 1 week).

### Protocol Security
- [ ] **Algorithm Choice**: Confirm usage of `X3DH` (Curve25519) and `Double Ratchet`.
- [ ] **Post-Quantum**: Verify `Kyber1024` (PQXDH) inclusion for future-proofing.
- [ ] **Side-Channels**: Ensure cryptographic operations (like comparisons) use constant-time functions (`subtle` crate) where applicable.

## 3. Web & Application Security (OWASP)

### Context Isolation
- [ ] **Origin Isolation**: Ensure the app is served from a dedicated domain/subdomain to leverage Same-Origin Policy.
- [ ] **HTTPS Only**: The Encryption API (`crypto.subtle`) is only available in Secure Contexts (HTTPS). Enforce HSTS.

### Content Security Policy (CSP)
- [ ] **WASM Restrictions**: Use `script-src 'wasm-unsafe-eval'` (required for WASM) but disallow `'unsafe-inline'`.
- [ ] **Connect Restrictions**: Restrict `connect-src` to known signalling server endpoints.

### Supply Chain
- [ ] **Dependency Audit**: Run `cargo audit` and `npm audit` regularly.
- [ ] **Lockfiles**: Commit `Cargo.lock` and `package-lock.json`.
- [ ] **WASM Integrity**: If loading WASM from a CDN, use Subresource Integrity (SRI) tags.

## 4. Operational Security

- [ ] **Logs**: Verify **NO** sensitive data (keys, plaintext messages, PII) is ever logged to the console, even in debug mode.
- [ ] **Analytics**: Ensure analytics tools do not capture message content or key material.
