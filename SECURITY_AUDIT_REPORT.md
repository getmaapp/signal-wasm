# 🔐 Security Code Review & Audit Report

**Project:** @getmaapp/signal-wasm  
**Version:** 0.1.1  
**Date:** 2026-02-02  
**Scope:** `src/lib.rs`, `Cargo.toml`, dependencies, and WebAssembly bridge  

---

## Executive Summary

| Category | Status | Notes |
|----------|--------|-------|
| Memory Safety | ✅ PASS | `#![deny(unsafe_code)]` enforced |
| Cryptography | ✅ PASS | Signal Protocol v0.86.11, PQXDH (Kyber1024) |
| Error Handling | ✅ PASS | Generic errors in release builds |
| Input Validation | ⚠️ PARTIAL | Device ID validation, but UUID validation removed |
| Randomness | ✅ PASS | Web Crypto API via `getrandom` |
| Supply Chain | ⚠️ WARNING | `bincode` crate unmaintained (non-critical) |
| Secrets Management | ✅ PASS | `Zeroizing` used for private keys |

---

## 1. Rust & WebAssembly Security

### 1.1 Memory Safety

| Check | Status | Details |
|-------|--------|---------|
| `unsafe_code = "deny"` | ✅ | Enforced via `Cargo.toml` lints |
| Panic handling | ✅ | `panic = "abort"` in release profile |
| Panic hooks | ✅ | Only enabled in `debug_assertions` |

**Code Evidence:**
```rust
// src/lib.rs:15
#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]

// Cargo.toml:76-77
[profile.release]
panic = "abort"
```

**Finding:** The `console_error_panic_hook` is correctly guarded:
```rust
// src/lib.rs:86-91
#[cfg(debug_assertions)]
{
    console_error_panic_hook::set_once();
    web_sys::console::log_1(&"[Signal WASM] Module initialised (Debug Mode)".into());
}
```

### 1.2 Integer Overflow Protection

| Check | Status | Details |
|-------|--------|---------|
| PreKey ID increment | ✅ | `checked_add` with overflow error |
| Signed PreKey ID increment | ✅ | `checked_add` with overflow error |
| Kyber PreKey ID increment | ✅ | `checked_add` with overflow error |

**Code Evidence:**
```rust
// src/lib.rs:578-582
self.next_prekey_id = self
    .next_prekey_id
    .checked_add(1)
    .ok_or_else(|| JsValue::from_str("PreKey ID overflow"))?;
```

### 1.3 Zeroize / Memory Clearing

| Check | Status | Details |
|-------|--------|---------|
| Identity private key | ✅ | `Zeroizing<Vec<u8>>` |
| Exported keys | ⚠️ | Warning documented |

**Code Evidence:**
```rust
// src/lib.rs:145-165
pub struct WasmIdentityKeyPair {
    public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

/// # Security Warning
/// Once these bytes are returned to JavaScript, they are managed by the JS garbage collector...
#[wasm_bindgen(getter)]
pub fn private_key(&self) -> Vec<u8> {
    (*self.private_key).clone()
}
```

**Recommendation:** ✅ **ACCEPTABLE** - Warning clearly documents the JS GC limitation.

---

## 2. Cryptography

### 2.1 Randomness (CSPRNG)

| Check | Status | Details |
|-------|--------|---------|
| Backend | ✅ | `getrandom` with `js`/`wasm_js` features |
| Kyber key generation | ✅ | Uses `rand::rng()` (Web Crypto) |

**Code Evidence:**
```rust
// Cargo.toml:42-43
getrandom_v02 = { package = "getrandom", version = "0.2", features = ["js"] }
getrandom = { version = "0.3", features = ["wasm_js"] }
```

```rust
// src/lib.rs:656-657
let mut rng = rand::rng();
let key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
```

### 2.2 Key Management

| Check | Status | Details |
|-------|--------|---------|
| One-time PreKeys | ✅ | Deleted after use by libsignal |
| Signed PreKey rotation | ⚠️ | Up to caller |
| Kyber1024 (PQXDH) | ✅ | Signal production default |

**Note:** Key rotation is documented as the caller's responsibility (every 2 days - 1 week for Signed PreKeys).

### 2.3 Protocol Security

| Algorithm | Status | Purpose |
|-----------|--------|---------|
| X3DH | ✅ | Initial key agreement |
| Double Ratchet | ✅ | Session encryption |
| Kyber1024 | ✅ | Post-quantum PQXDH |
| Curve25519 | ✅ | ECDH |

---

## 3. Error Handling & Information Disclosure

### 3.1 Error Message Handling

| Check | Status | Details |
|-------|--------|---------|
| Generic errors (release) | ✅ | "Operation failed" |
| Detailed errors (debug) | ✅ | Full error with `#[cfg(debug_assertions)]` |

**Code Evidence:**
```rust
// src/lib.rs:105-115
fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    #[cfg(debug_assertions)]
    {
        JsValue::from_str(&format!("SignalError: {}", e))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = e;
        JsValue::from_str("SignalError: Operation failed")
    }
}
```

### 3.2 Input Validation

| Check | Status | Details |
|-------|--------|---------|
| Device ID validation | ✅ | Range 1-127 |
| UUID validation | ⚠️ | **REMOVED** - accepts arbitrary strings |
| Key length validation | ✅ | Via libsignal deserialization |

**Code Evidence:**
```rust
// src/lib.rs:117-119
fn make_device_id(id: u32) -> Result<DeviceId, JsValue> {
    DeviceId::try_from(id).map_err(|_| JsValue::from_str("Invalid device ID (must be 1-127)"))
}

// src/lib.rs:449-450
pub fn new(local_uuid: &str, local_device_id: u32) -> Result<SignalClient, JsValue> {
    // Validation removed to support Firebase UIDs and arbitrary strings
```

**Finding:** UUID validation was intentionally removed to support Firebase UIDs. This is a design decision but should be documented clearly.

---

## 4. Constant-Time Operations

| Check | Status | Details |
|-------|--------|---------|
| Safety number verification | ✅ | `subtle::ConstantTimeEq` |

**Code Evidence:**
```rust
// src/lib.rs:1015-1017
use subtle::ConstantTimeEq;
let valid = scanned.ct_eq(&expected.scannable);
Ok(valid.into())
```

---

## 5. Group Messaging Security (GV2)

| Check | Status | Details |
|-------|--------|---------|
| Group Master Key | ✅ | 32 random bytes |
| Deterministic UUID mapping | ✅ | UUID v5 for arbitrary strings |
| Secret Params derivation | ✅ | Uses zkgroup |

**Code Evidence:**
```rust
// src/lib.rs:305-308
pub fn generate() -> WasmGroupMasterKey {
    let mut bytes = [0u8; 32];
    let mut rng = rand::rng();
    rand::prelude::Rng::fill(&mut rng, &mut bytes);

// src/lib.rs:123-129
fn map_group_id(id: &str) -> uuid::Uuid {
    if let Ok(uuid) = uuid::Uuid::parse_str(id) {
        uuid
    } else {
        uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, id.as_bytes())
    }
}
```

---

## 6. Supply Chain Security

### 6.1 Dependency Audit

```
Crate:    bincode
Version:  1.3.3
Warning:  unmaintained
ID:       RUSTSEC-2025-0141
```

**Impact:** LOW - Used only by `zkgroup` for serialization. No known vulnerabilities, just unmaintained.

### 6.2 Core Dependencies

| Dependency | Version | Source | Status |
|------------|---------|--------|--------|
| libsignal-protocol | v0.86.11 | Signal official | ✅ |
| wasm-bindgen | 0.2 | crates.io | ✅ |
| getrandom | 0.2/0.3 | crates.io | ✅ |
| zeroize | 1.7 | crates.io | ✅ |
| subtle | 2.6 | crates.io | ✅ |

### 6.3 Git Dependencies

All libsignal crates are pinned to tag `v0.86.11`:
```toml
libsignal-protocol = { git = "https://github.com/signalapp/libsignal", tag = "v0.86.11" }
```

**Recommendation:** ✅ **ACCEPTABLE** - Pinned tags prevent supply chain attacks via branch moving.

---

## 7. Web Security Considerations

### 7.1 WASM-Specific

| Check | Status | Details |
|-------|--------|---------|
| No eval() | N/A | WASM doesn't use JS eval |
| CSP compatibility | ⚠️ | Requires `wasm-unsafe-eval` |

### 7.2 Browser Security

| Check | Status | Details |
|-------|--------|---------|
| Secure Context required | ⚠️ | crypto.subtle requires HTTPS |
| Origin isolation | ℹ️ | Deployment concern |

---

## 8. Identified Issues & Recommendations

### 8.1 Low Severity

| # | Issue | Recommendation |
|---|-------|----------------|
| 1 | `bincode` unmaintained | Monitor for migration path in `zkgroup` |
| 2 | No explicit key rotation API | Document rotation schedule for consumers |
| 3 | `log_to_console` function exists | Consider removing in release builds |

### 8.2 Informational

| # | Observation | Note |
|---|-------------|------|
| 1 | Registration ID uses rejection sampling | ✅ Unbiased random generation |
| 2 | `futures::executor::block_on` in async context | ℹ️ Necessary for WASM sync bridge |

---

## 9. Security Checklist Summary

### 9.1 From SECURITY_CHECKLIST.md

| Item | Status |
|------|--------|
| No unsafe code | ✅ |
| Panic = abort | ✅ |
| Panic hooks debug-only | ✅ |
| Integer overflow protection | ✅ |
| Zeroize for secrets | ✅ |
| getrandom with js feature | ✅ |
| Constant-time comparisons | ✅ |
| Generic errors in release | ✅ |
| Dependency audit | ✅ (1 warning) |

---

## 10. Final Assessment

| Category | Score | Remarks |
|----------|-------|---------|
| Code Quality | A | Clean, well-documented |
| Cryptographic Implementation | A | Follows Signal Protocol spec |
| Memory Safety | A+ | No unsafe code |
| Error Handling | A | Good separation of debug/release |
| Supply Chain | B+ | One unmaintained dep (non-critical) |
| **Overall** | **A** | **Production-ready with minor monitoring** |

---

## Appendix: Key Security Controls

### Critical Functions Reviewed

```rust
// ✅ Secure - uses checked_add
pub fn generate_pre_keys(&mut self, count: u32) -> Result<Array, JsValue>

// ✅ Secure - generic errors in release
fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue

// ✅ Secure - constant-time comparison
pub fn verify_safety_number(&self, scanned: Vec<u8>, ...) -> Result<bool, JsValue>

// ✅ Secure - rejection sampling for reg_id
pub fn new(local_uuid: &str, local_device_id: u32) -> Result<SignalClient, JsValue>
```

---

*This audit was conducted on 2026-02-02 against the signal-wasm codebase. For updates or questions, refer to the project repository and Signal Protocol specifications.*
