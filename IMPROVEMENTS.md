# Signal-Wasm Improvement Tracking

This document tracks potential improvements to the signal-wasm library that would enhance error handling, debugging, or API ergonomics.

## Error Taxonomy Improvements

### IMP-001: Distinguish `SignatureValidationFailed` errors

**Current Behavior:**

All libsignal errors are converted to generic strings via `to_js_error`:

```rust
fn to_js_error<E: std::fmt::Display>(e: E) -> JsValue {
    #[cfg(debug_assertions)]
    {
        JsValue::from_str(&format!("SignalError: {}", e))
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = e; // Suppress unused warning
        JsValue::from_str("SignalError: Operation failed")
    }
}
```

This means `SignalProtocolError::SignatureValidationFailed` (from PQXDH signature verification) is indistinguishable from other errors like network issues or invalid keys.

**Desired Behavior:**

Distinguish signature validation failures so callers can:
1. Return specific error types (e.g., `InvalidPreKeyBundleError`)
2. Log security-relevant events differently
3. Provide better user feedback

**Implementation Options:**

**Option A: Error Code Prefix**

```rust
pub async fn process_pre_key_bundle(...) -> Result<(), JsValue> {
    // ... 
    match process_prekey_bundle(...).await {
        Ok(_) => Ok(()),
        Err(SignalProtocolError::SignatureValidationFailed) => {
            Err(JsValue::from_str("SignalError: SignatureValidationFailed"))
        }
        Err(e) => Err(to_js_error(e)),
    }
}
```

**Option B: Structured Error Objects**

```rust
#[wasm_bindgen]
pub struct SignalError {
    code: String,
    message: String,
}

#[wasm_bindgen]
impl SignalError {
    #[wasm_bindgen(getter)]
    pub fn code(&self) -> String { self.code.clone() }
    
    #[wasm_bindgen(getter)]
    pub fn message(&self) -> String { self.message.clone() }
}
```

**Option C: Specific Method for Signature Verification**

Expose a standalone method that returns boolean or specific error:

```rust
#[wasm_bindgen]
pub fn verify_prekey_bundle_signatures(
    identity_key: &[u8],
    signed_prekey: &[u8],
    signed_prekey_signature: &[u8],
    kyber_prekey: &[u8],
    kyber_prekey_signature: &[u8],
) -> Result<bool, JsValue> {
    // ... verify signatures explicitly
}
```

**Priority:** Medium  
**Security Relevance:** HIGH - Signature validation is critical for PQXDH security  
**Breaking Change:** Option A (no), Option B (yes - changes error type), Option C (no - additive)

**References:**
- libsignal: `rust/protocol/src/session.rs:191-202` (signature verification in `process_prekey_bundle`)
- PQXDH spec: https://signal.org/docs/specifications/pqxdh/#key-agreement
