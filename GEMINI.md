# GEMINI.md - AI Agent Context

> **Target Audience**: AI Agents (Gemini, Claude, GPT, etc.) working on `@getmaapp/libsignal-wasm`.
> **Purpose**: Accelerate context loading and prevent regression of known WASM specific issues.

## 1. Project Identity
- **Name**: `libsignal-wasm`
- **Type**: Rust crate compiled to WebAssembly (WASM).
- **Goal**: Expose Signal Protocol (Double Ratchet, X3DH) to JavaScript/TypeScript (Browser).
- **Language Standard**: **British English** (e.g., `Initialisation`, `Serialisation`, `Programmed`, `Colour`).

## 2. Architecture & File Structure
- **`src/lib.rs`**: Monolithic bridge file. Contains all `#[wasm_bindgen]` exports.
    - **Wrappers**: Maps `libsignal` Rust types (e.g., `SessionRecord`) to WASM classes (e.g., `WasmSessionRecord`).
- **`tests/web.rs`**: Integration tests running in headless Chrome.
    - **Framework**: `wasm-bindgen-test`.
- **`signal-wasm-demo/`**: React 19 demo app and E2E test suite.
    - **Tests**: Playwright E2E tests in `tests/e2e.spec.ts`.
- **`Cargo.toml`**: Configures dependencies. Note `getrandom` conflicts (v0.2 vs v0.3) resolution.

## 3. Critical Technical Constraints (WASM)

### 3.1 Randomness (`OsRng`)
- **Issue**: `OsRng` usage panics in WASM.
- **Solution**: Use `rand::rng()` which we have configured to use `getrandom` with the `js` feature (Web Crypto API).
- **Rule**: NEVER use `OsRng` directly.

### 3.2 Time (`SystemTime`)
- **Issue**: `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`.
- **Solution**: Use `js_sys::Date::now()` and cast to `u64`.
- **Snippet**:
  ```rust
  let now = (js_sys::Date::now() as u64) / 1000; // Seconds since epoch
  ```

### 3.3 Async/Await
- **Context**: Many `libsignal` operations are strictly synchronous in Rust but exposed as `async` in WASM to simulate JS promises or heavy compute.
- **Rule**: In `tests/web.rs`, ALWAYS `await` methods like `encrypt_message`, `decrypt_message`, `export_session`, `import_session`.

### 3.4 API Signatures
- **`export_session`** return type: `Result<Option<Vec<u8>>, JsValue>`.
    - **Mistake**: Treating it as `Result<Vec<u8>>`.
    - **Fix**: Unwrap the inner `Option`, usually `.expect("Session not found")`.

## 4. Testing Protocols

### Running Tests
All tests must pass in a headless browser environment:
```bash
wasm-pack test --headless --chrome
```

### Running E2E Tests (Demo App)
Verify full application integration using Playwright:
```bash
cd signal-wasm-demo
npx playwright test
```

### Coverage Status (as of Jan 2026)
- **Core Messaging**: 100% (Keys, Session, Encryption).
- **Persistence**: 100% (Export/Import/Restore verified).
- **Safety Numbers**: 100% (Displayable fingerprint matching).
- **Reference**: See `COVERAGE_REPORT.md`.

## 5. Development Rules
1. **Safety**: `#![deny(unsafe_code)]` is strictly enforced.
2. **Panics**: Allowed in `tests/` but forbidden in `src/lib.rs` runtime paths (use `Result<T, JsValue>`).
3. **Dependencies**: Do not introduce dependencies that require C bindings or system libraries not available in WASM.

## 6. Common Tasks
- **Adding a new wrapping Type**:
    1. Define struct `struct WasmNewType(InnerType);`
    2. Implement `#[wasm_bindgen]` methods calling `self.0.inner_method()`.
    3. Add `to_js_error` mapping.
    4. **Test** in `tests/web.rs`.
