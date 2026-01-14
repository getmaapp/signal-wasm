# Contributing to @getmaapp/signal-wasm

Welcome! We appreciate your interest in contributing to `@getmaapp/signal-wasm`. This document outlines the standards and behaviours expected for this project.

## 1. Language & Spelling

**Strict Rule**: All documentation, code comments, commit messages, and variable names (where typical for the domain) must use **British English**.

- **Correct**: `initialise`, `serialise`, `colour`, `behaviour`, `optimise`, `licence` (noun), `signalling`.
- **Incorrect**: `initialize`, `serialize`, `color`, `behavior`, `optimize`, `license` (noun), `signaling`.

*Tip*: If your IDE supports spell-checking, please configure it to `en-GB`.

## 2. Rust Development Guidelines

### Safety First
- **No Unsafe Code**: The `#![deny(unsafe_code)]` lint is enforced globally. Do not disable it.
- **Panic Strategy**:
    - **Production**: Panics must strictly `abort` to minimise binary size and prevent information leakage.
    - **handling**: Use `Result<T, JsValue>` for all failable WASM operations. Never `unwrap()` or `expect()` on runtime paths that could be triggered by external input.

### WASM API Design
- **Naming Convention**:
    - Exported methods: `snake_case` (e.g., `generate_pre_keys`, `export_session`).
    - Exported structs: `PascalCase` (e.g., `WasmIdentityKeyPair`).
    - Naming consistency: Use `pre_key` (two words) instead of `prekey`, matching the Rust crate's internal style where applicable, but ensuring the exposed API uses underscores (e.g., `message_type_pre_key`).
- **Memory Management**:
    - Use `Zeroizing<T>` for all secrets.
    - Be explicitly aware that `Zeroizing` does **not** protect data once it is returned to JavaScript (V8/SpiderMonkey memory managers take over). Document this caveat on any method returning sensitive bytes.

### Error Handling
- Use the `to_js_error` helper to convert internal Rust errors into `JsValue`.
- In `release` builds, ensure error messages are generic ("Operation failed") to prevent Oracle attacks. Detailed errors are permitted only in `debug` builds.

## 3. Demo Application (TypeScript/React)

- **Strict Typing**: No usage of `any`. Define interfaces for all stored data structures.
- **Async/Await**: Prefer `async/await` patterns over `.then()` chains.
- **Persistence**: Usage of `IndexedDB` is manual. Ensure all migrations are defined declaratively in the `MIGRATIONS` array in `storage.ts`.

## 4. Security

Before submitting code, you **must** review the [Security Checklist](./SECURITY_CHECKLIST.md).
- Ensure no keys are logged to the console.
- Ensure randomness is solely derived from `crypto.getRandomValues()` (via `getrandom` crate with `js` feature).

## 5. Workflow

### Commit Messages
Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes (remember: British English!)
- `refactor`: A code change that neither fixes a bug nor adds a feature

### Pull Requests
1. Ensure `wasm-pack test --headless --firefox --chrome` passes.
2. Ensure the demo app builds via `npm run build`.
3. Update `README.md` and `SECURITY_AUDIT_REPORT.md` if your changes affect the public API or security posture.

Thank you for helping us maintain a high-quality, secure library!
