# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.5] - 2026-08-16

### Fixed
- `WasmInMemKyberPreKeyStore.remove_kyber_pre_key(id)` now also prunes the
  evicted key's anti-replay entries from the exported usage set, matching
  canonical one-time-key deletion semantics. Canonical clients delete a
  consumed one-time Kyber pre-key and record no `(kyber_id,
  signed_prekey_id, base_key)` triple for it (Signal-iOS
  `SignalServiceKit/Axolotl/PreKeyStore.swift:199-225` @ 58cc49ec1;
  Signal-Desktop `ts/SignalProtocolStore.preload.ts:536-570` @ de8fe1e70;
  libsignal trait contract `rust/protocol/src/storage/traits.rs:116-138` @
  b5121d0). A triple for an evicted key is dead weight because a replay fails
  at `get_kyber_pre_key` (`InvalidKyberPreKeyId`) before the base-key check is
  ever reached; last-resort records must still not be evicted here so their
  triples persist.

## [0.6.4] - 2026-08-15

### Added
- `WasmInMemKyberPreKeyStore.remove_kyber_pre_key(id) -> boolean`: evicts a
  Kyber pre-key record from the in-memory store. Canonical clients delete a
  one-time Kyber pre-key the moment it is consumed
  (`KyberPreKeyStore::mark_kyber_pre_key_used` contract,
  `rust/protocol/src/storage/traits.rs:119-136`; Signal-iOS removes the row
  when `preKey.isOneTime`, `PreKeyStore.swift:199-225`); the trait leaves the
  deletion to the caller, and this primitive is how callers honour it. Until
  now a consumed one-time KEM secret stayed decapsulable in-memory until
  process exit. Last-resort records must not be evicted — their replay guard
  is the exported usage set. Idempotent; returns whether a record was present.

## [0.6.3] - 2026-08-15

### Notes
- Repackage of 0.6.2 with the complete build: the first 0.6.2 tarball was
  built from a stale `pkg/` and shipped without
  `session_remote_registration_id` and the documentation cleanup. 0.6.2 was
  unpublished; npm does not permit reusing an unpublished version, so the
  full content ships as 0.6.3. No source changes beyond the version bump.

## [0.6.2] - 2026-08-15

### Added
- **`InMemSessionStore.delete_session(address)`**: remove the in-memory session
  record for an address entirely. Canonical libsignal's `SessionStore` trait
  has no deletion operation (`rust/protocol/src/storage/traits.rs:150-160` @
  `b5121d0`), so the wrapper implements the public trait over its own map and
  exposes removal at the bridge. Returns `true` when a record was actually
  removed.
- **`InMemSessionStore.session_remote_registration_id(address)`**: read the
  remote registration id from the active session state. Returns `None` when no
  record exists or the record has no current state (e.g. after
  `archive_session`). Canonical Signal-Desktop sends this value in fan-out
  metadata (`ts/textsecure/OutgoingMessage.preload.ts:537` @ `de8fe1e70`) so
  Signal-Server's stale-registration check (`MessageSender.java:402-417` @
  `5eb1a76e9`) can force a session refresh when the recipient re-registers.

### Why
- Consumers with JS-mediated durable storage need a no-prior-session rollback
  path: after a first-contact decrypt/encrypt creates a session in the engine
  but the durable save fails, the engine state is ahead of storage. Deleting
  the wrapper-owned record lets the retry reprocess the PreKey ciphertext as a
  first-contact message. `archive_session` is not a substitute — it keeps the
  record live and rotates the ratchet state into the record's previous-states
  list so straggler messages still decrypt.

### Consumer impact
- Consumers can now call `delete_session(address)` with the same
  `(name, deviceId)` shape as `archive_session`. The return value is `true` if
  a record existed and was removed, `false` if no record existed. No breaking
  changes.

## [0.6.1] - 2026-08-14

### Security
- **`WasmGroupMasterKey` / `WasmGroupSecretParams` no longer retain an
  un-zeroisable upstream copy of the group secret.** Upstream
  `GroupMasterKey` and `GroupSecretParams` are `Copy` types with no
  `Zeroize` implementation
  (`rust/zkgroup/src/api/groups/group_params.rs:21-28`), so the
  previous wrapper stored a duplicate secret alongside the `Zeroizing`
  bytes and only zeroised the duplicate. The wrapper now keeps only the
  `Zeroizing<[u8; 32]>` master-key bytes and derives the upstream value on
  demand, dropping it immediately after use. This trades a small amount of
  repeated KDF work for a real reduction in secret retention.

### Added
- **Stable error codes for canonical protocol variants:**
  `SignatureValidationFailed`, `SessionNotFound`, `InvalidRegistrationId`
  (`libsignal` `error.rs:48-78`). These join the existing
  `NoSenderKeyState`, `DuplicatedMessage`, `UntrustedIdentity`,
  `InvalidKyberPreKeyId`, `InvalidPreKeyId`, `InvalidSignedPreKeyId`, and
  `ReusedKyberBaseKey` codes that callers already predicate on.

### Changed
- **Release builds now flatten wrapper-raised validation messages.**
  `validation_error` previously echoed caller-supplied strings (e.g.
  distribution-id values) even in release, matching the same flattening
  policy already applied to libsignal errors. Debug builds still include
  the detailed message.
- **`processPreKeyBundle` rejects a mismatched one-time prekey pair.**
  Passing `prekey_id` without `prekey`, or `prekey` without `prekey_id`,
  now returns a validation error instead of being silently coerced to
  `None`. A `None/None` pair remains valid (PQXDH signed-prekey-only
  fallback).

## [0.6.0] - 2026-08-12

PQXDH hardening: consumed one-time pre-key surfacing and durable kyber
anti-replay memory. Both are parity with Signal's own clients, not extra
caution — the `KyberPreKeyStore` trait contract (`libsignal
rust/protocol/src/storage/traits.rs:129-133`) requires clients to delete consumed
one-time keys and to reject reused `(kyber, signed prekey, base key)` triples,
and Signal-iOS / Signal-Desktop / Signal-Android all persist that state in
their databases. libsignal remains pinned to `main` @
[`b5121d0`](https://github.com/signalapp/libsignal/commit/b5121d07c72f9e631f178d907ca892587f64f9e2) — no vendored code changed.

### Added
- **`decryptMessage` now reports consumed one-time pre-key ids.** The engine
  learns exactly which keys a prekey-message decrypt consumed (`pre_key_used`
  in `rust/protocol/src/session_management.rs`) but upstream returns only the
  plaintext; with JS-mediated durability the TS layer could never tombstone
  them, so a consumed one-time kyber record was re-imported on next hydration
  and its KEM private key resurrected across restarts. The wrapper-owned
  stores now capture the engine's own store callbacks — the same call sites
  Signal's clients persist from — and the ids cross the boundary.
- **`InMemKyberPreKeyStore.export_kyber_usage()` / `import_kyber_usage(bytes)`**:
  durable kyber anti-replay memory. Upstream `InMemKyberPreKeyStore` keeps
  `base_keys_seen` private (`inmem.rs:203`), so the replay guard evaporated on
  every reload: a replayed PreKeySignalMessage against a live last-resort key
  decapsulated again after a restart. The set now exports for IndexedDB
  persistence (version byte `1`, u32 BE count, then per record
  `kyberId u32 BE ‖ signedPreKeyId u32 BE ‖ 33-byte base key`). Import is
  union-with-dedup and validates every byte — unknown version, length
  mismatch, or an invalid base key is a hard error, never a silent drop.
- New error code **`ReusedKyberBaseKey`** for kyber replay rejections. The
  matched detail string is wrapper-owned (the store constructs it), so this is
  the one sanctioned exception to the "codes match on type, never on message"
  rule; it lets callers distinguish replay rejection in release builds where
  messages are flattened.

### Changed
- **BREAKING (minor)**: `decryptMessage` now returns **`WasmDecryptResult`**
  instead of `Uint8Array`. Getters: `plaintext: Uint8Array`,
  `kyberPreKeyId?: number`, `oneTimePreKeyId?: number`,
  `signedPreKeyId?: number`. All id fields are `undefined` for Whisper
  (non-prekey) decrypts and for prekey messages that decrypted against an
  existing session. Migration: `const pt = await decryptMessage(...)` →
  `const { plaintext } = await decryptMessage(...)`, then tombstone any
  reported ids in your durable store.
- `WasmInMemPreKeyStore` and `WasmInMemKyberPreKeyStore` are now backed by
  wrapper-owned store implementations (the 0.4.0 `RemovableSenderKeyStore`
  precedent) instead of upstream's InMem stores. The JS API is unchanged; the
  engine-visible behaviour is byte-identical to upstream InMem (same
  not-found sentinels, same "reused base key" replay check). Under concurrent
  decrypts sharing one store set, `WasmDecryptResult` may report a superset of
  the caller's own consumed ids — every reported id was genuinely consumed, so
  tombstoning it is always safe.

### Notes
- Same-process replay of a prekey message is still caught by ratchet replay
  detection (`DuplicatedMessage`): the engine promotes the existing session
  for that base key and never reaches the kyber mark. `ReusedKyberBaseKey`
  fires exactly where `DuplicatedMessage` cannot reach — after a restart or
  session reset with a live last-resort key.
- Bridged clients need a matching native surface for both items (e.g. a Swift
  bridge on iOS); that is downstream consumer work, not part of this engine
  release.

## [0.5.0] - 2026-07-25

This release: canonical cross-perspective
safety-number verification, identity proof-of-possession, and a hygiene
sweep. libsignal remains pinned to `main` @
[`b5121d0`](https://github.com/signalapp/libsignal/commit/b5121d07c72f9e631f178d907ca892587f64f9e2) — no vendored code changed.

### Added
- **`verifyScannableFingerprint(scanned, localUuid, localIdentityKey, contactUuid, contactIdentityKey)`**:
  the web half of fixing safety-number verification. Uses the canonical
  `ScannableFingerprint::compare` semantics (libsignal
  `rust/protocol/src/fingerprint.rs`): decodes the scanned CombinedFingerprints,
  enforces version equality, and requires their.local == our.remote AND
  their.remote == our.local, in constant time. The old `verifySafetyNumber`
  recomputed OUR OWN fingerprint and byte-compared, so it could never validate
  a cross-perspective scan (the scanned QR encodes the OTHER party's
  fingerprints with local/remote swapped).
  - New error codes: **`FingerprintVersionMismatch`** (their version ≠ ours)
    and **`FingerprintParsingError`** (undecodable/malformed scanned payload).
- **`signWithIdentityKey(identityPrivateKey, message)` → `Uint8Array`** and
  **`verifyIdentitySignature(identityPublicKey, message, signature)` → `boolean`**:
  identity proof-of-possession (XEdDSA over the X25519 identity key, canonical
  `PrivateKey::calculate_signature` / `PublicKey::verify_signature`), for
  server-verifiable re-key authorisation. Verification is constant-time and
  returns `false` (never throws) for wrong key/message or malformed signature.
- New error codes **`InvalidPreKeyId`** and **`InvalidSignedPreKeyId`**
  (previously folded into `Generic`).
- Zeroization: the previously declared-but-unused `zeroize` dependency
  is now real. Serialized PreKey/SignedPreKey/KyberPreKey records (which
  contain the private half) and the group master-key bytes in
  `WasmGroupMasterKey` / `WasmGroupSecretParams` are held in
  `zeroize::Zeroizing` and overwritten on drop. Honest limits, documented in
  the README: the libsignal identity `PrivateKey` is an upstream `Copy` type
  that is not zeroed, and any bytes exported to JS are GC-managed copies that
  cannot be erased from Rust.

### Changed
- **BREAKING (minor)**: `WasmGroupSecretParams.serialize` is renamed to
  **`serialize_master_key`**. It always returned the 32-byte master key,
  not the 289-byte group params encoding; the explicit name stops future
  callers grabbing the wrong thing. The getter was unreferenced downstream.
- **BREAKING (minor)**: `log_to_console` is no longer exported from release
  builds — it is now gated behind `#[cfg(debug_assertions)]`.
- `has_session` and the `export_pre_key` / `export_signed_pre_key` /
  `export_kyber_pre_key` stores no longer swallow store errors as
  falsey/`None`. Only the canonical not-found sentinel
  (`InvalidPreKeyId` / `InvalidSignedPreKeyId` / `InvalidKyberPreKeyId`) maps
  to `None`; any other store error is surfaced as a typed JS `Error`.
- `verifySafetyNumber` is deprecated (doc comment) in favour of
  `verifyScannableFingerprint`; kept for API compatibility.

### Removed
- Unused direct dependencies `libsignal-core`, `signal-crypto`, and
  `zkcredential`. They remain in the tree transitively via
  `libsignal-protocol` / `zkgroup`, so feature unification is unaffected;
  verified with `cargo check --all-targets`.

### Notes
- Release builds keep `panic = "abort"` (correct for wasm: no unwinding across
  the boundary). README now documents that a Rust panic permanently bricks the
  instance and surfaces as the flattened `SignalError: Operation failed`;
  `console_error_panic_hook` remains
  registered at init in debug builds.

## [0.4.0] - 2026-07-17

Security hardening release. libsignal remains
pinned to `main` @ [`b5121d0`](https://github.com/signalapp/libsignal/commit/b5121d07c72f9e631f178d907ca892587f64f9e2) — no vendored code changed.

### Removed
- **BREAKING**: The internal `map_group_id` derivation (UUIDv5 hash of arbitrary
  group strings) is gone, with **no fallback**. Distribution ids were keyed in a
  second, incompatible namespace while callers minted their own UUIDs, so
  exports/hydration/decrypt could never line up. All
  `distributionId` parameters must now be **caller-minted UUID strings**;
  anything else is rejected with a `Generic`-coded validation error. Affected
  bindings (signatures unchanged, semantics tightened):
  - `createSenderKeyDistribution(localAddress, distributionId, senderKeyStore)`
  - `encryptGroupMessage(localAddress, distributionId, plaintext, senderKeyStore)`
  - `InMemSenderKeyStore.export_sender_key(address, distributionId)`
  - `InMemSenderKeyStore.import_sender_key(address, distributionId, bytes)`
  - `processSenderKeyDistribution` and `decryptGroupMessage` never derived an
    id (it is read from the SKDM / embedded in the ciphertext respectively) and
    are unchanged.
- **BREAKING (minor)**: Thrown errors are now real JS `Error` objects instead of
  bare strings. `err.message` is byte-identical to the old string, but
  `String(err)` now yields `"Error: SignalError: …"` (standard `Error`
  stringification). Catch sites reading `.message` are unaffected; catch sites
  doing `String(err)` will see the `"Error: "` prefix.
- Dropped the `uuid` crate's `v5` feature and the `hex` dev-dependency (both
  were only used by `map_group_id` / its test).

### Added
- **`remove_sender_key(address, distributionId)`** on `InMemSenderKeyStore`:
  deletes the sender-key record for `(address, distributionId)`,
  returning `true` when a record was actually removed. Rotation must delete the
  record before re-creating the distribution — otherwise
  `createSenderKeyDistribution` reuses the existing chain and removed group
  members keep deriving future message keys (canonical clients do the same:
  Signal-Desktop `sendToGroup.preload.ts:865-868`). Deletion is provable via
  `export_sender_key` returning `None` afterwards; covered by tests.
- **Structured error codes**: every thrown error carries a stable
  own `code` property, matched on the libsignal error **type** (never the
  message string) so it survives release-build message flattening:
  `NoSenderKeyState`, `DuplicatedMessage`, `UntrustedIdentity`,
  `InvalidKyberPreKeyId`, and `Generic` for everything else (including
  wrapper-side validation failures). The `message` string itself is unchanged:
  detailed in debug builds, flattened to `"SignalError: Operation failed"` in
  release builds.

### Changed
- `WasmInMemSenderKeyStore` is now backed by the wrapper's own `SenderKeyStore`
  trait implementation over a `HashMap` (`RemovableSenderKeyStore`) instead of
  upstream's `InMemSenderKeyStore`, whose map is private and offers no removal
  API (`rust/protocol/src/storage/inmem.rs:330`; the trait itself is only
  `store_sender_key` + `load_sender_key`, `rust/protocol/src/storage/traits.rs:164`).
  Behaviour of store/load is identical to upstream (same `Cow`-keyed map).
- New internal dependency: `async-trait` 0.1 (same version libsignal pins).

### Tests
- Group round-trip with a caller-minted distribution id:
  create → export → fresh store → import → encrypt on one store / decrypt on
  the other.
- Decrypt with the wrong distribution id fails with `NoSenderKeyState`.
- Decrypt on a store that never saw the SKDM fails with `NoSenderKeyState`.
- `remove_sender_key` → export returns `None`; remove + re-create produces
  **different** key material; the rotated distribution still round-trips.
- Non-UUID distribution ids are rejected (`Generic` code).
- All 17 tests pass under `wasm-pack test --headless --chrome`; `cargo clippy
  --target wasm32-unknown-unknown` is clean.

## [0.3.0] - 2026-07-17

### Changed
- **libsignal**: Updated all five libsignal dependencies (`libsignal-protocol`, `libsignal-core`, `signal-crypto`, `zkgroup`, `zkcredential`) from tag `v0.93.1` to `main` @ [`b5121d0`](https://github.com/signalapp/libsignal/commit/b5121d07c72f9e631f178d907ca892587f64f9e2) (2026-07-16, upstream workspace version 0.97.4).
  - Covers ~60 upstream commits, including the session/state/storage refactor (`rust/protocol/src/session.rs` still exists and contains `PreKeysUsed`; parts also moved to `session_management.rs`, `state/`, and `storage/`), dynamic `InvalidMessage` error descriptions, removal of `SignalMessage.verifyMac`, the ML-KEM parameter key-type fix, and SPQR integration.
  - New transitive dependency: `spqr` v1.5.1 (Sparse Post-Quantum Ratchet), pulled in by `libsignal-protocol`.
  - **No changes to `src/lib.rs` were required** — every libsignal API used by the wrapper remained source-compatible, and the public JavaScript/WASM API is unchanged.
- **Dependencies**: Bumped all crates within semver-compatible ranges (`cargo update`), notably `wasm-bindgen` 0.2.106 → 0.2.126, `uuid` 1.19 → 1.24, `zeroize` 1.8 → 1.9, `prost` 0.14.3 → 0.14.4, `rand` 0.9.4 → 0.9.5.

### Notes
- The getrandom "diamond dependency" (v0.2 + v0.3) is **still required** after the update: `getrandom` 0.2 (feature `js`) is pulled in by `rand_core` 0.6 consumers (`curve25519-dalek` 4.1.3, `x25519-dalek`, `password-hash`, `aes-gcm-siv` 0.11.1 via `crypto-common`), while `getrandom` 0.3 (feature `wasm_js`) serves `rand` 0.9 users (`libsignal-core`, `uuid`). Both pins remain in `Cargo.toml`.
- Verified with `cargo build` (host), `cargo build --target wasm32-unknown-unknown --release`, `cargo clippy --target wasm32-unknown-unknown` (no new warnings), and `wasm-pack test --headless --chrome` (all tests passing).

## [0.2.0] - 2026-05-03

### Removed
- **BREAKING**: Removed `SignalClient` entirely. There is no monolithic client object anymore.

### Added
- **Granular Crypto Primitives**: Exported `PrivateKey`, `PublicKey`, and `IdentityKeyPair` as standalone types.
  - `PrivateKey.generate()` — generates a new private key (no device ID required).
  - `PrivateKey.getPublicKey()` — derives the corresponding public key.
  - `IdentityKeyPair` constructor takes `(PublicKey, PrivateKey)`.
- **Protocol Address**: Exported `ProtocolAddress` as a standalone type. Device IDs are now scoped **only** to addressing.
- **Individual Stores**: Exported first-class store types:
  - `InMemIdentityKeyStore`
  - `InMemSessionStore`
  - `InMemPreKeyStore`
  - `InMemSignedPreKeyStore`
  - `InMemKyberPreKeyStore`
  - `InMemSenderKeyStore`
  - Each store supports import/export methods for IndexedDB persistence.
- **Standalone Protocol Operations**: All messaging operations are now standalone async functions:
  - `processPreKeyBundle()`
  - `encryptMessage()`
  - `decryptMessage()`
  - `createSenderKeyDistribution()` / `processSenderKeyDistribution()`
  - `encryptGroupMessage()` / `decryptGroupMessage()`
  - `generateSafetyNumber()` / `verifySafetyNumber()`
- **Standalone Key Generation**:
  - `generatePreKeys(startId, count, prekeyStore)` → `Promise<WasmPreKey[]>`
  - `generateSignedPreKey(keyId, identityKeyPair, signedPrekeyStore)` → `Promise<WasmSignedPreKey>`
  - `generateKyberPreKey(keyId, identityKeyPair, kyberPrekeyStore)` → `Promise<WasmKyberPreKey>`
  - `generateRegistrationId()`

### Changed
- **Identity generation no longer requires a device ID**. This eliminates the temp-device-ID problem at the architectural level.
- Store counters (`nextPreKeyId`, `nextSignedPreKeyId`, `nextKyberPreKeyId`) are now managed by the consumer, not an internal client state.
- **Async key generation**: `generatePreKeys`, `generateSignedPreKey`, and `generateKyberPreKey` are now `async` (return `Promise`).
- **libsignal v0.93.1**: Updated all libsignal dependencies from v0.92.0 to v0.93.1.
- **Safety numbers**: `generateSafetyNumber` now accepts any string identifier (Firebase UIDs, usernames, UUIDs).
- **PreKey ID wrapping**: IDs now wrap at 24 bits (`0x00FF_FFFF`) to match Signal behaviour.
- Demo app (`signal-wasm-demo`) rewritten to use the new granular API.
- All tests rewritten to use the new granular API.

### Security
- Replaced hardcoded `CiphertextMessageType` magic numbers (`2`, `3`, `7`) with upstream enum constants.
- Added `MAX_PREKEY_BATCH_SIZE` limit (500) and `MAX_RANDOM_BYTES_LENGTH` limit (1 MiB).
- Removed `futures::executor::block_on` from synchronous WASM functions — now fully async.
- Constants for fingerprint version (`2`) and iterations (`5200`) are now explicit rather than inline literals.

### Migration
```typescript
// Before (monolithic SignalClient)
const client = new SignalClient(uuid, deviceId);
const keyPair = client.get_identity_key_pair();
client.generate_pre_keys(100);
const ciphertext = await client.encrypt_message(recipientUuid, recipientDeviceId, plaintext);

// After (granular libsignal-style API)
const privateKey = PrivateKey.generate();
const publicKey = privateKey.getPublicKey();
const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
const registrationId = generateRegistrationId();
const identityStore = new InMemIdentityKeyStore(identityKeyPair, registrationId);
const sessionStore = new InMemSessionStore();
const localAddress = new ProtocolAddress(uuid, deviceId);
const recipientAddress = new ProtocolAddress(recipientUuid, recipientDeviceId);
const preKeys = await generatePreKeys(1, 100, prekeyStore);
const ciphertext = await encryptMessage(plaintext, recipientAddress, localAddress, sessionStore, identityStore);
```

## [0.1.2] - 2026-04-09

### Security
- Updated libsignal from v0.86.11 to v0.92.0, incorporating security enhancements including MAC sender ID verification for replay attack prevention
- SPQR v1 is now enforced for all newly initiated sessions, ensuring post-quantum security

### Changed
- **Internal**: Updated `message_encrypt` calls to include `local_address` parameter for recipient verification (required by libsignal v0.92.0)
- **Internal**: Updated `message_decrypt` calls to include `local_address` parameter for recipient verification (required by libsignal v0.92.0)
- Updated all libsignal dependencies to v0.92.0:
  - `libsignal-protocol`
  - `libsignal-core`
  - `signal-crypto`
  - `zkgroup`
  - `zkcredential`

### Notes
- No breaking changes to the public JavaScript/WASM API
- Fully backward compatible with messages from older clients

## [0.1.1] - 2026-01-28

### Added
- Support for Firebase UIDs and arbitrary strings as client IDs
- Deterministic Group UUID mapping for Stream Chat integration
- GV2 Private Group support (`WasmGroupMasterKey`, `WasmGroupIdentifier`, `WasmGroupSecretParams`)

### Changed
- Renamed package to `@getmaapp/signal-wasm`
- Updated package metadata and documentation

## [0.1.0] - 2026-01-14

### Added
- Initial release of signal-wasm
- Signal Protocol implementation compiled to WebAssembly
- X3DH key agreement protocol
- Double Ratchet messaging protocol
- Post-quantum Kyber1024 (PQXDH) support
- Group messaging via Sender Keys (GV1)
- Safety number generation and verification
- State persistence for IndexedDB
- Complete TypeScript definitions

[Unreleased]: https://github.com/getmaapp/signal-wasm/compare/v0.6.2...HEAD
[0.6.0]: https://github.com/getmaapp/signal-wasm/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/getmaapp/signal-wasm/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/getmaapp/signal-wasm/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/getmaapp/signal-wasm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/getmaapp/signal-wasm/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/getmaapp/signal-wasm/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/getmaapp/signal-wasm/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/getmaapp/signal-wasm/releases/tag/v0.1.0

<!-- [0.6.2] and [0.6.1] compare URLs are omitted: those tags do not exist
     yet and earlier unreleased versions had no forward refs in the working
     tree. Add `compare/v0.6.1...v0.6.2` and `compare/v0.6.0...v0.6.1` here
     once the tags are pushed. -->
