# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/getmaapp/signal-wasm/compare/v0.1.2...HEAD
[0.1.2]: https://github.com/getmaapp/signal-wasm/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/getmaapp/signal-wasm/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/getmaapp/signal-wasm/releases/tag/v0.1.0
