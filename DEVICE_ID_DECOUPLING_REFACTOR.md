# Device ID Decoupling Refactor

## Status

**Beta-breaking change.** No backward compatibility preserved. All consumers must migrate.

## Problem Statement

Our current `SignalClient` is a custom monolithic abstraction that conflates **cryptographic identity creation**, **protocol stores**, and **protocol addressing** (`local_uuid`, `local_device_id`) into a single object. This forces consumers to invent a "temporary" device ID solely to extract an identity key pair.

The upstream Signal team does **not** use a monolithic `SignalClient`. Their libsignal bindings expose:
- **Granular crypto primitives**: `PrivateKey.generate()`, `PublicKey`, `IdentityKeyPair`
- **Individual stores**: `InMemIdentityKeyStore`, `InMemSessionStore`, etc.
- **Protocol operations as standalone functions** that accept stores and `ProtocolAddress`
- **No object** that requires both identity keys and a device ID to construct

### Evidence from Upstream Signal

| Source | Finding |
|--------|---------|
| `libsignal/rust/protocol/src/identity_key.rs:99` | `IdentityKeyPair::generate(csprng)` — requires **only** a CSPRNG |
| `libsignal/rust/core/src/address.rs:678` | `DeviceId` is `NonZeroU8` (1–127), used **only** for `ProtocolAddress` |
| `libsignal/rust/bridge/shared/src/protocol.rs:181` | `PrivateKey_Generate()` — standalone function, no device ID |
| `libsignal/rust/bridge/shared/src/protocol.rs:188` | `PrivateKey_GetPublicKey()` — derives public key from private key |
| Signal-Desktop `ts/Curve.node.ts:74` | `generateKeyPair()` calls `client.PrivateKey.generate()` then `getPublicKey()` |
| Signal-Desktop `ts/textsecure/AccountManager.preload.ts:404` | `aciKeyPair = generateKeyPair()` happens **before** any `deviceId` assignment |
| Signal-Server | `Device.PRIMARY_ID = 1`; secondary IDs `2..127` assigned server-side |

## Goal

**Decompose `SignalClient` into granular exports that match upstream libsignal's API surface.**

This eliminates the temp device ID problem at the architectural level: identity generation requires no device ID because there is no monolithic object that demands one.

## Proposed Changes

### 1. Remove `SignalClient` Entirely

Delete the `SignalClient` struct and all its methods from `src/lib.rs`.

### 2. Export Granular Crypto Types

Match the upstream bridge exactly:

```rust
// === PrivateKey ===
#[wasm_bindgen]
pub struct WasmPrivateKey(PrivateKey);

#[wasm_bindgen]
impl WasmPrivateKey {
    #[wasm_bindgen(js_name = generate)]
    pub fn generate() -> WasmPrivateKey {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        WasmPrivateKey(keypair.private_key)
    }

    #[wasm_bindgen(js_name = getPublicKey)]
    pub fn get_public_key(&self) -> Result<WasmPublicKey, JsValue> {
        Ok(WasmPublicKey(self.0.public_key().map_err(to_js_error)?))
    }

    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmPrivateKey, JsValue> {
        Ok(WasmPrivateKey(PrivateKey::deserialize(data).map_err(to_js_error)?))
    }
}

// === PublicKey ===
#[wasm_bindgen]
pub struct WasmPublicKey(PublicKey);

#[wasm_bindgen]
impl WasmPublicKey {
    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        self.0.serialize().to_vec()
    }

    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmPublicKey, JsValue> {
        Ok(WasmPublicKey(PublicKey::deserialize(data).map_err(to_js_error)?))
    }
}

// === IdentityKeyPair ===
// Upstream represents this as a pair of (PublicKey, PrivateKey).
// We expose a thin wrapper for ergonomic construction.
#[wasm_bindgen]
pub struct WasmIdentityKeyPair {
    public_key: WasmPublicKey,
    private_key: WasmPrivateKey,
}

#[wasm_bindgen]
impl WasmIdentityKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new(public_key: &WasmPublicKey, private_key: &WasmPrivateKey) -> WasmIdentityKeyPair {
        WasmIdentityKeyPair {
            public_key: WasmPublicKey(public_key.0),
            private_key: WasmPrivateKey(private_key.0),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> WasmPublicKey {
        WasmPublicKey(self.public_key.0)
    }

    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> WasmPrivateKey {
        WasmPrivateKey(self.private_key.0)
    }

    /// Serialize to the standard protobuf format used by libsignal.
    #[wasm_bindgen]
    pub fn serialize(&self) -> Vec<u8> {
        let pair = IdentityKeyPair::new(
            self.public_key.0.into(),
            self.private_key.0.clone(),
        );
        pair.serialize().into_vec()
    }

    /// Deserialize from standard protobuf format.
    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmIdentityKeyPair, JsValue> {
        let pair = IdentityKeyPair::try_from(data).map_err(to_js_error)?;
        Ok(WasmIdentityKeyPair {
            public_key: WasmPublicKey(*pair.public_key()),
            private_key: WasmPrivateKey(pair.private_key().clone()),
        })
    }
}
```

### 3. Export Protocol Address

```rust
#[wasm_bindgen]
pub struct WasmProtocolAddress(ProtocolAddress);

#[wasm_bindgen]
impl WasmProtocolAddress {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, device_id: u32) -> Result<WasmProtocolAddress, JsValue> {
        let device_id = make_device_id(device_id)?;
        Ok(WasmProtocolAddress(ProtocolAddress::new(name, device_id)))
    }

    #[wasm_bindgen(getter)]
    pub fn name(&self) -> String {
        self.0.name().to_string()
    }

    #[wasm_bindgen(getter, js_name = deviceId)]
    pub fn device_id(&self) -> u32 {
        self.0.device_id().into()
    }
}
```

### 4. Export Individual Stores

```rust
#[wasm_bindgen]
pub struct WasmInMemIdentityKeyStore(InMemIdentityKeyStore);

#[wasm_bindgen]
impl WasmInMemIdentityKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(identity_key_pair: &WasmIdentityKeyPair, registration_id: u32) -> WasmInMemIdentityKeyStore {
        let pair = IdentityKeyPair::new(
            identity_key_pair.public_key.0.into(),
            identity_key_pair.private_key.0.clone(),
        );
        WasmInMemIdentityKeyStore(InMemIdentityKeyStore::new(pair, registration_id))
    }
}

#[wasm_bindgen]
pub struct WasmInMemSessionStore(InMemSessionStore);

#[wasm_bindgen]
impl WasmInMemSessionStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemSessionStore {
        WasmInMemSessionStore(InMemSessionStore::new())
    }
}

#[wasm_bindgen]
pub struct WasmInMemPreKeyStore(InMemPreKeyStore);

#[wasm_bindgen]
impl WasmInMemPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemPreKeyStore {
        WasmInMemPreKeyStore(InMemPreKeyStore::new())
    }
}

#[wasm_bindgen]
pub struct WasmInMemSignedPreKeyStore(InMemSignedPreKeyStore);

#[wasm_bindgen]
impl WasmInMemSignedPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemSignedPreKeyStore {
        WasmInMemSignedPreKeyStore(InMemSignedPreKeyStore::new())
    }
}

#[wasm_bindgen]
pub struct WasmInMemKyberPreKeyStore(InMemKyberPreKeyStore);

#[wasm_bindgen]
impl WasmInMemKyberPreKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemKyberPreKeyStore {
        WasmInMemKyberPreKeyStore(InMemKyberPreKeyStore::new())
    }
}

#[wasm_bindgen]
pub struct WasmInMemSenderKeyStore(InMemSenderKeyStore);

#[wasm_bindgen]
impl WasmInMemSenderKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmInMemSenderKeyStore {
        WasmInMemSenderKeyStore(InMemSenderKeyStore::new())
    }
}
```

### 5. Export Protocol Operations as Standalone Functions

Replace `SignalClient` instance methods with standalone async functions that accept stores and addresses explicitly. This matches upstream's function-per-operation pattern.

```rust
/// Process a PreKeyBundle to establish a session.
#[wasm_bindgen]
pub async fn process_pre_key_bundle(
    recipient: &WasmProtocolAddress,
    registration_id: u32,
    identity_key: &WasmPublicKey,
    signed_prekey_id: u32,
    signed_prekey: &WasmPublicKey,
    signed_prekey_signature: &[u8],
    prekey_id: Option<u32>,
    prekey: Option<WasmPublicKey>,
    kyber_prekey_id: u32,
    kyber_prekey: &[u8],
    kyber_prekey_signature: &[u8],
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
) -> Result<(), JsValue> {
    // ... implementation using process_prekey_bundle from libsignal ...
}

/// Encrypt a Signal message.
#[wasm_bindgen]
pub async fn encrypt_message(
    plaintext: &[u8],
    recipient: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
) -> Result<WasmCiphertext, JsValue> {
    // ... implementation using message_encrypt ...
}

/// Decrypt a Signal message.
#[wasm_bindgen]
pub async fn decrypt_message(
    ciphertext: &[u8],
    message_type: u8,
    sender: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
    prekey_store: &mut WasmInMemPreKeyStore,
    signed_prekey_store: &WasmInMemSignedPreKeyStore,
    kyber_prekey_store: &mut WasmInMemKyberPreKeyStore,
) -> Result<Vec<u8>, JsValue> {
    // ... implementation using message_decrypt ...
}

// ... group messaging, safety numbers, key generation, etc.
```

### 6. Export PreKey Generation Functions

```rust
/// Generate a batch of one-time PreKeys.
#[wasm_bindgen]
pub fn generate_pre_keys(
    start_id: u32,
    count: u32,
    prekey_store: &mut WasmInMemPreKeyStore,
) -> Result<Vec<JsValue>, JsValue> {
    // ...
}

/// Generate a signed PreKey.
#[wasm_bindgen]
pub fn generate_signed_pre_key(
    key_id: u32,
    identity_key_pair: &WasmIdentityKeyPair,
    signed_prekey_store: &mut WasmInMemSignedPreKeyStore,
) -> Result<WasmSignedPreKey, JsValue> {
    // ...
}

/// Generate a Kyber PreKey.
#[wasm_bindgen]
pub fn generate_kyber_pre_key(
    key_id: u32,
    identity_key_pair: &WasmIdentityKeyPair,
    kyber_prekey_store: &mut WasmInMemKyberPreKeyStore,
) -> Result<WasmKyberPreKey, JsValue> {
    // ...
}
```

### 7. Export Utility Functions

```rust
/// Generate a registration ID using unbiased rejection sampling (1..=16380).
#[wasm_bindgen]
pub fn generate_registration_id() -> u32 {
    loop {
        let val = rand::random::<u32>();
        if val < (u32::MAX / 16380) * 16380 {
            break (val % 16380) + 1;
        }
    }
}

// Existing utilities remain:
// generate_uuid(), uuid_to_string(), uuid_from_string(),
// generate_attachment_key(), generate_random_bytes(), message_type_*, etc.
```

## Files to Modify

| File | Change |
|------|--------|
| `src/lib.rs` | Remove `SignalClient`; add granular types, stores, and standalone functions |
| `tests/web.rs` | Rewrite to use new granular API |
| `signal-wasm-demo/src/**/*.ts` | Rewrite to use new granular API |
| `pkg/*` | Auto-regenerated by `wasm-pack` |
| `CHANGELOG.md` | Document breaking changes |

## Generated TypeScript API (Target)

```typescript
// === Crypto Primitives ===
export class PrivateKey {
  free(): void;
  static generate(): PrivateKey;
  getPublicKey(): PublicKey;
  serialize(): Uint8Array;
  static deserialize(data: Uint8Array): PrivateKey;
}

export class PublicKey {
  free(): void;
  serialize(): Uint8Array;
  static deserialize(data: Uint8Array): PublicKey;
}

export class IdentityKeyPair {
  free(): void;
  constructor(publicKey: PublicKey, privateKey: PrivateKey);
  readonly publicKey: PublicKey;
  readonly privateKey: PrivateKey;
  serialize(): Uint8Array;
  static deserialize(data: Uint8Array): IdentityKeyPair;
}

// === Addressing ===
export class ProtocolAddress {
  free(): void;
  constructor(name: string, deviceId: number);
  readonly name: string;
  readonly deviceId: number;
}

// === Stores ===
export class InMemIdentityKeyStore {
  free(): void;
  constructor(identityKeyPair: IdentityKeyPair, registrationId: number);
}

export class InMemSessionStore {
  free(): void;
  constructor();
}

export class InMemPreKeyStore {
  free(): void;
  constructor();
}

export class InMemSignedPreKeyStore {
  free(): void;
  constructor();
}

export class InMemKyberPreKeyStore {
  free(): void;
  constructor();
}

export class InMemSenderKeyStore {
  free(): void;
  constructor();
}

// === PreKey Types ===
export class PreKey { ... }
export class SignedPreKey { ... }
export class KyberPreKey { ... }

// === Protocol Operations ===
export function processPreKeyBundle(
  recipient: ProtocolAddress,
  registrationId: number,
  identityKey: PublicKey,
  signedPrekeyId: number,
  signedPrekey: PublicKey,
  signedPrekeySignature: Uint8Array,
  prekeyId: number | undefined,
  prekey: PublicKey | undefined,
  kyberPrekeyId: number,
  kyberPrekey: Uint8Array,
  kyberPrekeySignature: Uint8Array,
  sessionStore: InMemSessionStore,
  identityStore: InMemIdentityKeyStore
): Promise<void>;

export function encryptMessage(
  plaintext: Uint8Array,
  recipient: ProtocolAddress,
  localAddress: ProtocolAddress,
  sessionStore: InMemSessionStore,
  identityStore: InMemIdentityKeyStore
): Promise<WasmCiphertext>;

export function decryptMessage(
  ciphertext: Uint8Array,
  messageType: number,
  sender: ProtocolAddress,
  localAddress: ProtocolAddress,
  sessionStore: InMemSessionStore,
  identityStore: InMemIdentityKeyStore,
  prekeyStore: InMemPreKeyStore,
  signedPrekeyStore: InMemSignedPreKeyStore,
  kyberPrekeyStore: InMemKyberPreKeyStore
): Promise<Uint8Array>;

// ... group messaging, safety numbers, store import/export, etc.

// === Utilities ===
export function generateRegistrationId(): number;
export function generateUuid(): Uint8Array;
export function uuidToString(bytes: Uint8Array): string;
export function uuidFromString(s: string): Uint8Array;
export function generateAttachmentKey(): Uint8Array;
export function generateRandomBytes(length: number): Uint8Array;
```

## Migration Path for Consumers

### Before (monolithic `SignalClient`)

```typescript
const client = new SignalClient(uuid, deviceId);
const keyPair = client.get_identity_key_pair();
client.generate_pre_keys(100);
const ciphertext = await client.encrypt_message(recipientUuid, recipientDeviceId, plaintext);
```

### After (granular libsignal-style API)

```typescript
// 1. Generate identity (no device ID needed)
const privateKey = PrivateKey.generate();
const publicKey = privateKey.getPublicKey();
const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
const registrationId = generateRegistrationId();

// 2. Create stores
const identityStore = new InMemIdentityKeyStore(identityKeyPair, registrationId);
const sessionStore = new InMemSessionStore();
const prekeyStore = new InMemPreKeyStore();
const signedPrekeyStore = new InMemSignedPreKeyStore();
const kyberPrekeyStore = new InMemKyberPreKeyStore();
const senderKeyStore = new InMemSenderKeyStore();

// 3. Create addresses (device ID only used here)
const localAddress = new ProtocolAddress(uuid, deviceId);
const recipientAddress = new ProtocolAddress(recipientUuid, recipientDeviceId);

// 4. Generate keys
const preKeys = await generatePreKeys(1, 100, prekeyStore);
const signedPreKey = await generateSignedPreKey(1, identityKeyPair, signedPrekeyStore);

// 5. Encrypt
const ciphertext = await encryptMessage(
  plaintext,
  recipientAddress,
  localAddress,
  sessionStore,
  identityStore
);
```

## Why This Is Identical to the Signal Team

| Aspect | Signal Team (libsignal) | Our Refactored API |
|--------|------------------------|-------------------|
| Key generation | `PrivateKey.generate()` → `getPublicKey()` | `PrivateKey.generate()` → `getPublicKey()` |
| Identity representation | `IdentityKeyPair(pubKey, privKey)` | `IdentityKeyPair(pubKey, privKey)` |
| Store architecture | Individual `InMem*Store` types | Individual `InMem*Store` types |
| Device ID scope | Only `ProtocolAddress` | Only `ProtocolAddress` |
| Encryption | `message_encrypt(plaintext, address, stores...)` | `encryptMessage(plaintext, address, stores...)` |
| Session establishment | `process_prekey_bundle(bundle, address, stores...)` | `processPreKeyBundle(bundle, address, stores...)` |
| Monolithic client | **Does not exist** | **Removed** |

## Rationale

Beta software is the **only** opportunity to fix fundamental API design mistakes. Our monolithic `SignalClient` was a well-intentioned simplification, but it:

1. **Hides libsignal's true architecture** from developers
2. **Forces temp device IDs** due to constructor coupling
3. **Prevents flexible store composition** (e.g., IndexedDB-backed stores)
4. **Diverges from upstream** documentation, examples, and mental models
5. **Blocks secondary-device linking** where server assigns device ID after keys exist

By decomposing into granular exports, we:
- Align 1:1 with Signal's official libsignal API
- Eliminate the temp device ID problem architecturally
- Enable custom store implementations (IndexedDB, OPFS, etc.)
- Make the library teachable using Signal's own documentation
- Support all registration flows: primary, linked, and restored

## References

- `libsignal/rust/protocol/src/identity_key.rs:99` — `IdentityKeyPair::generate`
- `libsignal/rust/core/src/address.rs:678` — `DeviceId` definition
- `libsignal/rust/bridge/shared/src/protocol.rs:181` — `PrivateKey_Generate`
- `libsignal/rust/bridge/shared/src/protocol.rs:257` — `IdentityKeyPair_Serialize`
- Signal-Desktop `ts/Curve.node.ts:74` — `generateKeyPair()` implementation
- Signal-Desktop `ts/textsecure/AccountManager.preload.ts:404` — Account creation flow
