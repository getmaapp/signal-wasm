//! libsignal WASM Bridge — Granular API
//!
//! Exposes cryptographic primitives, individual protocol stores, and standalone
//! protocol operations matching upstream libsignal's architecture.
//!
//! ## Design
//! - No monolithic client. Identity generation requires **no device ID**.
//! - `PrivateKey::generate()` → `getPublicKey()` → `IdentityKeyPair`
//! - Device IDs are used **only** in `ProtocolAddress`.
//! - Stores are first-class objects: `InMemSessionStore`, `InMemIdentityKeyStore`, etc.
//! - Protocol operations are standalone async functions that accept stores explicitly.

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]

use zkgroup::groups::{GroupMasterKey, GroupSecretParams};
use zkgroup::GroupIdentifierBytes;

use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;
use libsignal_protocol::{
    create_sender_key_distribution_message,
    group_decrypt,
    group_encrypt,
    kem,
    message_decrypt,
    message_encrypt,
    process_prekey_bundle,
    process_sender_key_distribution_message,
    CiphertextMessage,
    CiphertextMessageType,
    DeviceId,
    Fingerprint,
    GenericSignedPreKey,
    IdentityKey,
    IdentityKeyPair,
    InMemIdentityKeyStore,
    InMemKyberPreKeyStore,
    InMemPreKeyStore,
    InMemSenderKeyStore,
    InMemSessionStore,
    InMemSignedPreKeyStore,
    KeyPair,
    KyberPreKeyRecord,
    KyberPreKeyStore,
    PreKeyBundle,
    PreKeyRecord,
    PreKeySignalMessage,
    PreKeyStore,
    PrivateKey,
    ProtocolAddress,
    PublicKey,
    SenderKeyDistributionMessage,
    SenderKeyRecord,
    SenderKeyStore,
    SessionRecord,
    SessionStore,
    SignalMessage,
    SignedPreKeyRecord,
    SignedPreKeyStore,
    Timestamp,
};

// ============================================================================
// SECTION 0: Constants
// ============================================================================

/// Signal Protocol fingerprint version.
const FINGERPRINT_VERSION: u32 = 2;
/// Signal Protocol fingerprint iteration count.
const FINGERPRINT_ITERATIONS: u32 = 5200;

/// Maximum valid device ID (Signal convention, though DeviceId allows 1-255).
const MAX_DEVICE_ID: u32 = 127;

/// Maximum registration ID value (inclusive).
const MAX_REGISTRATION_ID: u32 = 16380;

/// Maximum number of PreKeys that can be generated in a single batch.
const MAX_PREKEY_BATCH_SIZE: u32 = 500;

/// Maximum length for `generate_random_bytes` to prevent DoS via huge allocation.
const MAX_RANDOM_BYTES_LENGTH: usize = 1_048_576; // 1 MiB

/// Standard size of a Group Master Key.
const GROUP_MASTER_KEY_SIZE: usize = 32;

/// Standard size of an attachment encryption key.
const ATTACHMENT_KEY_SIZE: usize = 64;

// ============================================================================
// SECTION 1: Initialisation
// ============================================================================

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(debug_assertions)]
    {
        console_error_panic_hook::set_once();
        web_sys::console::log_1(&"[Signal WASM] Module initialised (Debug Mode)".into());
    }
}

#[wasm_bindgen]
pub fn log_to_console(message: &str) {
    web_sys::console::log_1(&message.into());
}

// ============================================================================
// SECTION 2: Error Handling & Validation
// ============================================================================

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

fn make_device_id(id: u32) -> Result<DeviceId, JsValue> {
    DeviceId::try_from(id).map_err(|_| {
        JsValue::from_str(&format!("Invalid device ID (must be 1-{})", MAX_DEVICE_ID))
    })
}

/// A Signal-specific namespace for UUIDv5 derivation, distinct from NAMESPACE_DNS.
const SIGNAL_NAMESPACE_UUID: uuid::Uuid = uuid::Uuid::from_bytes([
    0x5e, 0x0d, 0x4f, 0xe5, 0x5c, 0x2a, 0x4f, 0x7a,
    0x8e, 0x1e, 0x3f, 0x8e, 0x2e, 0x8b, 0x1e, 0x3f,
]);

fn map_group_id(id: &str) -> uuid::Uuid {
    if let Ok(uuid) = uuid::Uuid::parse_str(id) {
        uuid
    } else {
        uuid::Uuid::new_v5(&SIGNAL_NAMESPACE_UUID, id.as_bytes())
    }
}

fn now_system_time() -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}

fn now_timestamp() -> Timestamp {
    Timestamp::from_epoch_millis(js_sys::Date::now() as u64)
}

// ============================================================================
// SECTION 3: Granular Crypto Types
// ============================================================================

/// PrivateKey — standalone asymmetric secret key.
#[wasm_bindgen]
#[derive(Clone)]
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

/// PublicKey — standalone asymmetric public key.
#[wasm_bindgen]
#[derive(Clone)]
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

/// IdentityKeyPair — wraps a (PublicKey, PrivateKey) pair used as the long-term identity.
#[wasm_bindgen]
#[derive(Clone)]
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
            self.private_key.0,
        );
        pair.serialize().into_vec()
    }

    /// Deserialize from standard protobuf format.
    #[wasm_bindgen(js_name = deserialize)]
    pub fn deserialize(data: &[u8]) -> Result<WasmIdentityKeyPair, JsValue> {
        let pair = IdentityKeyPair::try_from(data).map_err(to_js_error)?;
        let pub_key = *pair.identity_key();
        let priv_key = *pair.private_key();
        Ok(WasmIdentityKeyPair {
            public_key: WasmPublicKey(pub_key.into()),
            private_key: WasmPrivateKey(priv_key),
        })
    }
}

// ============================================================================
// SECTION 4: Protocol Address
// ============================================================================

#[wasm_bindgen]
#[derive(Clone)]
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

// ============================================================================
// SECTION 5: Individual Stores
// ============================================================================

#[wasm_bindgen]
pub struct WasmInMemIdentityKeyStore(InMemIdentityKeyStore);

#[wasm_bindgen]
impl WasmInMemIdentityKeyStore {
    #[wasm_bindgen(constructor)]
    pub fn new(identity_key_pair: &WasmIdentityKeyPair, registration_id: u32) -> WasmInMemIdentityKeyStore {
        let pair = IdentityKeyPair::new(
            identity_key_pair.public_key.0.into(),
            identity_key_pair.private_key.0,
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

    #[wasm_bindgen]
    pub async fn has_session(&self, address: &WasmProtocolAddress) -> Result<bool, JsValue> {
        let result = self
            .0
            .load_session(&address.0)
            .await
            .map(|s| s.is_some())
            .unwrap_or(false);
        Ok(result)
    }

    #[wasm_bindgen]
    pub async fn archive_session(&mut self, address: &WasmProtocolAddress) -> Result<(), JsValue> {
        if let Some(mut session) = self.0.load_session(&address.0).await.map_err(to_js_error)? {
            session.archive_current_state().map_err(to_js_error)?;
            self.0.store_session(&address.0, &session).await.map_err(to_js_error)?;
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_session(&self, address: &WasmProtocolAddress) -> Result<Option<Vec<u8>>, JsValue> {
        match self.0.load_session(&address.0).await.map_err(to_js_error)? {
            Some(session) => Ok(Some(session.serialize().map_err(to_js_error)?)),
            None => Ok(None),
        }
    }

    #[wasm_bindgen]
    pub async fn import_session(&mut self, address: &WasmProtocolAddress, session_bytes: &[u8]) -> Result<(), JsValue> {
        let session = SessionRecord::deserialize(session_bytes).map_err(to_js_error)?;
        self.0.store_session(&address.0, &session).await.map_err(to_js_error)?;
        Ok(())
    }
}

impl Default for WasmInMemSessionStore {
    fn default() -> Self {
        Self::new()
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

    #[wasm_bindgen]
    pub async fn import_pre_key(&mut self, id: u32, record_bytes: &[u8]) -> Result<(), JsValue> {
        let record = PreKeyRecord::deserialize(record_bytes).map_err(to_js_error)?;
        if u32::from(record.id().map_err(to_js_error)?) != id {
            return Err(JsValue::from_str("PreKey ID mismatch"));
        }
        self.0.save_pre_key(id.into(), &record).await.map_err(to_js_error)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        match self.0.get_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            Err(_) => Ok(None),
        }
    }
}

impl Default for WasmInMemPreKeyStore {
    fn default() -> Self {
        Self::new()
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

    #[wasm_bindgen]
    pub async fn import_signed_pre_key(&mut self, id: u32, record_bytes: &[u8]) -> Result<(), JsValue> {
        let record = SignedPreKeyRecord::deserialize(record_bytes).map_err(to_js_error)?;
        if u32::from(record.id().map_err(to_js_error)?) != id {
            return Err(JsValue::from_str("Signed PreKey ID mismatch"));
        }
        self.0.save_signed_pre_key(id.into(), &record).await.map_err(to_js_error)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        match self.0.get_signed_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            Err(_) => Ok(None),
        }
    }
}

impl Default for WasmInMemSignedPreKeyStore {
    fn default() -> Self {
        Self::new()
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

    #[wasm_bindgen]
    pub async fn import_kyber_pre_key(&mut self, id: u32, record_bytes: &[u8]) -> Result<(), JsValue> {
        let record = KyberPreKeyRecord::deserialize(record_bytes).map_err(to_js_error)?;
        if u32::from(record.id().map_err(to_js_error)?) != id {
            return Err(JsValue::from_str("Kyber PreKey ID mismatch"));
        }
        self.0.save_kyber_pre_key(id.into(), &record).await.map_err(to_js_error)?;
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn export_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        match self.0.get_kyber_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            Err(_) => Ok(None),
        }
    }
}

impl Default for WasmInMemKyberPreKeyStore {
    fn default() -> Self {
        Self::new()
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

    #[wasm_bindgen]
    pub async fn export_sender_key(
        &mut self,
        address: &WasmProtocolAddress,
        distribution_id: String,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let dist_id = map_group_id(&distribution_id);
        match self.0.load_sender_key(&address.0, dist_id).await.map_err(to_js_error)? {
            Some(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            None => Ok(None),
        }
    }

    #[wasm_bindgen]
    pub async fn import_sender_key(
        &mut self,
        address: &WasmProtocolAddress,
        distribution_id: String,
        record_bytes: &[u8],
    ) -> Result<(), JsValue> {
        let dist_id = map_group_id(&distribution_id);
        let record = SenderKeyRecord::deserialize(record_bytes).map_err(to_js_error)?;
        self.0.store_sender_key(&address.0, dist_id, &record).await.map_err(to_js_error)?;
        Ok(())
    }
}

impl Default for WasmInMemSenderKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SECTION 6: Exported Key / Message Types
// ============================================================================

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmPreKey {
    id: u32,
    public_key: Vec<u8>,
    record: Vec<u8>,
}

#[wasm_bindgen]
impl WasmPreKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmSignedPreKey {
    id: u32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    record: Vec<u8>,
}

#[wasm_bindgen]
impl WasmSignedPreKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.clone()
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmKyberPreKey {
    id: u32,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    timestamp: u64,
    record: Vec<u8>,
}

#[wasm_bindgen]
impl WasmKyberPreKey {
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Vec<u8> {
        self.signature.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[wasm_bindgen(getter)]
    pub fn record(&self) -> Vec<u8> {
        self.record.clone()
    }
}

#[wasm_bindgen]
pub struct WasmCiphertext {
    message_type: u8,
    body: Vec<u8>,
}

#[wasm_bindgen]
impl WasmCiphertext {
    #[wasm_bindgen(getter)]
    pub fn message_type(&self) -> u8 {
        self.message_type
    }

    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
}

#[wasm_bindgen]
pub struct WasmSafetyNumber {
    displayable: String,
    scannable: Vec<u8>,
}

#[wasm_bindgen]
impl WasmSafetyNumber {
    #[wasm_bindgen(getter)]
    pub fn displayable(&self) -> String {
        self.displayable.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn scannable(&self) -> Vec<u8> {
        self.scannable.clone()
    }
}

// ============================================================================
// SECTION 7: Group Messaging v2 (GV2) Types
// ============================================================================

#[wasm_bindgen]
pub struct WasmGroupMasterKey {
    inner: GroupMasterKey,
    bytes: [u8; GROUP_MASTER_KEY_SIZE],
}

#[wasm_bindgen]
impl WasmGroupMasterKey {
    #[wasm_bindgen]
    pub fn generate() -> WasmGroupMasterKey {
        let mut bytes = [0u8; GROUP_MASTER_KEY_SIZE];
        let mut rng = rand::rng();
        rand::prelude::Rng::fill(&mut rng, &mut bytes);
        WasmGroupMasterKey {
            inner: GroupMasterKey::new(bytes),
            bytes,
        }
    }

    #[wasm_bindgen]
    pub fn from_bytes(bytes: &[u8]) -> Result<WasmGroupMasterKey, JsValue> {
        let array: [u8; GROUP_MASTER_KEY_SIZE] = bytes.try_into().map_err(|_| {
            JsValue::from_str(&format!("Invalid key length (must be {} bytes)", GROUP_MASTER_KEY_SIZE))
        })?;
        Ok(WasmGroupMasterKey {
            inner: GroupMasterKey::new(array),
            bytes: array,
        })
    }

    #[wasm_bindgen(getter)]
    pub fn serialize(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }

    #[wasm_bindgen]
    pub fn derive_secret_params(&self) -> WasmGroupSecretParams {
        WasmGroupSecretParams {
            inner: GroupSecretParams::derive_from_master_key(self.inner),
            master_key_bytes: self.bytes,
        }
    }

    #[wasm_bindgen]
    pub fn derive_identifier(&self) -> WasmGroupIdentifier {
        let params = GroupSecretParams::derive_from_master_key(self.inner);
        WasmGroupIdentifier {
            inner: params.get_group_identifier(),
        }
    }
}

#[wasm_bindgen]
pub struct WasmGroupIdentifier {
    inner: GroupIdentifierBytes,
}

#[wasm_bindgen]
impl WasmGroupIdentifier {
    #[wasm_bindgen(getter)]
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.to_vec()
    }
}

#[wasm_bindgen]
pub struct WasmGroupSecretParams {
    inner: GroupSecretParams,
    master_key_bytes: [u8; GROUP_MASTER_KEY_SIZE],
}

#[wasm_bindgen]
impl WasmGroupSecretParams {
    #[wasm_bindgen(getter)]
    pub fn serialize(&self) -> Vec<u8> {
        self.master_key_bytes.to_vec()
    }

    #[wasm_bindgen]
    pub fn get_identifier(&self) -> WasmGroupIdentifier {
        WasmGroupIdentifier {
            inner: self.inner.get_group_identifier(),
        }
    }
}

// ============================================================================
// SECTION 8: Standalone Key Generation
// ============================================================================

/// Generate a batch of one-time PreKeys.
#[wasm_bindgen(js_name = generatePreKeys)]
pub async fn generate_pre_keys(
    start_id: u32,
    count: u32,
    prekey_store: &mut WasmInMemPreKeyStore,
) -> Result<Vec<WasmPreKey>, JsValue> {
    if count > MAX_PREKEY_BATCH_SIZE {
        return Err(JsValue::from_str(&format!(
            "Batch size {} exceeds maximum {}",
            count, MAX_PREKEY_BATCH_SIZE
        )));
    }
    let mut rng = rand::rng();
    let mut result = Vec::new();

    for i in 0..count {
        let id = start_id.wrapping_add(i) & 0x00FF_FFFF;
        let key_pair = KeyPair::generate(&mut rng);
        let prekey_record = PreKeyRecord::new(id.into(), &key_pair);
        let serialized = prekey_record.serialize().map_err(to_js_error)?;

        prekey_store.0.save_pre_key(id.into(), &prekey_record)
            .await
            .map_err(to_js_error)?;

        result.push(WasmPreKey {
            id,
            public_key: key_pair.public_key.serialize().to_vec(),
            record: serialized,
        });
    }

    Ok(result)
}

/// Generate a signed PreKey.
#[wasm_bindgen(js_name = generateSignedPreKey)]
pub async fn generate_signed_pre_key(
    key_id: u32,
    identity_key_pair: &WasmIdentityKeyPair,
    signed_prekey_store: &mut WasmInMemSignedPreKeyStore,
) -> Result<WasmSignedPreKey, JsValue> {
    let mut rng = rand::rng();
    let key_pair = KeyPair::generate(&mut rng);
    let signature = identity_key_pair
        .private_key
        .0
        .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
        .map_err(to_js_error)?;

    let timestamp = now_timestamp();
    let signed_prekey_record = SignedPreKeyRecord::new(key_id.into(), timestamp, &key_pair, &signature);
    let serialized = signed_prekey_record.serialize().map_err(to_js_error)?;

    signed_prekey_store
        .0
        .save_signed_pre_key(key_id.into(), &signed_prekey_record)
        .await
        .map_err(to_js_error)?;

    Ok(WasmSignedPreKey {
        id: key_id,
        public_key: key_pair.public_key.serialize().to_vec(),
        signature: signature.to_vec(),
        timestamp: timestamp.epoch_millis(),
        record: serialized,
    })
}

/// Generate a Kyber PreKey for post-quantum security.
#[wasm_bindgen(js_name = generateKyberPreKey)]
pub async fn generate_kyber_pre_key(
    key_id: u32,
    identity_key_pair: &WasmIdentityKeyPair,
    kyber_prekey_store: &mut WasmInMemKyberPreKeyStore,
) -> Result<WasmKyberPreKey, JsValue> {
    let mut rng = rand::rng();
    let key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
    let signature = identity_key_pair
        .private_key
        .0
        .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
        .map_err(to_js_error)?;
    let timestamp = now_timestamp();
    let kyber_record = KyberPreKeyRecord::new(key_id.into(), timestamp, &key_pair, &signature);
    let serialized = kyber_record.serialize().map_err(to_js_error)?;

    let public_key = key_pair.public_key.serialize().to_vec();

    kyber_prekey_store
        .0
        .save_kyber_pre_key(key_id.into(), &kyber_record)
        .await
        .map_err(to_js_error)?;

    Ok(WasmKyberPreKey {
        id: key_id,
        public_key,
        signature: signature.to_vec(),
        timestamp: timestamp.epoch_millis(),
        record: serialized,
    })
}

/// Generate a registration ID using unbiased rejection sampling (1..=MAX_REGISTRATION_ID).
#[wasm_bindgen(js_name = generateRegistrationId)]
pub fn generate_registration_id() -> u32 {
    loop {
        let val = rand::random::<u32>();
        if val < (u32::MAX / MAX_REGISTRATION_ID) * MAX_REGISTRATION_ID {
            break (val % MAX_REGISTRATION_ID) + 1;
        }
    }
}

// ============================================================================
// SECTION 9: Standalone Protocol Operations
// ============================================================================

/// Process a PreKeyBundle to establish a session.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = processPreKeyBundle)]
pub async fn process_pre_key_bundle(
    recipient: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    registration_id: u32,
    identity_key: &WasmPublicKey,
    signed_prekey_id: u32,
    signed_prekey: &WasmPublicKey,
    signed_prekey_signature: &[u8],
    prekey_id: Option<u32>,
    prekey: Option<Vec<u8>>,
    kyber_prekey_id: u32,
    kyber_prekey: &[u8],
    kyber_prekey_signature: &[u8],
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
) -> Result<(), JsValue> {
    let identity_key_pub = identity_key.0;
    let signed_prekey_pub = signed_prekey.0;
    let kyber_prekey_pub = kem::PublicKey::deserialize(kyber_prekey).map_err(to_js_error)?;

    let prekey_tuple = match (prekey_id, prekey) {
        (Some(id), Some(bytes)) => {
            let pk = PublicKey::deserialize(&bytes).map_err(to_js_error)?;
            Some((id.into(), pk))
        }
        _ => None,
    };

    let bundle = PreKeyBundle::new(
        registration_id,
        recipient.0.device_id(),
        prekey_tuple,
        signed_prekey_id.into(),
        signed_prekey_pub,
        signed_prekey_signature.to_vec(),
        kyber_prekey_id.into(),
        kyber_prekey_pub,
        kyber_prekey_signature.to_vec(),
        identity_key_pub.into(),
    )
    .map_err(to_js_error)?;

    let mut rng = rand::rng();
    process_prekey_bundle(
        &recipient.0,
        &local_address.0,
        &mut session_store.0,
        &mut identity_store.0,
        &bundle,
        now_system_time(),
        &mut rng,
    )
    .await
    .map_err(to_js_error)?;

    Ok(())
}

/// Encrypt a Signal message.
#[wasm_bindgen(js_name = encryptMessage)]
pub async fn encrypt_message(
    plaintext: &[u8],
    recipient: &WasmProtocolAddress,
    local_address: &WasmProtocolAddress,
    session_store: &mut WasmInMemSessionStore,
    identity_store: &mut WasmInMemIdentityKeyStore,
) -> Result<WasmCiphertext, JsValue> {
    let mut rng = rand::rng();
    let ciphertext = message_encrypt(
        plaintext,
        &recipient.0,
        &local_address.0,
        &mut session_store.0,
        &mut identity_store.0,
        now_system_time(),
        &mut rng,
    )
    .await
    .map_err(to_js_error)?;

    Ok(WasmCiphertext {
        message_type: ciphertext.message_type() as u8,
        body: ciphertext.serialize().to_vec(),
    })
}

/// Decrypt a Signal message.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen(js_name = decryptMessage)]
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
    let mut rng = rand::rng();

    let msg_type = CiphertextMessageType::try_from(message_type).map_err(|_| {
        JsValue::from_str(&format!("Unknown message type: {}", message_type))
    })?;

    let ciphertext_msg: CiphertextMessage = match msg_type {
        CiphertextMessageType::Whisper => CiphertextMessage::SignalMessage(
            SignalMessage::try_from(ciphertext).map_err(to_js_error)?,
        ),
        CiphertextMessageType::PreKey => CiphertextMessage::PreKeySignalMessage(
            PreKeySignalMessage::try_from(ciphertext).map_err(to_js_error)?,
        ),
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unsupported message type for decrypt: {:?}",
                msg_type
            )))
        }
    };

    let plaintext = message_decrypt(
        &ciphertext_msg,
        &sender.0,
        &local_address.0,
        &mut session_store.0,
        &mut identity_store.0,
        &mut prekey_store.0,
        &signed_prekey_store.0,
        &mut kyber_prekey_store.0,
        &mut rng,
    )
    .await
    .map_err(to_js_error)?;

    Ok(plaintext)
}

/// Create a sender key distribution message.
#[wasm_bindgen(js_name = createSenderKeyDistribution)]
pub async fn create_sender_key_distribution(
    local_address: &WasmProtocolAddress,
    distribution_id: String,
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let dist_id = map_group_id(&distribution_id);
    let mut rng = rand::rng();
    let skdm = create_sender_key_distribution_message(
        &local_address.0,
        dist_id,
        &mut sender_key_store.0,
        &mut rng,
    )
    .await
    .map_err(to_js_error)?;

    Ok(skdm.serialized().to_vec())
}

/// Process a sender key distribution message.
#[wasm_bindgen(js_name = processSenderKeyDistribution)]
pub async fn process_sender_key_distribution(
    sender_address: &WasmProtocolAddress,
    distribution_message: &[u8],
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<(), JsValue> {
    let skdm = SenderKeyDistributionMessage::try_from(distribution_message).map_err(to_js_error)?;
    process_sender_key_distribution_message(&sender_address.0, &skdm, &mut sender_key_store.0)
        .await
        .map_err(to_js_error)?;
    Ok(())
}

/// Encrypt a group message.
#[wasm_bindgen(js_name = encryptGroupMessage)]
pub async fn encrypt_group_message(
    local_address: &WasmProtocolAddress,
    distribution_id: String,
    plaintext: &[u8],
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let dist_id = map_group_id(&distribution_id);
    let mut rng = rand::rng();
    let ciphertext = group_encrypt(
        &mut sender_key_store.0,
        &local_address.0,
        dist_id,
        plaintext,
        &mut rng,
    )
    .await
    .map_err(to_js_error)?;

    Ok(ciphertext.serialized().to_vec())
}

/// Decrypt a group message.
#[wasm_bindgen(js_name = decryptGroupMessage)]
pub async fn decrypt_group_message(
    sender_address: &WasmProtocolAddress,
    ciphertext: &[u8],
    sender_key_store: &mut WasmInMemSenderKeyStore,
) -> Result<Vec<u8>, JsValue> {
    let plaintext = group_decrypt(ciphertext, &mut sender_key_store.0, &sender_address.0)
        .await
        .map_err(to_js_error)?;

    Ok(plaintext)
}

/// Generate a safety number.
#[wasm_bindgen(js_name = generateSafetyNumber)]
pub fn generate_safety_number(
    local_uuid: String,
    local_identity_key: &WasmPublicKey,
    contact_uuid: String,
    contact_identity_key: &WasmPublicKey,
) -> Result<WasmSafetyNumber, JsValue> {
    let local_key: IdentityKey = local_identity_key.0.into();
    let contact_key: IdentityKey = contact_identity_key.0.into();

    let fingerprint = Fingerprint::new(
        FINGERPRINT_VERSION,
        FINGERPRINT_ITERATIONS,
        local_uuid.as_bytes(),
        &local_key,
        contact_uuid.as_bytes(),
        &contact_key,
    )
    .map_err(to_js_error)?;

    Ok(WasmSafetyNumber {
        displayable: fingerprint.display.to_string(),
        scannable: fingerprint.scannable.serialize().map_err(to_js_error)?,
    })
}

/// Verify a scanned safety number.
#[wasm_bindgen(js_name = verifySafetyNumber)]
pub fn verify_safety_number(
    scanned: &[u8],
    local_uuid: String,
    local_identity_key: &WasmPublicKey,
    contact_uuid: String,
    contact_identity_key: &WasmPublicKey,
) -> Result<bool, JsValue> {
    let expected = generate_safety_number(
        local_uuid,
        local_identity_key,
        contact_uuid,
        contact_identity_key,
    )?;

    let valid = scanned.ct_eq(&expected.scannable);
    Ok(valid.into())
}

// ============================================================================
// SECTION 10: Utility Functions
// ============================================================================

#[wasm_bindgen]
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    if length > MAX_RANDOM_BYTES_LENGTH {
        return Err(JsValue::from_str(&format!(
            "Requested length {} exceeds maximum allowed {} bytes",
            length, MAX_RANDOM_BYTES_LENGTH
        )));
    }
    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes).map_err(|e| JsValue::from_str(&format!("CSPRNG error: {}", e)))?;
    Ok(bytes)
}

#[wasm_bindgen]
pub fn generate_attachment_key() -> Result<Vec<u8>, JsValue> {
    generate_random_bytes(ATTACHMENT_KEY_SIZE)
}

#[wasm_bindgen]
pub fn generate_uuid() -> Vec<u8> {
    uuid::Uuid::new_v4().as_bytes().to_vec()
}

#[wasm_bindgen]
pub fn uuid_to_string(bytes: &[u8]) -> Result<String, JsValue> {
    if bytes.len() != 16 {
        return Err(JsValue::from_str("UUID must be 16 bytes"));
    }
    let uuid = uuid::Uuid::from_slice(bytes).map_err(to_js_error)?;
    Ok(uuid.to_string())
}

#[wasm_bindgen]
pub fn uuid_from_string(s: &str) -> Result<Vec<u8>, JsValue> {
    let uuid = uuid::Uuid::parse_str(s).map_err(to_js_error)?;
    Ok(uuid.as_bytes().to_vec())
}

#[wasm_bindgen]
pub fn message_type_signal() -> u8 {
    CiphertextMessageType::Whisper as u8
}

#[wasm_bindgen]
pub fn message_type_pre_key() -> u8 {
    CiphertextMessageType::PreKey as u8
}

#[wasm_bindgen]
pub fn message_type_sender_key() -> u8 {
    CiphertextMessageType::SenderKey as u8
}
