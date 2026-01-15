//! libsignal WASM Bridge - Complete Implementation
//!
//! This module provides a complete 1:1 bridge between libsignal-protocol and JavaScript
//! via WebAssembly. It exposes the Signal Protocol for E2EE messaging in browsers.
//!
//! ## Features
//! - Identity key generation and management
//! - PreKey generation (EC + Signed + Kyber PQXDH)
//! - Session establishment via X3DH/PQXDH
//! - 1:1 message encryption/decryption
//! - Group messaging via Sender Keys
//! - Safety number generation and verification
//! - Store serialisation for IndexedDB persistence

#![deny(unsafe_code)]
#![warn(clippy::unwrap_used)]

use js_sys::Array;
use subtle::ConstantTimeEq;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// Re-export libsignal types
use libsignal_protocol::{
    create_sender_key_distribution_message,
    group_decrypt,
    group_encrypt,
    // KEM
    kem,
    message_decrypt,
    // Encryption/Decryption
    message_encrypt,
    process_prekey_bundle,
    process_sender_key_distribution_message,
    // Messages
    CiphertextMessage,
    DeviceId,
    // Fingerprints
    Fingerprint,
    // Other types
    GenericSignedPreKey,
    IdentityKey,
    // Identity
    IdentityKeyPair,
    InMemIdentityKeyStore,
    InMemKyberPreKeyStore,
    InMemPreKeyStore,
    InMemSenderKeyStore,
    // Stores
    InMemSessionStore,
    InMemSignedPreKeyStore,
    KeyPair,
    KyberPreKeyRecord,
    KyberPreKeyStore,
    PreKeyBundle,
    // PreKeys
    PreKeyRecord,
    PreKeySignalMessage,
    PreKeyStore,
    PrivateKey,
    // Addresses
    ProtocolAddress,
    PublicKey,
    SenderKeyDistributionMessage,
    SenderKeyRecord,
    SenderKeyStore,
    // Sessions
    SessionRecord,
    // Store traits
    SessionStore,
    SignalMessage,
    SignedPreKeyRecord,
    SignedPreKeyStore,
    Timestamp,
};

// ============================================================================
// SECTION 1: Initialisation
// ============================================================================

/// Initialise the WASM module. Called automatically when the module loads.
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(debug_assertions)]
    {
        console_error_panic_hook::set_once();
        web_sys::console::log_1(&"[Signal WASM] Module initialised (Debug Mode)".into());
    }
}

/// Log a message to the browser console (for debugging)
#[wasm_bindgen]
pub fn log_to_console(message: &str) {
    web_sys::console::log_1(&message.into());
}

// ============================================================================
// SECTION 2: Error Handling & Validation
// ============================================================================

/// Convert errors to generic JS errors (avoid leaking internal details)
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

fn make_device_id(id: u32) -> Result<DeviceId, JsValue> {
    DeviceId::try_from(id).map_err(|_| JsValue::from_str("Invalid device ID (must be 1-127)"))
}

/// Validate UUID format
fn validate_uuid(s: &str) -> Result<(), JsValue> {
    uuid::Uuid::parse_str(s).map_err(|_| JsValue::from_str("Invalid UUID format"))?;
    Ok(())
}

fn now_timestamp() -> Timestamp {
    let ms = js_sys::Date::now() as u64;
    Timestamp::from_epoch_millis(ms)
}

// ============================================================================
// SECTION 3: Exported Key Types
// ============================================================================

/// Represents a generated identity key pair
#[wasm_bindgen]
pub struct WasmIdentityKeyPair {
    public_key: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmIdentityKeyPair {
    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Get the private key bytes.
    ///
    /// # Security Warning
    /// Once these bytes are returned to JavaScript, they are managed by the JS garbage collector (V8/SpiderMonkey).
    /// Rust's `Zeroizing` protection NO LONGER APPLIES. The memory may persist until GC runs and
    /// is not guaranteed to be securely erased.
    #[wasm_bindgen(getter)]
    pub fn private_key(&self) -> Vec<u8> {
        (*self.private_key).clone()
    }
}

/// A single PreKey for upload to the server
#[wasm_bindgen]
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

/// A signed PreKey for upload to the server
#[wasm_bindgen]
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

/// A Kyber (post-quantum) PreKey for upload to the server
#[wasm_bindgen]
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

/// Safety number for identity verification
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

/// Encrypted message result
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

// ============================================================================
// SECTION 4: The Main Signal Client
// ============================================================================

/// The main Signal Protocol client.
///
/// Holds all cryptographic state for E2EE messaging.
/// Create one instance when your app starts.
#[wasm_bindgen]
pub struct SignalClient {
    identity_key_pair: IdentityKeyPair,
    registration_id: u32,

    // Protocol stores
    session_store: InMemSessionStore,
    identity_store: InMemIdentityKeyStore,
    prekey_store: InMemPreKeyStore,
    signed_prekey_store: InMemSignedPreKeyStore,
    sender_key_store: InMemSenderKeyStore,
    kyber_prekey_store: InMemKyberPreKeyStore,

    // Local identity
    local_uuid: String,
    local_device_id: DeviceId,

    // Counters
    next_prekey_id: u32,
    next_signed_prekey_id: u32,
    next_kyber_prekey_id: u32,
}

#[wasm_bindgen]
impl SignalClient {
    // ========================================================================
    // CONSTRUCTION
    // ========================================================================

    /// Create a new SignalClient with a fresh identity.
    #[wasm_bindgen(constructor)]
    pub fn new(local_uuid: &str, local_device_id: u32) -> Result<SignalClient, JsValue> {
        // Validate UUID format
        validate_uuid(local_uuid)?;

        let device_id = make_device_id(local_device_id)?;
        let mut rng = rand::rng();
        let identity_key_pair = IdentityKeyPair::generate(&mut rng);

        // Generate registration ID using rejection sampling (unbiased)
        let registration_id = loop {
            let val = rand::random::<u32>();
            if val < (u32::MAX / 16380) * 16380 {
                break (val % 16380) + 1;
            }
        };

        let identity_store = InMemIdentityKeyStore::new(identity_key_pair.clone(), registration_id);

        Ok(SignalClient {
            identity_key_pair,
            registration_id,
            session_store: InMemSessionStore::new(),
            identity_store,
            prekey_store: InMemPreKeyStore::new(),
            signed_prekey_store: InMemSignedPreKeyStore::new(),
            sender_key_store: InMemSenderKeyStore::new(),
            kyber_prekey_store: InMemKyberPreKeyStore::new(),
            local_uuid: local_uuid.to_string(),
            local_device_id: device_id,
            next_prekey_id: 1,
            next_signed_prekey_id: 1,
            next_kyber_prekey_id: 1,
        })
    }

    /// Restore a SignalClient from previously saved state.
    #[wasm_bindgen]
    pub fn restore(
        identity_public_key: &[u8],
        identity_private_key: &[u8],
        registration_id: u32,
        local_uuid: &str,
        local_device_id: u32,
        next_prekey_id: u32,
        next_signed_prekey_id: u32,
        next_kyber_prekey_id: u32,
    ) -> Result<SignalClient, JsValue> {
        let device_id = make_device_id(local_device_id)?;

        let public_key = PublicKey::deserialize(identity_public_key).map_err(to_js_error)?;
        let private_key = PrivateKey::deserialize(identity_private_key).map_err(to_js_error)?;
        let identity_key_pair = IdentityKeyPair::new(public_key.into(), private_key);

        let identity_store = InMemIdentityKeyStore::new(identity_key_pair.clone(), registration_id);

        Ok(SignalClient {
            identity_key_pair,
            registration_id,
            session_store: InMemSessionStore::new(),
            identity_store,
            prekey_store: InMemPreKeyStore::new(),
            signed_prekey_store: InMemSignedPreKeyStore::new(),
            sender_key_store: InMemSenderKeyStore::new(),
            kyber_prekey_store: InMemKyberPreKeyStore::new(),
            local_uuid: local_uuid.to_string(),
            local_device_id: device_id,
            next_prekey_id,
            next_signed_prekey_id,
            next_kyber_prekey_id,
        })
    }

    // ========================================================================
    // KEY EXPORT
    // ========================================================================

    #[wasm_bindgen]
    pub fn get_identity_key_pair(&self) -> WasmIdentityKeyPair {
        WasmIdentityKeyPair {
            public_key: self.identity_key_pair.public_key().serialize().to_vec(),
            private_key: Zeroizing::new(self.identity_key_pair.private_key().serialize().to_vec()),
        }
    }

    #[wasm_bindgen]
    pub fn get_identity_public_key(&self) -> Vec<u8> {
        self.identity_key_pair.public_key().serialize().to_vec()
    }

    #[wasm_bindgen]
    pub fn get_registration_id(&self) -> u32 {
        self.registration_id
    }

    #[wasm_bindgen]
    pub fn get_local_uuid(&self) -> String {
        self.local_uuid.clone()
    }

    #[wasm_bindgen]
    pub fn get_local_device_id(&self) -> u32 {
        self.local_device_id.into()
    }

    #[wasm_bindgen]
    pub fn get_next_pre_key_id(&self) -> u32 {
        self.next_prekey_id
    }

    #[wasm_bindgen]
    pub fn get_next_signed_pre_key_id(&self) -> u32 {
        self.next_signed_prekey_id
    }

    #[wasm_bindgen]
    pub fn get_next_kyber_pre_key_id(&self) -> u32 {
        self.next_kyber_prekey_id
    }

    // ========================================================================
    // EC PREKEY GENERATION
    // ========================================================================

    /// Generate a batch of one-time PreKeys.
    #[wasm_bindgen]
    pub fn generate_pre_keys(&mut self, count: u32) -> Result<Array, JsValue> {
        let mut rng = rand::rng();
        let result = Array::new();

        for _ in 0..count {
            let id = self.next_prekey_id;
            self.next_prekey_id = self
                .next_prekey_id
                .checked_add(1)
                .ok_or_else(|| JsValue::from_str("PreKey ID overflow"))?;

            let key_pair = KeyPair::generate(&mut rng);
            let prekey_record = PreKeyRecord::new(id.into(), &key_pair);
            let serialized = prekey_record.serialize().map_err(to_js_error)?;

            futures::executor::block_on(self.prekey_store.save_pre_key(id.into(), &prekey_record))
                .map_err(to_js_error)?;

            let wasm_prekey = WasmPreKey {
                id,
                public_key: key_pair.public_key.serialize().to_vec(),
                record: serialized,
            };
            result.push(&JsValue::from(wasm_prekey));
        }

        Ok(result)
    }

    /// Generate a signed PreKey.
    #[wasm_bindgen]
    pub fn generate_signed_pre_key(&mut self) -> Result<WasmSignedPreKey, JsValue> {
        let mut rng = rand::rng();

        let id = self.next_signed_prekey_id;
        self.next_signed_prekey_id = self
            .next_signed_prekey_id
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("Signed PreKey ID overflow"))?;

        let key_pair = KeyPair::generate(&mut rng);
        let signature = self
            .identity_key_pair
            .private_key()
            .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
            .map_err(to_js_error)?;

        let timestamp = now_timestamp();
        let signed_prekey_record =
            SignedPreKeyRecord::new(id.into(), timestamp, &key_pair, &signature);
        let serialized = signed_prekey_record.serialize().map_err(to_js_error)?;

        futures::executor::block_on(
            self.signed_prekey_store
                .save_signed_pre_key(id.into(), &signed_prekey_record),
        )
        .map_err(to_js_error)?;

        Ok(WasmSignedPreKey {
            id,
            public_key: key_pair.public_key.serialize().to_vec(),
            signature: signature.to_vec(),
            timestamp: timestamp.epoch_millis(),
            record: serialized,
        })
    }

    // ========================================================================
    // KYBER (PQXDH) PREKEY GENERATION
    // ========================================================================

    /// Generate a Kyber PreKey for post-quantum security.
    /// Uses Kyber1024 (Signal production default).
    #[wasm_bindgen]
    pub fn generate_kyber_pre_key(&mut self) -> Result<WasmKyberPreKey, JsValue> {
        let id = self.next_kyber_prekey_id;
        self.next_kyber_prekey_id = self
            .next_kyber_prekey_id
            .checked_add(1)
            .ok_or_else(|| JsValue::from_str("Kyber PreKey ID overflow"))?;

        // Generate Kyber keypair with WASM-compatible RNG (Web Crypto API)
        // Note: KyberPreKeyRecord::generate uses OsRng internally which panics in WASM
        let mut rng = rand::rng();
        let key_pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let signature = self
            .identity_key_pair
            .private_key()
            .calculate_signature(&key_pair.public_key.serialize(), &mut rng)
            .map_err(to_js_error)?;
        let timestamp = now_timestamp();
        let kyber_record = KyberPreKeyRecord::new(id.into(), timestamp, &key_pair, &signature);
        let serialized = kyber_record.serialize().map_err(to_js_error)?;

        let public_key = key_pair.public_key.serialize().to_vec();

        futures::executor::block_on(
            self.kyber_prekey_store
                .save_kyber_pre_key(id.into(), &kyber_record),
        )
        .map_err(to_js_error)?;

        Ok(WasmKyberPreKey {
            id,
            public_key,
            signature: signature.to_vec(),
            timestamp: timestamp.epoch_millis(),
            record: serialized,
        })
    }

    /// Generate multiple Kyber PreKeys.
    #[wasm_bindgen]
    pub fn generate_kyber_pre_keys(&mut self, count: u32) -> Result<Array, JsValue> {
        let result = Array::new();
        for _ in 0..count {
            let kpk = self.generate_kyber_pre_key()?;
            result.push(&JsValue::from(kpk));
        }
        Ok(result)
    }

    // ========================================================================
    // SESSION ESTABLISHMENT
    // ========================================================================

    /// Process a PreKeyBundle to establish a session.
    #[wasm_bindgen]
    pub async fn process_pre_key_bundle(
        &mut self,
        recipient_uuid: String,
        recipient_device_id: u32,
        registration_id: u32,
        identity_key: Vec<u8>,
        signed_prekey_id: u32,
        signed_prekey: Vec<u8>,
        signed_prekey_signature: Vec<u8>,
        prekey_id: Option<u32>,
        prekey: Option<Vec<u8>>,
        kyber_prekey_id: u32,
        kyber_prekey: Vec<u8>,
        kyber_prekey_signature: Vec<u8>,
    ) -> Result<(), JsValue> {
        let device_id = make_device_id(recipient_device_id)?;
        let address = ProtocolAddress::new(recipient_uuid, device_id);

        let identity_key_pub = PublicKey::deserialize(&identity_key).map_err(to_js_error)?;
        let signed_prekey_pub = PublicKey::deserialize(&signed_prekey).map_err(to_js_error)?;
        let kyber_prekey_pub = kem::PublicKey::deserialize(&kyber_prekey).map_err(to_js_error)?;

        let prekey_tuple = match (prekey_id, prekey) {
            (Some(id), Some(bytes)) => {
                let pk = PublicKey::deserialize(&bytes).map_err(to_js_error)?;
                Some((id.into(), pk))
            }
            _ => None,
        };

        let bundle = PreKeyBundle::new(
            registration_id,
            device_id,
            prekey_tuple,
            signed_prekey_id.into(),
            signed_prekey_pub,
            signed_prekey_signature,
            kyber_prekey_id.into(),
            kyber_prekey_pub,
            kyber_prekey_signature,
            identity_key_pub.into(),
        )
        .map_err(to_js_error)?;

        let mut rng = rand::rng();
        process_prekey_bundle(
            &address,
            &mut self.session_store,
            &mut self.identity_store,
            &bundle,
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64),
            &mut rng,
        )
        .await
        .map_err(to_js_error)?;

        Ok(())
    }

    /// Check if a session exists.
    #[wasm_bindgen]
    pub async fn has_session(
        &self,
        recipient_uuid: String,
        device_id: u32,
    ) -> Result<bool, JsValue> {
        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(recipient_uuid, dev_id);
        let result = self
            .session_store
            .load_session(&address)
            .await
            .map(|s| s.is_some())
            .unwrap_or(false);
        Ok(result)
    }

    /// Archive a session.
    #[wasm_bindgen]
    pub async fn archive_session(
        &mut self,
        contact_uuid: String,
        device_id: u32,
    ) -> Result<(), JsValue> {
        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(contact_uuid, dev_id);

        if let Some(mut session) = self
            .session_store
            .load_session(&address)
            .await
            .map_err(to_js_error)?
        {
            session.archive_current_state().map_err(to_js_error)?;
            self.session_store
                .store_session(&address, &session)
                .await
                .map_err(to_js_error)?;
        }

        Ok(())
    }

    // ========================================================================
    // 1:1 MESSAGE ENCRYPTION/DECRYPTION
    // ========================================================================

    /// Encrypt a message.
    #[wasm_bindgen]
    pub async fn encrypt_message(
        &mut self,
        recipient_uuid: String,
        device_id: u32,
        plaintext: Vec<u8>,
    ) -> Result<WasmCiphertext, JsValue> {
        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(recipient_uuid, dev_id);

        let mut rng = rand::rng();
        let ciphertext = message_encrypt(
            &plaintext,
            &address,
            &mut self.session_store,
            &mut self.identity_store,
            std::time::UNIX_EPOCH + std::time::Duration::from_millis(js_sys::Date::now() as u64),
            &mut rng,
        )
        .await
        .map_err(to_js_error)?;

        Ok(WasmCiphertext {
            message_type: ciphertext.message_type() as u8,
            body: ciphertext.serialize().to_vec(),
        })
    }

    /// Decrypt a message.
    #[wasm_bindgen]
    pub async fn decrypt_message(
        &mut self,
        sender_uuid: String,
        sender_device_id: u32,
        ciphertext: Vec<u8>,
        message_type: u8,
    ) -> Result<Vec<u8>, JsValue> {
        let dev_id = make_device_id(sender_device_id)?;
        let address = ProtocolAddress::new(sender_uuid, dev_id);

        let mut rng = rand::rng();

        let ciphertext_msg: CiphertextMessage = match message_type {
            2 => CiphertextMessage::SignalMessage(
                SignalMessage::try_from(ciphertext.as_slice()).map_err(to_js_error)?,
            ),
            3 => CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(ciphertext.as_slice()).map_err(to_js_error)?,
            ),
            _ => {
                return Err(JsValue::from_str(&format!(
                    "Unknown message type: {}",
                    message_type
                )))
            }
        };

        let plaintext = message_decrypt(
            &ciphertext_msg,
            &address,
            &mut self.session_store,
            &mut self.identity_store,
            &mut self.prekey_store,
            &self.signed_prekey_store,
            &mut self.kyber_prekey_store,
            &mut rng,
        )
        .await
        .map_err(to_js_error)?;

        Ok(plaintext)
    }

    // ========================================================================
    // GROUP MESSAGING
    // ========================================================================

    /// Create a sender key distribution message.
    #[wasm_bindgen]
    pub async fn create_sender_key_distribution(
        &mut self,
        distribution_id: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if distribution_id.len() != 16 {
            return Err(JsValue::from_str("distribution_id must be 16 bytes (UUID)"));
        }

        let dist_id = uuid::Uuid::from_slice(&distribution_id).map_err(to_js_error)?;
        let address = ProtocolAddress::new(self.local_uuid.clone(), self.local_device_id);

        let mut rng = rand::rng();
        let skdm = create_sender_key_distribution_message(
            &address,
            dist_id,
            &mut self.sender_key_store,
            &mut rng,
        )
        .await
        .map_err(to_js_error)?;

        Ok(skdm.serialized().to_vec())
    }

    /// Process a sender key distribution message.
    #[wasm_bindgen]
    pub async fn process_sender_key_distribution(
        &mut self,
        sender_uuid: String,
        sender_device_id: u32,
        distribution_message: Vec<u8>,
    ) -> Result<(), JsValue> {
        let dev_id = make_device_id(sender_device_id)?;
        let address = ProtocolAddress::new(sender_uuid, dev_id);
        let skdm = SenderKeyDistributionMessage::try_from(distribution_message.as_slice())
            .map_err(to_js_error)?;

        process_sender_key_distribution_message(&address, &skdm, &mut self.sender_key_store)
            .await
            .map_err(to_js_error)?;

        Ok(())
    }

    /// Encrypt a group message.
    #[wasm_bindgen]
    pub async fn encrypt_group_message(
        &mut self,
        distribution_id: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        if distribution_id.len() != 16 {
            return Err(JsValue::from_str("distribution_id must be 16 bytes (UUID)"));
        }

        let dist_id = uuid::Uuid::from_slice(&distribution_id).map_err(to_js_error)?;
        let address = ProtocolAddress::new(self.local_uuid.clone(), self.local_device_id);

        let mut rng = rand::rng();
        let ciphertext = group_encrypt(
            &mut self.sender_key_store,
            &address,
            dist_id,
            &plaintext,
            &mut rng,
        )
        .await
        .map_err(to_js_error)?;

        Ok(ciphertext.serialized().to_vec())
    }

    /// Decrypt a group message.
    #[wasm_bindgen]
    pub async fn decrypt_group_message(
        &mut self,
        sender_uuid: String,
        sender_device_id: u32,
        ciphertext: Vec<u8>,
    ) -> Result<Vec<u8>, JsValue> {
        let dev_id = make_device_id(sender_device_id)?;
        let address = ProtocolAddress::new(sender_uuid, dev_id);

        let plaintext = group_decrypt(&ciphertext, &mut self.sender_key_store, &address)
            .await
            .map_err(to_js_error)?;

        Ok(plaintext)
    }

    // ========================================================================
    // SAFETY NUMBERS
    // ========================================================================

    /// Generate a safety number.
    /// NOTE: We clone identity_key upfront to avoid wasm_bindgen aliasing issues.
    #[wasm_bindgen]
    pub fn generate_safety_number(
        &self,
        contact_uuid: String,
        contact_identity_key: Vec<u8>,
    ) -> Result<WasmSafetyNumber, JsValue> {
        // Clone to avoid aliasing issues with wasm_bindgen
        let local_uuid = self.local_uuid.clone();
        let local_identity_key = self.identity_key_pair.identity_key().clone();

        let contact_key_pub = PublicKey::deserialize(&contact_identity_key).map_err(to_js_error)?;
        let contact_key: IdentityKey = contact_key_pub.into();

        let fingerprint = Fingerprint::new(
            2,
            5200,
            local_uuid.as_bytes(),
            &local_identity_key,
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
    #[wasm_bindgen]
    pub fn verify_safety_number(
        &self,
        scanned: Vec<u8>,
        contact_uuid: String,
        contact_identity_key: Vec<u8>,
    ) -> Result<bool, JsValue> {
        let expected = self.generate_safety_number(contact_uuid, contact_identity_key)?;

        // Use constant-time comparison to prevent timing side-channels
        let valid = scanned.ct_eq(&expected.scannable);
        Ok(valid.into())
    }

    // ========================================================================
    // STORE SERIALISATION
    // ========================================================================

    /// Export a session.
    #[wasm_bindgen]
    pub async fn export_session(
        &self,
        contact_uuid: String,
        device_id: u32,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(contact_uuid, dev_id);

        match self
            .session_store
            .load_session(&address)
            .await
            .map_err(to_js_error)?
        {
            Some(session) => Ok(Some(session.serialize().map_err(to_js_error)?)),
            None => Ok(None),
        }
    }

    /// Import a session.
    #[wasm_bindgen]
    pub async fn import_session(
        &mut self,
        contact_uuid: String,
        device_id: u32,
        session_bytes: Vec<u8>,
    ) -> Result<(), JsValue> {
        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(contact_uuid, dev_id);
        let session = SessionRecord::deserialize(&session_bytes).map_err(to_js_error)?;
        self.session_store
            .store_session(&address, &session)
            .await
            .map_err(to_js_error)?;
        Ok(())
    }

    /// Import a PreKey.
    #[wasm_bindgen]
    pub async fn import_pre_key(&mut self, id: u32, record_bytes: Vec<u8>) -> Result<(), JsValue> {
        let record = PreKeyRecord::deserialize(&record_bytes).map_err(to_js_error)?;
        if u32::from(record.id().map_err(to_js_error)?) != id {
            return Err(JsValue::from_str("PreKey ID mismatch"));
        }
        self.prekey_store
            .save_pre_key(id.into(), &record)
            .await
            .map_err(to_js_error)?;
        Ok(())
    }

    /// Import a Signed PreKey.
    #[wasm_bindgen]
    pub async fn import_signed_pre_key(
        &mut self,
        id: u32,
        record_bytes: Vec<u8>,
    ) -> Result<(), JsValue> {
        let record = SignedPreKeyRecord::deserialize(&record_bytes).map_err(to_js_error)?;
        if u32::from(record.id().map_err(to_js_error)?) != id {
            return Err(JsValue::from_str("Signed PreKey ID mismatch"));
        }
        self.signed_prekey_store
            .save_signed_pre_key(id.into(), &record)
            .await
            .map_err(to_js_error)?;
        Ok(())
    }

    /// Import a Kyber PreKey.
    #[wasm_bindgen]
    pub async fn import_kyber_pre_key(
        &mut self,
        id: u32,
        record_bytes: Vec<u8>,
    ) -> Result<(), JsValue> {
        let record = KyberPreKeyRecord::deserialize(&record_bytes).map_err(to_js_error)?;
        if u32::from(record.id().map_err(to_js_error)?) != id {
            return Err(JsValue::from_str("Kyber PreKey ID mismatch"));
        }
        self.kyber_prekey_store
            .save_kyber_pre_key(id.into(), &record)
            .await
            .map_err(to_js_error)?;
        Ok(())
    }

    /// Export a sender key.
    #[wasm_bindgen]
    pub async fn export_sender_key(
        &mut self,
        group_member_uuid: String,
        device_id: u32,
        distribution_id: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, JsValue> {
        if distribution_id.len() != 16 {
            return Err(JsValue::from_str("distribution_id must be 16 bytes"));
        }

        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(group_member_uuid, dev_id);
        let dist_id = uuid::Uuid::from_slice(&distribution_id).map_err(to_js_error)?;

        match self
            .sender_key_store
            .load_sender_key(&address, dist_id)
            .await
            .map_err(to_js_error)?
        {
            Some(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            None => Ok(None),
        }
    }

    /// Import a sender key.
    #[wasm_bindgen]
    pub async fn import_sender_key(
        &mut self,
        group_member_uuid: String,
        device_id: u32,
        distribution_id: Vec<u8>,
        record_bytes: Vec<u8>,
    ) -> Result<(), JsValue> {
        if distribution_id.len() != 16 {
            return Err(JsValue::from_str("distribution_id must be 16 bytes"));
        }

        let dev_id = make_device_id(device_id)?;
        let address = ProtocolAddress::new(group_member_uuid, dev_id);
        let dist_id = uuid::Uuid::from_slice(&distribution_id).map_err(to_js_error)?;
        let record = SenderKeyRecord::deserialize(&record_bytes).map_err(to_js_error)?;

        self.sender_key_store
            .store_sender_key(&address, dist_id, &record)
            .await
            .map_err(to_js_error)?;

        Ok(())
    }

    /// Export a PreKey.
    #[wasm_bindgen]
    pub async fn export_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        match self.prekey_store.get_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            Err(_) => Ok(None),
        }
    }

    /// Export a Signed PreKey.
    #[wasm_bindgen]
    pub async fn export_signed_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        match self.signed_prekey_store.get_signed_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            Err(_) => Ok(None),
        }
    }

    /// Export a Kyber PreKey.
    #[wasm_bindgen]
    pub async fn export_kyber_pre_key(&self, id: u32) -> Result<Option<Vec<u8>>, JsValue> {
        match self.kyber_prekey_store.get_kyber_pre_key(id.into()).await {
            Ok(record) => Ok(Some(record.serialize().map_err(to_js_error)?)),
            Err(_) => Ok(None),
        }
    }
}

// ============================================================================
// SECTION 5: Utility Functions
// ============================================================================

/// Generate random bytes (returns error if CSPRNG fails).
#[wasm_bindgen]
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>, JsValue> {
    let mut bytes = vec![0u8; length];
    getrandom::fill(&mut bytes).map_err(|e| JsValue::from_str(&format!("CSPRNG error: {}", e)))?;
    Ok(bytes)
}

/// Generate a random attachment key (64 bytes).
#[wasm_bindgen]
pub fn generate_attachment_key() -> Result<Vec<u8>, JsValue> {
    generate_random_bytes(64)
}

/// Generate a random UUID v4.
#[wasm_bindgen]
pub fn generate_uuid() -> Vec<u8> {
    uuid::Uuid::new_v4().as_bytes().to_vec()
}

/// Convert UUID bytes to string.
#[wasm_bindgen]
pub fn uuid_to_string(bytes: &[u8]) -> Result<String, JsValue> {
    if bytes.len() != 16 {
        return Err(JsValue::from_str("UUID must be 16 bytes"));
    }
    let uuid = uuid::Uuid::from_slice(bytes).map_err(to_js_error)?;
    Ok(uuid.to_string())
}

/// Parse UUID string to bytes.
#[wasm_bindgen]
pub fn uuid_from_string(s: &str) -> Result<Vec<u8>, JsValue> {
    let uuid = uuid::Uuid::parse_str(s).map_err(to_js_error)?;
    Ok(uuid.as_bytes().to_vec())
}

// ============================================================================
// SECTION 6: Message Type Constants
// ============================================================================

/// Get message type for SignalMessage (normal message)
#[wasm_bindgen]
pub fn message_type_signal() -> u8 {
    2 // CiphertextMessageType::Whisper
}

/// Get message type for PreKeySignalMessage (first message establishing session)
#[wasm_bindgen]
pub fn message_type_pre_key() -> u8 {
    3 // CiphertextMessageType::PreKey
}

/// Get message type for SenderKeyMessage (group message)
#[wasm_bindgen]
pub fn message_type_sender_key() -> u8 {
    7 // CiphertextMessageType::SenderKey
}
