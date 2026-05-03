//! Test suite for the WebAssembly interface of libsignal-wasm.
//!
//! Run with:
//! wasm-pack test --headless --chrome
//! or
//! wasm-pack test --headless --firefox

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use signal_wasm::*;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn create_test_identity() -> (WasmIdentityKeyPair, u32) {
    let private_key = WasmPrivateKey::generate();
    let public_key = private_key.get_public_key().unwrap();
    let identity_key_pair = WasmIdentityKeyPair::new(&public_key, &private_key);
    let registration_id = generate_registration_id();
    (identity_key_pair, registration_id)
}

#[wasm_bindgen_test]
async fn test_identity_key_generation() {
    init();
    let private_key = WasmPrivateKey::generate();
    let public_key = private_key.get_public_key().expect("Failed to derive public key");

    assert!(!public_key.serialize().is_empty());

    let identity_key_pair = WasmIdentityKeyPair::new(&public_key, &private_key);
    assert_eq!(identity_key_pair.public_key().serialize(), public_key.serialize());
    assert_eq!(identity_key_pair.private_key().serialize(), private_key.serialize());

    // Round-trip serialization
    let serialized = identity_key_pair.serialize();
    let restored = WasmIdentityKeyPair::deserialize(&serialized).expect("Deserialization failed");
    assert_eq!(restored.public_key().serialize(), public_key.serialize());
    assert_eq!(restored.private_key().serialize(), private_key.serialize());
}

#[wasm_bindgen_test]
async fn test_protocol_address() {
    let addr = WasmProtocolAddress::new("alice_firebase_uid".to_string(), 1).unwrap();
    assert_eq!(addr.name(), "alice_firebase_uid");
    assert_eq!(addr.device_id(), 1);
}

#[wasm_bindgen_test]
async fn test_pre_key_generation() {
    let (_identity_key_pair, _registration_id) = create_test_identity();
    let mut prekey_store = WasmInMemPreKeyStore::new();

    let pre_keys = generate_pre_keys(1, 5, &mut prekey_store).await.expect("Failed to generate prekeys");
    assert_eq!(pre_keys.len(), 5);

    let first = &pre_keys[0];
    assert_eq!(first.id(), 1);
    assert!(!first.public_key().is_empty());
    assert!(!first.record().is_empty());

    // Store should contain the key
    let exported = prekey_store.export_pre_key(1).await.unwrap();
    assert!(exported.is_some());
}

#[wasm_bindgen_test]
async fn test_signed_pre_key_generation() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut signed_prekey_store = WasmInMemSignedPreKeyStore::new();

    let spk = generate_signed_pre_key(1, &identity_key_pair, &mut signed_prekey_store)
        .await
        .expect("Failed to generate signed prekey");

    assert_eq!(spk.id(), 1);
    assert!(!spk.signature().is_empty());
    assert!(!spk.public_key().is_empty());

    let exported = signed_prekey_store.export_signed_pre_key(1).await.unwrap();
    assert!(exported.is_some());
}

#[wasm_bindgen_test]
async fn test_kyber_pre_key_generation() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut kyber_prekey_store = WasmInMemKyberPreKeyStore::new();

    let kpk = generate_kyber_pre_key(1, &identity_key_pair, &mut kyber_prekey_store)
        .await
        .expect("Failed to generate kyber key");

    assert_eq!(kpk.id(), 1);
    assert!(!kpk.signature().is_empty());
    assert_eq!(kpk.public_key().len(), 1569); // Kyber1024 public key size

    let exported = kyber_prekey_store.export_kyber_pre_key(1).await.unwrap();
    assert!(exported.is_some());
}

#[wasm_bindgen_test]
async fn test_session_establishment_and_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // --- Alice setup ---
    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    // --- Bob setup ---
    let (bob_identity, bob_reg_id) = create_test_identity();
    let mut bob_session_store = WasmInMemSessionStore::new();
    let mut bob_identity_store = WasmInMemIdentityKeyStore::new(&bob_identity, bob_reg_id);
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // --- Bob Generates Keys ---
    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store).await.unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store).await.unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store).await.unwrap();

    let pk = &bob_pre_keys[0];
    let bob_identity_pk = WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

    // --- Alice Establishes Session ---
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap(),
        &bob_spk.signature(),
        Some(pk.id()),
        Some(pk.public_key()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Alice failed to process bundle");

    // --- Messaging ---
    let message_body = b"Hello WASM World!";

    // 1. Alice Encrypts
    let ciphertext = encrypt_message(
        message_body,
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Encryption failed");

    assert_eq!(ciphertext.message_type(), 3); // PreKeyMessage initially

    // 2. Bob Decrypts
    let decrypted = decrypt_message(
        &ciphertext.body(),
        ciphertext.message_type(),
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
        &mut bob_prekey_store,
        &bob_signed_prekey_store,
        &mut bob_kyber_prekey_store,
    )
    .await
    .expect("Decryption failed");

    assert_eq!(decrypted, message_body);

    // 3. Bob Replies (Standard Message)
    let reply_body = b"Ack!";
    let reply_cipher = encrypt_message(
        reply_body,
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
    )
    .await
    .expect("Reply encryption failed");

    assert_eq!(reply_cipher.message_type(), 2); // SignalMessage now

    let reply_decrypted = decrypt_message(
        &reply_cipher.body(),
        reply_cipher.message_type(),
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
        &mut WasmInMemPreKeyStore::new(),
        &WasmInMemSignedPreKeyStore::new(),
        &mut WasmInMemKyberPreKeyStore::new(),
    )
    .await
    .expect("Reply decryption failed");

    assert_eq!(reply_decrypted, reply_body);
}

#[wasm_bindgen_test]
async fn test_group_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";
    let group_id_str = hex::encode("000102030405060708090a0b0c0d0e0f");

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (_bob_identity, _bob_reg_id) = create_test_identity();
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();
    let _bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // 1. Alice Creates Group (SenderKeyDistribution)
    let dist_msg = create_sender_key_distribution(
        &alice_address,
        group_id_str.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    // 2. Bob Processes Distribution
    process_sender_key_distribution(
        &alice_address,
        &dist_msg,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Bob failed to process distribution");

    // 3. Alice Encrypts to Group
    let plaintext = b"Group Hello";
    let group_cipher = encrypt_group_message(
        &alice_address,
        group_id_str.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    // 4. Bob Decrypts
    let decrypted = decrypt_group_message(
        &alice_address,
        &group_cipher,
        &mut bob_sender_key_store,
    )
    .await
    .expect("Group decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_gv2_key_derivation() {
    let master_key = WasmGroupMasterKey::generate();
    assert_eq!(master_key.serialize().len(), 32);

    let group_id = master_key.derive_identifier();
    assert_eq!(group_id.serialize().len(), 32);

    let params = master_key.derive_secret_params();
    assert_eq!(params.serialize().len(), 32);

    let master_key_bytes = master_key.serialize();
    let master_key_2 = WasmGroupMasterKey::from_bytes(&master_key_bytes).unwrap();
    assert_eq!(master_key_2.serialize(), master_key_bytes);

    let group_id_2 = master_key_2.derive_identifier();
    assert_eq!(group_id_2.serialize(), group_id.serialize());
}

#[wasm_bindgen_test]
async fn test_persistence() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (bob_identity, bob_reg_id) = create_test_identity();
    let mut bob_session_store = WasmInMemSessionStore::new();
    let mut bob_identity_store = WasmInMemIdentityKeyStore::new(&bob_identity, bob_reg_id);
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // Bob generates keys
    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store).await.unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store).await.unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store).await.unwrap();

    let pk = &bob_pre_keys[0];
    let bob_identity_pk = WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

    // Alice establishes session
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap(),
        &bob_spk.signature(),
        Some(pk.id()),
        Some(pk.public_key()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Alice failed to process bundle");

    // Alice sends a message
    let cipher1 = encrypt_message(
        b"Msg 1",
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .unwrap();

    decrypt_message(
        &cipher1.body(),
        cipher1.message_type(),
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
        &mut bob_prekey_store,
        &bob_signed_prekey_store,
        &mut bob_kyber_prekey_store,
    )
    .await
    .unwrap();

    // EXPORT SESSION (Alice)
    let alice_session_data = alice_session_store
        .export_session(&bob_address)
        .await
        .expect("Failed to export session")
        .expect("Session not found");
    assert!(!alice_session_data.is_empty());

    // RESTORE: Create Alice 2
    let mut alice2_session_store = WasmInMemSessionStore::new();
    let mut alice2_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);

    // Import the session we exported
    alice2_session_store
        .import_session(&bob_address, &alice_session_data)
        .await
        .expect("Failed to import session");

    // Alice 2 sends message to Bob (Should work if session persisted)
    let cipher2 = encrypt_message(
        b"Msg 2",
        &bob_address,
        &alice_address,
        &mut alice2_session_store,
        &mut alice2_identity_store,
    )
    .await
    .unwrap();

    let decrypted2 = decrypt_message(
        &cipher2.body(),
        cipher2.message_type(),
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
        &mut WasmInMemPreKeyStore::new(),
        &WasmInMemSignedPreKeyStore::new(),
        &mut WasmInMemKyberPreKeyStore::new(),
    )
    .await
    .unwrap();

    assert_eq!(decrypted2, b"Msg 2");
}

#[wasm_bindgen_test]
async fn test_safety_numbers() {
    let (alice_identity, _) = create_test_identity();
    let (bob_identity, _) = create_test_identity();

    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // 1. Generate SN (Alice view of Bob)
    let sn_alice = generate_safety_number(
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect("Alice failed to gen SN");

    // 2. Generate SN (Bob view of Alice)
    let sn_bob = generate_safety_number(
        bob_uuid.to_string(),
        &bob_identity.public_key(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
    )
    .expect("Bob failed to gen SN");

    // 3. Compare (Should match)
    assert_eq!(sn_alice.displayable(), sn_bob.displayable());

    // 4. Verify Self-Consistency
    let valid = verify_safety_number(
        &sn_alice.scannable(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect("Verification failed");

    assert!(valid);
}

#[wasm_bindgen_test]
async fn test_registration_id_generation() {
    let reg_id = generate_registration_id();
    assert!(reg_id > 0);
    assert!(reg_id <= 16380);
}

#[wasm_bindgen_test]
async fn test_uuid_utilities() {
    let uuid_bytes = generate_uuid();
    assert_eq!(uuid_bytes.len(), 16);

    let uuid_str = uuid_to_string(&uuid_bytes).unwrap();
    let recovered = uuid_from_string(&uuid_str).unwrap();
    assert_eq!(recovered, uuid_bytes);
}
