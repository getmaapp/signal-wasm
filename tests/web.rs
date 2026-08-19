//! Test suite for the WebAssembly interface of libsignal-wasm.
//!
//! Run with:
//! wasm-pack test --headless --chrome
//! or
//! wasm-pack test --headless --firefox

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::montgomery::MontgomeryPoint;
use signal_wasm::*;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn create_test_identity() -> (WasmIdentityKeyPair, u32) {
    let private_key = WasmPrivateKey::generate();
    let public_key = private_key.get_public_key().unwrap();
    let identity_key_pair = WasmIdentityKeyPair::new(&public_key, &private_key);
    let registration_id = generate_registration_id();
    (identity_key_pair, registration_id)
}

/// Mint a caller-supplied distribution id (UUID string), as the TS domain does.
fn mint_distribution_id() -> String {
    uuid_to_string(&generate_uuid()).expect("Failed to mint distribution id")
}

/// Read the stable `code` property attached to a thrown JS error.
fn js_error_code(err: &JsValue) -> String {
    js_sys::Reflect::get(err, &JsValue::from_str("code"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

/// Read the `message` property of a thrown JS error.
fn js_error_message(err: &JsValue) -> String {
    js_sys::Reflect::get(err, &JsValue::from_str("message"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default()
}

#[wasm_bindgen_test]
async fn test_identity_key_generation() {
    init();
    let private_key = WasmPrivateKey::generate();
    let public_key = private_key
        .get_public_key()
        .expect("Failed to derive public key");

    assert!(!public_key.serialize().is_empty());

    let identity_key_pair = WasmIdentityKeyPair::new(&public_key, &private_key);
    assert_eq!(
        identity_key_pair.public_key().serialize(),
        public_key.serialize()
    );
    assert_eq!(
        identity_key_pair.private_key().serialize(),
        private_key.serialize()
    );

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

    let pre_keys = generate_pre_keys(1, 5, &mut prekey_store)
        .await
        .expect("Failed to generate prekeys");
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
    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store)
        .await
        .unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .unwrap();

    let pk = &bob_pre_keys[0];
    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

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

    assert_eq!(decrypted.plaintext(), message_body);

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

    assert_eq!(reply_decrypted.plaintext(), reply_body);
    // A Whisper (non-prekey) decrypt consumes nothing.
    assert!(reply_decrypted.kyber_pre_key_id().is_none());
    assert!(reply_decrypted.signed_pre_key_id().is_none());
    assert!(reply_decrypted.one_time_pre_key_id().is_none());
}

#[wasm_bindgen_test]
async fn test_delete_session_removes_record() {
    let mut f = establish_prekey_session(true).await;

    assert!(
        f.alice_session_store
            .has_session(&f.bob_address)
            .await
            .expect("has_session failed"),
        "session should exist after processing bundle"
    );

    let removed = f
        .alice_session_store
        .delete_session(&f.bob_address)
        .await
        .expect("delete_session failed");
    assert!(removed, "delete_session should report a removed record");

    assert!(
        !f.alice_session_store
            .has_session(&f.bob_address)
            .await
            .expect("has_session failed after delete"),
        "session should be gone after delete"
    );
}

#[wasm_bindgen_test]
async fn test_delete_session_missing_returns_false() {
    let mut session_store = WasmInMemSessionStore::new();
    let address = WasmProtocolAddress::new("nobody".to_string(), 1).unwrap();

    let removed = session_store
        .delete_session(&address)
        .await
        .expect("delete_session failed");
    assert!(
        !removed,
        "delete_session on a missing address must return false"
    );
}

#[wasm_bindgen_test]
async fn test_delete_then_reestablish_session_round_trip() {
    let mut f = establish_prekey_session(true).await;

    // Roll back the freshly created session.
    let removed = f
        .alice_session_store
        .delete_session(&f.bob_address)
        .await
        .expect("delete_session failed");
    assert!(removed, "delete_session should report a removed record");

    // Re-establish with a fresh bundle (new prekey material).
    let bob_pre_keys_2 = generate_pre_keys(2, 1, &mut f.bob_prekey_store)
        .await
        .expect("Failed to generate second prekey batch");
    let bob_spk_2 = generate_signed_pre_key(2, &f.bob_identity, &mut f.bob_signed_prekey_store)
        .await
        .expect("Failed to generate second signed prekey");
    let bob_kpk_2 = generate_kyber_pre_key(2, &f.bob_identity, &mut f.bob_kyber_prekey_store)
        .await
        .expect("Failed to generate second kyber prekey");

    let bob_identity_pk =
        WasmPublicKey::deserialize(&f.bob_identity.public_key().serialize()).unwrap();

    process_pre_key_bundle(
        &f.bob_address,
        &f.alice_address,
        f.bob_reg_id,
        &bob_identity_pk,
        bob_spk_2.id(),
        &WasmPublicKey::deserialize(&bob_spk_2.public_key()).unwrap(),
        &bob_spk_2.signature(),
        Some(bob_pre_keys_2[0].id()),
        Some(bob_pre_keys_2[0].public_key()),
        bob_kpk_2.id(),
        &bob_kpk_2.public_key(),
        &bob_kpk_2.signature(),
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("Re-establishment bundle failed");

    // Round-trip after rollback + re-establishment.
    let message = b"after rollback";
    let ciphertext = encrypt_message(
        message,
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("Encrypt after re-establish failed");

    let decrypted = decrypt_message(
        &ciphertext.body(),
        ciphertext.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
        &mut f.bob_prekey_store,
        &f.bob_signed_prekey_store,
        &mut f.bob_kyber_prekey_store,
    )
    .await
    .expect("Decrypt after re-establish failed");

    assert_eq!(decrypted.plaintext(), message);
}

#[wasm_bindgen_test]
async fn test_session_remote_registration_id_missing_record() {
    let session_store = WasmInMemSessionStore::new();
    let address = WasmProtocolAddress::new("nobody".to_string(), 1).unwrap();

    let id = session_store
        .session_remote_registration_id(&address)
        .await
        .expect("session_remote_registration_id failed");
    assert!(id.is_none(), "missing record must return None");
}

#[wasm_bindgen_test]
async fn test_session_remote_registration_id_established_session() {
    let f = establish_prekey_session(true).await;

    let id = f
        .alice_session_store
        .session_remote_registration_id(&f.bob_address)
        .await
        .expect("session_remote_registration_id failed");
    assert_eq!(
        id,
        Some(f.bob_reg_id),
        "established session must expose Bob's registration id"
    );
}

#[wasm_bindgen_test]
async fn test_session_remote_registration_id_archived_returns_none() {
    let mut f = establish_prekey_session(true).await;

    let id_before = f
        .alice_session_store
        .session_remote_registration_id(&f.bob_address)
        .await
        .expect("session_remote_registration_id failed before archive");
    assert!(id_before.is_some(), "current session should carry an id");

    f.alice_session_store
        .archive_session(&f.bob_address)
        .await
        .expect("archive_session failed");

    let id_after = f
        .alice_session_store
        .session_remote_registration_id(&f.bob_address)
        .await
        .expect("session_remote_registration_id failed after archive");
    assert!(
        id_after.is_none(),
        "archived record with no current state must return None"
    );
}

#[wasm_bindgen_test]
async fn test_session_remote_registration_id_refreshed_after_re_register() {
    let mut f = establish_prekey_session(true).await;

    f.alice_session_store
        .archive_session(&f.bob_address)
        .await
        .expect("archive_session failed");

    // Bob re-registers with a new registration id and fresh keys.
    let bob_reg_id_2 = generate_registration_id();
    let bob_pre_keys_2 = generate_pre_keys(2, 1, &mut f.bob_prekey_store)
        .await
        .expect("Failed to generate second prekey batch");
    let bob_spk_2 = generate_signed_pre_key(2, &f.bob_identity, &mut f.bob_signed_prekey_store)
        .await
        .expect("Failed to generate second signed prekey");
    let bob_kpk_2 = generate_kyber_pre_key(2, &f.bob_identity, &mut f.bob_kyber_prekey_store)
        .await
        .expect("Failed to generate second kyber prekey");

    let bob_identity_pk =
        WasmPublicKey::deserialize(&f.bob_identity.public_key().serialize()).unwrap();

    process_pre_key_bundle(
        &f.bob_address,
        &f.alice_address,
        bob_reg_id_2,
        &bob_identity_pk,
        bob_spk_2.id(),
        &WasmPublicKey::deserialize(&bob_spk_2.public_key()).unwrap(),
        &bob_spk_2.signature(),
        Some(bob_pre_keys_2[0].id()),
        Some(bob_pre_keys_2[0].public_key()),
        bob_kpk_2.id(),
        &bob_kpk_2.public_key(),
        &bob_kpk_2.signature(),
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("Re-establishment bundle failed");

    let id = f
        .alice_session_store
        .session_remote_registration_id(&f.bob_address)
        .await
        .expect("session_remote_registration_id failed after re-register");
    assert_eq!(
        id,
        Some(bob_reg_id_2),
        "fresh bundle over archived record must expose the new registration id"
    );
}

#[wasm_bindgen_test]
async fn test_group_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";
    // Caller-minted distribution id (must be a UUID string since 0.4.0).
    let distribution_id = uuid_to_string(&generate_uuid()).expect("Failed to mint distribution id");

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (_bob_identity, _bob_reg_id) = create_test_identity();
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();
    let _bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    // 1. Alice Creates Group (SenderKeyDistribution)
    let dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    // 2. Bob Processes Distribution
    process_sender_key_distribution(&alice_address, &dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process distribution");

    // 3. Alice Encrypts to Group
    let plaintext = b"Group Hello";
    let group_cipher = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    // 4. Bob Decrypts
    let decrypted = decrypt_group_message(&alice_address, &group_cipher, &mut bob_sender_key_store)
        .await
        .expect("Group decryption failed");

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_group_roundtrip_caller_minted_distribution_id() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    // Caller-minted distribution id, threaded end-to-end.
    let distribution_id = mint_distribution_id();

    // 1. Alice creates the distribution under the caller-minted id.
    create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    // 2. Export the record and hydrate a fresh store (persistence path).
    let exported = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export sender key")
        .expect("Sender key missing after create");

    let mut restored_sender_key_store = WasmInMemSenderKeyStore::new();
    restored_sender_key_store
        .import_sender_key(&alice_address, distribution_id.clone(), &exported)
        .await
        .expect("Failed to import sender key");

    // 3. Encrypt on Alice's store, decrypt on the restored store.
    let plaintext = b"Hydrated group round-trip";
    let ciphertext = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    let decrypted =
        decrypt_group_message(&alice_address, &ciphertext, &mut restored_sender_key_store)
            .await
            .expect("Group decryption on restored store failed");

    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_group_decrypt_wrong_distribution_id_fails() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();

    let known_distribution_id = mint_distribution_id();
    let unknown_distribution_id = mint_distribution_id();

    // Bob knows only `known_distribution_id`.
    let dist_msg = create_sender_key_distribution(
        &alice_address,
        known_distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");
    process_sender_key_distribution(&alice_address, &dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process distribution");

    // Alice encrypts under a different distribution id; the ciphertext
    // therefore embeds an id Bob has no record for.
    create_sender_key_distribution(
        &alice_address,
        unknown_distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create second distribution");
    let ciphertext = encrypt_group_message(
        &alice_address,
        unknown_distribution_id.clone(),
        b"Wrong id",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    let err = decrypt_group_message(&alice_address, &ciphertext, &mut bob_sender_key_store)
        .await
        .expect_err("Decryption with the wrong distribution id must fail");

    assert_eq!(js_error_code(&err), "NoSenderKeyState");
    assert!(js_error_message(&err).starts_with("SignalError:"));
}

#[wasm_bindgen_test]
async fn test_remove_sender_key_rotates_key_material() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let distribution_id = mint_distribution_id();

    // 1. Create and export the original key material.
    create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");
    let original = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export sender key")
        .expect("Sender key missing after create");

    // 2. Remove: export must then return None, and a second remove is a no-op.
    let removed = alice_sender_key_store
        .remove_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to remove sender key");
    assert!(removed, "remove_sender_key should report a removed record");

    let after_remove = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export after remove");
    assert!(after_remove.is_none(), "export after remove must be None");

    let removed_again = alice_sender_key_store
        .remove_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Second remove failed");
    assert!(
        !removed_again,
        "second remove_sender_key should report no record"
    );

    // 3. Re-create under the same distribution id: fresh key material.
    let new_dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to re-create distribution");
    let rotated = alice_sender_key_store
        .export_sender_key(&alice_address, distribution_id.clone())
        .await
        .expect("Failed to export rotated sender key")
        .expect("Sender key missing after re-create");

    assert_ne!(
        original, rotated,
        "remove + re-create must produce fresh key material"
    );

    // 4. The rotated distribution is fully functional.
    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();
    process_sender_key_distribution(&alice_address, &new_dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process rotated distribution");

    let plaintext = b"Post-rotation message";
    let ciphertext = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        plaintext,
        &mut alice_sender_key_store,
    )
    .await
    .expect("Post-rotation encryption failed");
    let decrypted = decrypt_group_message(&alice_address, &ciphertext, &mut bob_sender_key_store)
        .await
        .expect("Post-rotation decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
async fn test_group_decrypt_unknown_distribution_error_code() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let distribution_id = mint_distribution_id();

    create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");
    let ciphertext = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        b"Unknown to Bob",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encryption failed");

    // Bob never processed any SKDM, so the record lookup misses.
    let mut fresh_sender_key_store = WasmInMemSenderKeyStore::new();
    let err = decrypt_group_message(&alice_address, &ciphertext, &mut fresh_sender_key_store)
        .await
        .expect_err("Decryption with an unknown distribution id must fail");

    assert_eq!(js_error_code(&err), "NoSenderKeyState");
    assert!(js_error_message(&err).starts_with("SignalError:"));
}

#[wasm_bindgen_test]
async fn test_group_rejects_non_uuid_distribution_id() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();
    let mut sender_key_store = WasmInMemSenderKeyStore::new();

    // The pre-0.4.0 hash path is gone: arbitrary group strings are rejected.
    let err = create_sender_key_distribution(
        &alice_address,
        "team:general-chat-1".to_string(),
        &mut sender_key_store,
    )
    .await
    .expect_err("Non-UUID distribution id must be rejected");
    assert_eq!(js_error_code(&err), "Generic");

    let err = encrypt_group_message(
        &alice_address,
        "not-a-uuid".to_string(),
        b"x",
        &mut sender_key_store,
    )
    .await
    .expect_err("Non-UUID distribution id must be rejected");
    assert_eq!(js_error_code(&err), "Generic");
}

#[wasm_bindgen_test]
async fn test_gv2_key_derivation() {
    let master_key = WasmGroupMasterKey::generate();
    assert_eq!(master_key.serialize().len(), 32);

    let group_id = master_key.derive_identifier();
    assert_eq!(group_id.serialize().len(), 32);

    let params = master_key.derive_secret_params();
    assert_eq!(params.serialize_master_key().len(), 32);

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
    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store)
        .await
        .unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .unwrap();

    let pk = &bob_pre_keys[0];
    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

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

    assert_eq!(decrypted2.plaintext(), b"Msg 2");
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
    assert!(reg_id <= 16383);
}

#[wasm_bindgen_test]
async fn test_uuid_utilities() {
    let uuid_bytes = generate_uuid();
    assert_eq!(uuid_bytes.len(), 16);

    let uuid_str = uuid_to_string(&uuid_bytes).unwrap();
    let recovered = uuid_from_string(&uuid_str).unwrap();
    assert_eq!(recovered, uuid_bytes);
}

#[wasm_bindgen_test]
async fn test_scannable_fingerprint_cross_perspective() {
    let (alice_identity, _) = create_test_identity();
    let (bob_identity, _) = create_test_identity();

    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // Bob's QR code: Bob's view (local=Bob, remote=Alice).
    let sn_bob = generate_safety_number(
        bob_uuid.to_string(),
        &bob_identity.public_key(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
    )
    .expect("Bob failed to gen SN");

    // Positive: Alice scans Bob's QR and verifies against HER view.
    let valid = verify_scannable_fingerprint(
        &sn_bob.scannable(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect("Cross-perspective verify failed");
    assert!(valid, "A scanning B's QR must verify");

    // Negative: tampered payload must not verify.
    let mut tampered = sn_bob.scannable();
    let n = tampered.len();
    tampered[n - 1] ^= 0x01;
    let result = verify_scannable_fingerprint(
        &tampered,
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    );
    match result {
        Ok(v) => assert!(!v, "Tampered payload must not verify"),
        Err(e) => assert_eq!(js_error_code(&e), "FingerprintParsingError"),
    }

    // Negative: wrong version throws FingerprintVersionMismatch.
    // CombinedFingerprints protobuf: field 1 (version) is a varint, so a v2
    // encoding starts with 0x08 0x02; rewriting the version byte to 1 gives a
    // well-formed payload with a mismatched version.
    let mut wrong_version = sn_bob.scannable();
    assert_eq!(
        &wrong_version[..2],
        &[0x08, 0x02],
        "expected v2 varint header"
    );
    wrong_version[1] = 0x01;
    let err = verify_scannable_fingerprint(
        &wrong_version,
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect_err("Version mismatch must throw");
    assert_eq!(js_error_code(&err), "FingerprintVersionMismatch");

    // Negative: garbage payload throws FingerprintParsingError.
    let err = verify_scannable_fingerprint(
        &[0xFF, 0xFF, 0xFF],
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        bob_uuid.to_string(),
        &bob_identity.public_key(),
    )
    .expect_err("Garbage payload must throw");
    assert_eq!(js_error_code(&err), "FingerprintParsingError");

    // Negative: swapped identities (Alice verifies against the WRONG contact)
    // must not verify.
    let (mallory_identity, _) = create_test_identity();
    let valid = verify_scannable_fingerprint(
        &sn_bob.scannable(),
        alice_uuid.to_string(),
        &alice_identity.public_key(),
        "00000000-0000-0000-0000-00000000000C".to_string(),
        &mallory_identity.public_key(),
    )
    .expect("verify should return false, not throw");
    assert!(!valid, "Wrong contact identity must not verify");
}

#[wasm_bindgen_test]
async fn test_identity_proof_of_possession() {
    let (identity, _) = create_test_identity();
    let message = b"re-key authorisation challenge 0123456789";

    // Round-trip.
    let signature =
        sign_with_identity_key(&identity.private_key(), message).expect("signing failed");
    assert_eq!(signature.len(), 64, "XEdDSA signature is 64 bytes");
    assert!(verify_identity_signature(
        &identity.public_key(),
        message,
        &signature
    ));

    // Negative: wrong message.
    assert!(!verify_identity_signature(
        &identity.public_key(),
        b"different challenge",
        &signature
    ));

    // Negative: wrong key.
    let (other_identity, _) = create_test_identity();
    assert!(!verify_identity_signature(
        &other_identity.public_key(),
        message,
        &signature
    ));

    // Negative: malformed signature must return false, not throw.
    assert!(!verify_identity_signature(
        &identity.public_key(),
        message,
        &[0u8; 8]
    ));
}

#[wasm_bindgen_test]
async fn test_group_secret_params_master_key_getter() {
    // The getter is explicitly the 32-byte master key, and it must agree
    // with the master key it was derived from.
    let master_key = WasmGroupMasterKey::generate();
    let params = master_key.derive_secret_params();
    let exported = params.serialize_master_key();
    assert_eq!(exported.len(), 32);
    assert_eq!(exported, master_key.serialize());
}

// ============================================================================
// 0.6.0: consumed pre-key surfacing + durable kyber anti-replay
// ============================================================================

/// Shared Alice→Bob fixture. Bob has signed prekey 1 and kyber prekey 1, and
/// optionally one-time EC prekey 1; Alice has processed Bob's bundle.
struct PreKeyFixture {
    alice_address: WasmProtocolAddress,
    bob_address: WasmProtocolAddress,
    alice_session_store: WasmInMemSessionStore,
    alice_identity_store: WasmInMemIdentityKeyStore,
    bob_identity: WasmIdentityKeyPair,
    bob_reg_id: u32,
    bob_session_store: WasmInMemSessionStore,
    bob_identity_store: WasmInMemIdentityKeyStore,
    bob_prekey_store: WasmInMemPreKeyStore,
    bob_signed_prekey_store: WasmInMemSignedPreKeyStore,
    bob_kyber_prekey_store: WasmInMemKyberPreKeyStore,
}

async fn establish_prekey_session(with_one_time_ec: bool) -> PreKeyFixture {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    let (alice_identity, alice_reg_id) = create_test_identity();
    let alice_session_store = WasmInMemSessionStore::new();
    let alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (bob_identity, bob_reg_id) = create_test_identity();
    let bob_session_store = WasmInMemSessionStore::new();
    let bob_identity_store = WasmInMemIdentityKeyStore::new(&bob_identity, bob_reg_id);
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .unwrap();

    let (prekey_id, prekey) = if with_one_time_ec {
        let keys = generate_pre_keys(1, 1, &mut bob_prekey_store)
            .await
            .unwrap();
        (Some(keys[0].id()), Some(keys[0].public_key()))
    } else {
        (None, None)
    };

    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

    let mut fixture = PreKeyFixture {
        alice_address,
        bob_address,
        alice_session_store,
        alice_identity_store,
        bob_identity,
        bob_reg_id,
        bob_session_store,
        bob_identity_store,
        bob_prekey_store,
        bob_signed_prekey_store,
        bob_kyber_prekey_store,
    };

    process_pre_key_bundle(
        &fixture.bob_address,
        &fixture.alice_address,
        fixture.bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap(),
        &bob_spk.signature(),
        prekey_id,
        prekey,
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut fixture.alice_session_store,
        &mut fixture.alice_identity_store,
    )
    .await
    .expect("Alice failed to process bundle");

    fixture
}

/// Alice's first message to Bob (a PreKeySignalMessage) for fixture `f`.
async fn alice_first_message(f: &mut PreKeyFixture, body: &[u8]) -> WasmCiphertext {
    let ct = encrypt_message(
        body,
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("Encryption failed");
    assert_eq!(ct.message_type(), 3); // PreKeyMessage
    ct
}

/// Bob decrypts Alice's message using his fixture stores.
async fn bob_decrypts(
    f: &mut PreKeyFixture,
    ct: &WasmCiphertext,
) -> Result<WasmDecryptResult, JsValue> {
    decrypt_message(
        &ct.body(),
        ct.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
        &mut f.bob_prekey_store,
        &f.bob_signed_prekey_store,
        &mut f.bob_kyber_prekey_store,
    )
    .await
}

// ----------------------------------------------------------------------------
// Protobuf helpers for tampering with a PreKeySignalMessage's `base_key`
// (field 2, length-delimited bytes) without a full protobuf dependency.
// ----------------------------------------------------------------------------

fn read_varint(buf: &[u8], pos: &mut usize) -> u64 {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        assert!(*pos < buf.len(), "truncated varint");
        let byte = buf[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return result;
        }
        shift += 7;
        assert!(shift <= 63, "varint overflow");
    }
}

fn write_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(5);
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

/// Return the payload of the length-delimited field `field_number`, or `None`
/// if it is absent.
fn protobuf_bytes_field(buf: &[u8], field_number: u32) -> Option<Vec<u8>> {
    let mut pos = 0;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos) as u32;
        let wire = tag & 7;
        let num = tag >> 3;
        match wire {
            0 => {
                read_varint(buf, &mut pos);
            }
            2 => {
                let len = read_varint(buf, &mut pos) as usize;
                assert!(
                    pos + len <= buf.len(),
                    "truncated length-delimited field"
                );
                let data = buf[pos..pos + len].to_vec();
                pos += len;
                if num == field_number {
                    return Some(data);
                }
            }
            _ => panic!("unexpected protobuf wire type {}", wire),
        }
    }
    None
}

/// Re-encode `buf` with the payload of length-delimited field `field_number`
/// replaced by `new_payload`. All other fields are copied unchanged.
fn replace_protobuf_bytes_field(buf: &[u8], field_number: u32, new_payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(buf.len());
    let mut pos = 0;
    while pos < buf.len() {
        let tag_start = pos;
        let tag = read_varint(buf, &mut pos) as u32;
        let wire = tag & 7;
        let num = tag >> 3;
        match wire {
            0 => {
                read_varint(buf, &mut pos);
                out.extend_from_slice(&buf[tag_start..pos]);
            }
            2 => {
                let len = read_varint(buf, &mut pos) as usize;
                let end = pos + len;
                assert!(
                    end <= buf.len(),
                    "truncated length-delimited field"
                );
                if num == field_number {
                    out.extend_from_slice(&write_varint(tag as u64));
                    out.extend_from_slice(&write_varint(new_payload.len() as u64));
                    out.extend_from_slice(new_payload);
                } else {
                    out.extend_from_slice(&buf[tag_start..end]);
                }
                pos = end;
            }
            _ => panic!("unexpected protobuf wire type {}", wire),
        }
    }
    out
}

// ----------------------------------------------------------------------------
// PQXDH base-key boundary parity: libsignal @ b5121d0 rejects malformed
// ephemeral base keys during Bob's session initialisation. Our wasm boundary
// generates Alice's base key inside `process_pre_key_bundle`, so the malformed
// key is injected by tampering with the `base_key` field of the resulting
// PreKeySignalMessage and driving `decrypt_message`.
// ----------------------------------------------------------------------------

/// Mirrors `test_bob_rejects_highbit_basekey`
/// (`rust/protocol/tests/ratchet.rs:151-220` @ `b5121d0`).
#[wasm_bindgen_test]
async fn test_bob_rejects_highbit_basekey() {
    let mut f = establish_prekey_session(false).await;
    let ct = alice_first_message(&mut f, b"high-bit base key").await;

    // Skip the leading ciphertext-version byte; the remainder is the protobuf
    // PreKeySignalMessage.
    let proto_body = &ct.body()[1..];

    let mut base_key = protobuf_bytes_field(proto_body, 2)
        .expect("PreKeySignalMessage must contain base_key");
    assert_eq!(base_key.len(), 33, "base_key is a type-5 public key");

    // Set the high bit of the Montgomery u-coordinate (the last raw byte after
    // the leading 0x05 key-type byte), which `PublicKey::is_canonical` rejects
    // in `scalar_is_in_range`.
    base_key[32] |= 0b1000_0000_u8;

    let mut tampered = vec![ct.body()[0]];
    tampered.extend_from_slice(&replace_protobuf_bytes_field(proto_body, 2, &base_key));

    let result = decrypt_message(
        &tampered,
        ct.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
        &mut f.bob_prekey_store,
        &f.bob_signed_prekey_store,
        &mut f.bob_kyber_prekey_store,
    )
    .await;
    assert!(result.is_err(), "high-bit base key must be rejected");
}

/// Mirrors `test_bob_rejects_torsioned_basekey`
/// (`rust/protocol/tests/ratchet.rs:84-150` @ `b5121d0`).
#[wasm_bindgen_test]
async fn test_bob_rejects_torsioned_basekey() {
    let mut f = establish_prekey_session(false).await;
    let ct = alice_first_message(&mut f, b"torsioned base key").await;

    // Skip the leading ciphertext-version byte; the remainder is the protobuf
    // PreKeySignalMessage.
    let proto_body = &ct.body()[1..];

    let base_key = protobuf_bytes_field(proto_body, 2)
        .expect("PreKeySignalMessage must contain base_key");
    assert_eq!(base_key.len(), 33, "base_key is a type-5 public key");

    let raw: [u8; 32] = base_key[1..].try_into().unwrap();
    let mont = MontgomeryPoint(raw);
    let ed = mont
        .to_edwards(0)
        .expect("valid base key maps to an Edwards point");
    let tweaked = ed + EIGHT_TORSION[1];
    let tweaked_mont = tweaked.to_montgomery();

    let mut tweaked_key = vec![0x05u8];
    tweaked_key.extend_from_slice(&tweaked_mont.to_bytes());

    let mut tampered = vec![ct.body()[0]];
    tampered.extend_from_slice(&replace_protobuf_bytes_field(proto_body, 2, &tweaked_key));

    let result = decrypt_message(
        &tampered,
        ct.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
        &mut f.bob_prekey_store,
        &f.bob_signed_prekey_store,
        &mut f.bob_kyber_prekey_store,
    )
    .await;
    assert!(
        result.is_err(),
        "torsioned/non-torsion-free base key must be rejected"
    );
}

#[wasm_bindgen_test]
async fn test_decrypt_reports_consumed_prekey_ids() {
    let mut f = establish_prekey_session(true).await;
    let ct = alice_first_message(&mut f, b"first").await;

    let result = bob_decrypts(&mut f, &ct).await.expect("Decryption failed");

    assert_eq!(result.plaintext(), b"first");
    // The prekey message consumed one-time EC prekey 1 and kyber prekey 1,
    // paired with signed prekey 1.
    assert_eq!(result.one_time_pre_key_id(), Some(1));
    assert_eq!(result.kyber_pre_key_id(), Some(1));
    assert_eq!(result.signed_pre_key_id(), Some(1));

    // The engine removed the one-time EC key itself; the kyber record remains
    // (one-time vs last-resort deletion is the TS layer's job, per the
    // KyberPreKeyStore trait contract).
    assert!(f
        .bob_prekey_store
        .export_pre_key(1)
        .await
        .unwrap()
        .is_none());
    assert!(f
        .bob_kyber_prekey_store
        .export_kyber_pre_key(1)
        .await
        .unwrap()
        .is_some());
}

#[wasm_bindgen_test]
async fn test_replayed_prekey_message_same_process_is_duplicated() {
    let mut f = establish_prekey_session(true).await;
    let ct = alice_first_message(&mut f, b"replay me").await;

    bob_decrypts(&mut f, &ct)
        .await
        .expect("First decryption failed");

    // Same-process replay: the session established from this base key is still
    // current, so the engine short-circuits before the kyber mark and the
    // inner message fails ratchet replay detection instead.
    let err = bob_decrypts(&mut f, &ct)
        .await
        .err()
        .expect("Replay must be rejected");
    assert_eq!(js_error_code(&err), "DuplicatedMessage");
}

#[wasm_bindgen_test]
async fn test_kyber_usage_export_import_roundtrip() {
    let mut f = establish_prekey_session(true).await;
    let ct = alice_first_message(&mut f, b"mark me").await;
    bob_decrypts(&mut f, &ct).await.expect("Decryption failed");

    let usage = f.bob_kyber_prekey_store.export_kyber_usage();
    // version (1) + count (4) + one 41-byte record
    assert_eq!(usage.len(), 46);
    assert_eq!(usage[0], 1);

    // Import into a fresh store; union semantics make re-import a no-op.
    let mut restored = WasmInMemKyberPreKeyStore::new();
    restored.import_kyber_usage(&usage).expect("Import failed");
    restored
        .import_kyber_usage(&usage)
        .expect("Re-import must be idempotent");
    assert_eq!(restored.export_kyber_usage().len(), 46);

    // Malformed exports are hard errors, never silent drops.
    assert!(restored.import_kyber_usage(&[]).is_err());
    assert!(restored.import_kyber_usage(&[2, 0, 0, 0, 0]).is_err()); // version
    assert!(restored.import_kyber_usage(&[1, 0, 0, 0, 1]).is_err()); // short payload
    let mut bad_key = vec![1u8, 0, 0, 0, 1];
    bad_key.extend_from_slice(&[0u8; 41]);
    assert!(restored.import_kyber_usage(&bad_key).is_err()); // invalid base key
}

/// A replayed PreKeySignalMessage against a live last-resort kyber key
/// must still be rejected after a restart — but only if the anti-replay memory
/// was persisted and re-imported.
#[wasm_bindgen_test]
async fn test_kyber_replay_rejected_across_restart() {
    // Last-resort-only bundle: no one-time EC key, mirroring the fallback
    // path where one-time keys are exhausted.
    let mut f = establish_prekey_session(false).await;
    let ct = alice_first_message(&mut f, b"last resort").await;

    let first = bob_decrypts(&mut f, &ct)
        .await
        .expect("First decryption failed");
    assert_eq!(first.plaintext(), b"last resort");
    assert_eq!(first.kyber_pre_key_id(), Some(1));
    assert_eq!(first.one_time_pre_key_id(), None); // no one-time EC key in play

    // What the TS layer persists: the kyber record, the signed prekey, and
    // the usage set.
    let kyber_record = f
        .bob_kyber_prekey_store
        .export_kyber_pre_key(1)
        .await
        .unwrap()
        .expect("Kyber record missing");
    let signed_record = f
        .bob_signed_prekey_store
        .export_signed_pre_key(1)
        .await
        .unwrap()
        .expect("Signed prekey missing");
    let usage = f.bob_kyber_prekey_store.export_kyber_usage();

    // Control — "restart" WITHOUT the usage import: the replay decapsulates
    // again. This is the pre-0.6.0 hole; if this ever fails, the fix test
    // below proves nothing.
    let mut vulnerable_kyber = WasmInMemKyberPreKeyStore::new();
    vulnerable_kyber
        .import_kyber_pre_key(1, &kyber_record)
        .await
        .unwrap();
    let mut control_signed = WasmInMemSignedPreKeyStore::new();
    control_signed
        .import_signed_pre_key(1, &signed_record)
        .await
        .unwrap();
    let replay = decrypt_message(
        &ct.body(),
        ct.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut WasmInMemSessionStore::new(),
        &mut WasmInMemIdentityKeyStore::new(&f.bob_identity, f.bob_reg_id),
        &mut WasmInMemPreKeyStore::new(),
        &control_signed,
        &mut vulnerable_kyber,
    )
    .await;
    assert!(
        replay.is_ok(),
        "control replay should succeed without usage import"
    );

    // The fix — "restart" WITH the usage import: the replay is rejected.
    let mut patched_kyber = WasmInMemKyberPreKeyStore::new();
    patched_kyber
        .import_kyber_pre_key(1, &kyber_record)
        .await
        .unwrap();
    patched_kyber
        .import_kyber_usage(&usage)
        .expect("Usage import failed");
    let mut patched_signed = WasmInMemSignedPreKeyStore::new();
    patched_signed
        .import_signed_pre_key(1, &signed_record)
        .await
        .unwrap();

    let err = decrypt_message(
        &ct.body(),
        ct.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut WasmInMemSessionStore::new(),
        &mut WasmInMemIdentityKeyStore::new(&f.bob_identity, f.bob_reg_id),
        &mut WasmInMemPreKeyStore::new(),
        &patched_signed,
        &mut patched_kyber,
    )
    .await
    .err()
    .expect("Replay with persisted usage must be rejected");
    assert_eq!(js_error_code(&err), "ReusedKyberBaseKey");
}

// ============================================================================
// Canonical parity coverage: ported from libsignal @ b5121d0.
//
// Mappings to canonical tests are documented on each test. Where the wasm API
// cannot expose an internal value (e.g. alice_base_key), the assertion is
// translated to an observable public-API equivalent and the canonical source is
// still cited.
// ============================================================================

/// Bob encrypts a reply to Alice on his fixture session.
async fn bob_encrypts(f: &mut PreKeyFixture, body: &[u8]) -> WasmCiphertext {
    let ct = encrypt_message(
        body,
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
    )
    .await
    .expect("Bob reply encryption failed");
    ct
}

/// Alice decrypts a message from Bob on her fixture session.
async fn alice_decrypts(
    f: &mut PreKeyFixture,
    ct: &WasmCiphertext,
) -> Result<WasmDecryptResult, JsValue> {
    decrypt_message(
        &ct.body(),
        ct.message_type(),
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
        &mut WasmInMemPreKeyStore::new(),
        &WasmInMemSignedPreKeyStore::new(),
        &mut WasmInMemKyberPreKeyStore::new(),
    )
    .await
}

// ----------------------------------------------------------------------------
// (a) 1:1 session parity
// ----------------------------------------------------------------------------

/// Mirrors `run_session_interaction` (rust/protocol/tests/session.rs:2610),
/// driven by `test_basic_session` (session.rs:791).
///
/// Out-of-order message delivery still decrypts correctly after an initial
/// bidirectional exchange.
#[wasm_bindgen_test]
async fn test_session_out_of_order_delivery() {
    let mut f = establish_prekey_session(false).await;

    // Initial bidirectional exchange to give both sides a sender chain.
    let first = alice_first_message(&mut f, b"first").await;
    bob_decrypts(&mut f, &first)
        .await
        .expect("Bob failed to decrypt first");

    let reply = bob_encrypts(&mut f, b"reply").await;
    assert_eq!(reply.message_type(), 2); // Whisper
    alice_decrypts(&mut f, &reply)
        .await
        .expect("Alice failed to decrypt reply");

    const ALICE_MESSAGE_COUNT: usize = 50;
    const BOB_MESSAGE_COUNT: usize = 50;

    let mut alice_ciphertexts = Vec::with_capacity(ALICE_MESSAGE_COUNT);
    for i in 0..ALICE_MESSAGE_COUNT {
        let body = format!("Alice out-of-order {i}");
        let ct = encrypt_message(
            body.as_bytes(),
            &f.bob_address,
            &f.alice_address,
            &mut f.alice_session_store,
            &mut f.alice_identity_store,
        )
        .await
        .expect("Alice encrypt failed");
        alice_ciphertexts.push((body, ct));
    }

    // Decrypt in reverse order (deterministic out-of-order delivery).
    for i in (0..ALICE_MESSAGE_COUNT).rev() {
        let decrypted = bob_decrypts(&mut f, &alice_ciphertexts[i].1)
            .await
            .expect("Bob failed to decrypt out-of-order Alice message");
        assert_eq!(decrypted.plaintext(), alice_ciphertexts[i].0.as_bytes());
    }

    let mut bob_ciphertexts = Vec::with_capacity(BOB_MESSAGE_COUNT);
    for i in 0..BOB_MESSAGE_COUNT {
        let body = format!("Bob out-of-order {i}");
        let ct = encrypt_message(
            body.as_bytes(),
            &f.alice_address,
            &f.bob_address,
            &mut f.bob_session_store,
            &mut f.bob_identity_store,
        )
        .await
        .expect("Bob encrypt failed");
        bob_ciphertexts.push((body, ct));
    }

    for i in (0..BOB_MESSAGE_COUNT).rev() {
        let decrypted = alice_decrypts(&mut f, &bob_ciphertexts[i].1)
            .await
            .expect("Alice failed to decrypt out-of-order Bob message");
        assert_eq!(decrypted.plaintext(), bob_ciphertexts[i].0.as_bytes());
    }
}

/// Mirrors `test_message_key_limits` (rust/protocol/tests/session.rs:798).
///
/// A 2000-key skip works: messages up to `MAX_MESSAGE_KEYS` ahead of the last
/// decrypted message can still be decrypted. An older message that falls out of
/// the skipped-key window is rejected as a duplicate.
#[wasm_bindgen_test]
async fn test_session_skipped_key_window() {
    let mut f = establish_prekey_session(false).await;

    const MAX_MESSAGE_KEYS: usize = 2000;
    const TOO_MANY_MESSAGES: usize = MAX_MESSAGE_KEYS + 300;

    let mut inflight = Vec::with_capacity(TOO_MANY_MESSAGES);
    for i in 0..TOO_MANY_MESSAGES {
        let body = format!("It's over {i}");
        let ct = encrypt_message(
            body.as_bytes(),
            &f.bob_address,
            &f.alice_address,
            &mut f.alice_session_store,
            &mut f.alice_identity_store,
        )
        .await
        .expect("Alice encrypt failed");
        inflight.push(ct);
    }

    let decrypted_1000 = bob_decrypts(&mut f, &inflight[1000])
        .await
        .expect("Message at index 1000 should decrypt");
    assert_eq!(
        decrypted_1000.plaintext(),
        format!("It's over 1000").as_bytes()
    );

    let decrypted_last = bob_decrypts(&mut f, &inflight[TOO_MANY_MESSAGES - 1])
        .await
        .expect("Last message should decrypt");
    assert_eq!(
        decrypted_last.plaintext(),
        format!("It's over {}", TOO_MANY_MESSAGES - 1).as_bytes()
    );

    let err = match bob_decrypts(&mut f, &inflight[5]).await {
        Ok(_) => panic!("Message older than the skipped-key window must fail"),
        Err(e) => e,
    };
    assert_eq!(js_error_code(&err), "DuplicatedMessage");
}

/// Mirrors `test_chain_jump_over_limit` (rust/protocol/tests/session.rs:248).
///
/// The receiver rejects a message whose chain counter is more than
/// `MAX_FORWARD_JUMPS` (25_000) ahead of the last received counter.
#[wasm_bindgen_test]
async fn test_session_chain_jump_over_limit() {
    let mut f = establish_prekey_session(false).await;

    const MAX_FORWARD_JUMPS: usize = 25_000;

    for _ in 0..(MAX_FORWARD_JUMPS + 1) {
        let _ct = encrypt_message(
            b"Yet another message for you",
            &f.bob_address,
            &f.alice_address,
            &mut f.alice_session_store,
            &mut f.alice_identity_store,
        )
        .await
        .expect("Alice encrypt failed");
    }

    let too_far = encrypt_message(
        b"Now you have gone too far",
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("Alice encrypt failed");

    match bob_decrypts(&mut f, &too_far).await {
        Ok(_) => panic!("A >25k chain jump must be rejected"),
        Err(_) => {}
    }
}

// ----------------------------------------------------------------------------
// (b) Group sender-key parity
// ----------------------------------------------------------------------------

/// Mirrors `group_basic_ratchet` (rust/protocol/tests/groups.rs:917).
///
/// Replay is rejected; out-of-order messages inside the skipped-key window are
/// accepted.
#[wasm_bindgen_test]
async fn test_group_replay_and_out_of_order_within_window() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let distribution_id = mint_distribution_id();

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();

    let dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    process_sender_key_distribution(&alice_address, &dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process distribution");

    let ct1 = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        b"swim camp",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encrypt 1 failed");
    let ct2 = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        b"robot camp",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encrypt 2 failed");
    let ct3 = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        b"ninja camp",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encrypt 3 failed");

    let pt1 = decrypt_group_message(&alice_address, &ct1, &mut bob_sender_key_store)
        .await
        .expect("Group decrypt 1 failed");
    assert_eq!(pt1, b"swim camp");

    let err = decrypt_group_message(&alice_address, &ct1, &mut bob_sender_key_store)
        .await
        .expect_err("Replay of message 1 must be rejected");
    assert_eq!(js_error_code(&err), "DuplicatedMessage");

    let pt3 = decrypt_group_message(&alice_address, &ct3, &mut bob_sender_key_store)
        .await
        .expect("Group decrypt 3 failed");
    assert_eq!(pt3, b"ninja camp");

    let pt2 = decrypt_group_message(&alice_address, &ct2, &mut bob_sender_key_store)
        .await
        .expect("Out-of-order group decrypt 2 failed");
    assert_eq!(pt2, b"robot camp");
}

/// Mirrors `group_out_of_order` (rust/protocol/tests/groups.rs:1089).
///
/// A full batch of 100 sender-key messages delivered out of order decrypts
/// correctly.
#[wasm_bindgen_test]
async fn test_group_out_of_order_batch() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let distribution_id = mint_distribution_id();

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();

    let dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    process_sender_key_distribution(&alice_address, &dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process distribution");

    const COUNT: usize = 100;
    let mut ciphertexts = Vec::with_capacity(COUNT);
    let mut expected = Vec::with_capacity(COUNT);
    for i in 0..COUNT {
        let body = format!("nefarious plotting {i:02}/100");
        let ct = encrypt_group_message(
            &alice_address,
            distribution_id.clone(),
            body.as_bytes(),
            &mut alice_sender_key_store,
        )
        .await
        .expect("Group encrypt failed");
        ciphertexts.push(ct);
        expected.push(body);
    }

    // Deterministic out-of-order delivery: decrypt in reverse order.
    for i in (0..COUNT).rev() {
        let pt = decrypt_group_message(&alice_address, &ciphertexts[i], &mut bob_sender_key_store)
            .await
            .expect("Group decrypt failed");
        assert_eq!(pt, expected[i].as_bytes());
    }
}

/// Mirrors `group_too_far_in_the_future` (rust/protocol/tests/groups.rs:1160).
///
/// A sender-key message whose iteration is >25_000 ahead of the receiver's
/// current chain position is rejected.
#[wasm_bindgen_test]
async fn test_group_too_far_in_the_future() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let distribution_id = mint_distribution_id();

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();

    let dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    process_sender_key_distribution(&alice_address, &dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process distribution");

    for i in 0..25001 {
        encrypt_group_message(
            &alice_address,
            distribution_id.clone(),
            format!("nefarious plotting {i}").as_bytes(),
            &mut alice_sender_key_store,
        )
        .await
        .expect("Group encrypt failed");
    }

    let too_far = encrypt_group_message(
        &alice_address,
        distribution_id.clone(),
        b"you got the plan?",
        &mut alice_sender_key_store,
    )
    .await
    .expect("Group encrypt failed");

    decrypt_group_message(&alice_address, &too_far, &mut bob_sender_key_store)
        .await
        .expect_err("A >25k sender-key jump must be rejected");
}

/// Mirrors `group_message_key_limit` (rust/protocol/tests/groups.rs:1226).
///
/// The sender-key skipped-message window is 2000 keys; messages inside the
/// window decrypt, messages that fall out are rejected.
#[wasm_bindgen_test]
async fn test_group_message_key_limit() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let distribution_id = mint_distribution_id();

    let (_alice_identity, _alice_reg_id) = create_test_identity();
    let mut alice_sender_key_store = WasmInMemSenderKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let mut bob_sender_key_store = WasmInMemSenderKeyStore::new();

    let dist_msg = create_sender_key_distribution(
        &alice_address,
        distribution_id.clone(),
        &mut alice_sender_key_store,
    )
    .await
    .expect("Failed to create sender key distribution");

    process_sender_key_distribution(&alice_address, &dist_msg, &mut bob_sender_key_store)
        .await
        .expect("Bob failed to process distribution");

    const LIMIT: usize = 2010;
    let mut ciphertexts = Vec::with_capacity(LIMIT);
    for _ in 0..LIMIT {
        ciphertexts.push(
            encrypt_group_message(
                &alice_address,
                distribution_id.clone(),
                b"too many messages",
                &mut alice_sender_key_store,
            )
            .await
            .expect("Group encrypt failed"),
        );
    }

    let pt_1000 = decrypt_group_message(
        &alice_address,
        &ciphertexts[1000],
        &mut bob_sender_key_store,
    )
    .await
    .expect("Message at index 1000 should decrypt");
    assert_eq!(pt_1000, b"too many messages");

    let pt_last = decrypt_group_message(
        &alice_address,
        &ciphertexts[ciphertexts.len() - 1],
        &mut bob_sender_key_store,
    )
    .await
    .expect("Last message should decrypt");
    assert_eq!(pt_last, b"too many messages");

    decrypt_group_message(&alice_address, &ciphertexts[0], &mut bob_sender_key_store)
        .await
        .expect_err("Message older than the sender-key window must fail");
}

// ----------------------------------------------------------------------------
// (c) Negative signature tests on PreKeyBundle processing
// ----------------------------------------------------------------------------

/// Mirrors `test_bad_signed_pre_key_signature` (rust/protocol/tests/session.rs:407).
#[wasm_bindgen_test]
async fn test_bad_signed_pre_key_signature() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (bob_identity, bob_reg_id) = create_test_identity();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();

    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .expect("Failed to generate signed prekey");
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .expect("Failed to generate kyber prekey");

    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();
    let signed_prekey_pk = WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap();

    let good_signature = bob_spk.signature();

    for bit in 0..8 * good_signature.len() {
        let mut bad_signature = good_signature.clone();
        bad_signature[bit / 8] ^= 0x01u8 << (bit % 8);

        let result = process_pre_key_bundle(
            &bob_address,
            &alice_address,
            bob_reg_id,
            &bob_identity_pk,
            bob_spk.id(),
            &signed_prekey_pk,
            &bad_signature,
            None,
            None,
            bob_kpk.id(),
            &bob_kpk.public_key(),
            &bob_kpk.signature(),
            &mut alice_session_store,
            &mut alice_identity_store,
        )
        .await;

        assert!(
            result.is_err(),
            "Corrupted signed-prekey signature bit {bit} must be rejected"
        );
    }

    // Non-corrupted signature must be accepted.
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &signed_prekey_pk,
        &good_signature,
        None,
        None,
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Good signed-prekey signature must be accepted");
}

/// Negative counterpart for kyber prekey signatures, modelled on
/// `test_bad_signed_pre_key_signature` (rust/protocol/tests/session.rs:407).
///
/// libsignal's PreKeyBundle verifies the kyber prekey signature during
/// process_prekey_bundle; a corrupted signature is rejected.
#[wasm_bindgen_test]
async fn test_bad_kyber_pre_key_signature() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (bob_identity, bob_reg_id) = create_test_identity();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();

    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .expect("Failed to generate signed prekey");
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .expect("Failed to generate kyber prekey");

    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();
    let signed_prekey_pk = WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap();

    let good_signature = bob_kpk.signature();

    for bit in 0..8 * good_signature.len() {
        let mut bad_signature = good_signature.clone();
        bad_signature[bit / 8] ^= 0x01u8 << (bit % 8);

        let result = process_pre_key_bundle(
            &bob_address,
            &alice_address,
            bob_reg_id,
            &bob_identity_pk,
            bob_spk.id(),
            &signed_prekey_pk,
            &bob_spk.signature(),
            None,
            None,
            bob_kpk.id(),
            &bob_kpk.public_key(),
            &bad_signature,
            &mut alice_session_store,
            &mut alice_identity_store,
        )
        .await;

        assert!(
            result.is_err(),
            "Corrupted kyber prekey signature bit {bit} must be rejected"
        );
    }

    // Non-corrupted signature must be accepted.
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &signed_prekey_pk,
        &bob_spk.signature(),
        None,
        None,
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &good_signature,
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Good kyber prekey signature must be accepted");
}

/// Wrapper-level validation: a mismatched one-time prekey pair must be rejected
/// rather than silently coerced to `None`.
#[wasm_bindgen_test]
async fn test_process_pre_key_bundle_rejects_mismatched_prekey_pair() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let (bob_identity, bob_reg_id) = create_test_identity();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();

    let bob_pre_keys = generate_pre_keys(1, 1, &mut bob_prekey_store)
        .await
        .unwrap();
    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .unwrap();
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .unwrap();

    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();
    let signed_prekey_pk = WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap();
    let prekey_pk = WasmPublicKey::deserialize(&bob_pre_keys[0].public_key()).unwrap();

    // id without key
    let result = process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &signed_prekey_pk,
        &bob_spk.signature(),
        Some(bob_pre_keys[0].id()),
        None,
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await;
    assert!(result.is_err(), "prekey_id without prekey must be rejected");
    assert_eq!(js_error_code(&result.unwrap_err()), "Generic");

    // key without id
    let result = process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &signed_prekey_pk,
        &bob_spk.signature(),
        None,
        Some(prekey_pk.serialize()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await;
    assert!(result.is_err(), "prekey without prekey_id must be rejected");
    assert_eq!(js_error_code(&result.unwrap_err()), "Generic");

    // Both present still succeeds.
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &signed_prekey_pk,
        &bob_spk.signature(),
        Some(bob_pre_keys[0].id()),
        Some(bob_pre_keys[0].public_key()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("matched prekey pair must be accepted");
}

// ----------------------------------------------------------------------------
// (d) Straggler decrypt after promote_state
// ----------------------------------------------------------------------------

/// Mirrors `prekey_message_to_archived_session` (rust/protocol/tests/session.rs:2489).
///
/// After Alice establishes a new session with Bob (archiving the old one in the
/// same record), a late message encrypted under the previous session still
/// decrypts and promotes the archived state back to current.
#[wasm_bindgen_test]
async fn test_straggler_decrypt_after_promote_state() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";

    // Alice's keys.
    let (alice_identity, alice_reg_id) = create_test_identity();
    let mut alice_session_store = WasmInMemSessionStore::new();
    let mut alice_identity_store = WasmInMemIdentityKeyStore::new(&alice_identity, alice_reg_id);
    let mut alice_prekey_store = WasmInMemPreKeyStore::new();
    let mut alice_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut alice_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let alice_address = WasmProtocolAddress::new(alice_uuid.to_string(), 1).unwrap();

    let alice_spk = generate_signed_pre_key(1, &alice_identity, &mut alice_signed_prekey_store)
        .await
        .expect("Alice signed prekey");
    let alice_kpk = generate_kyber_pre_key(1, &alice_identity, &mut alice_kyber_prekey_store)
        .await
        .expect("Alice kyber prekey");
    let alice_prekeys = generate_pre_keys(1, 1, &mut alice_prekey_store)
        .await
        .expect("Alice prekeys");
    let alice_prekey = &alice_prekeys[0];

    // Bob's keys.
    let (bob_identity, bob_reg_id) = create_test_identity();
    let mut bob_session_store = WasmInMemSessionStore::new();
    let mut bob_identity_store = WasmInMemIdentityKeyStore::new(&bob_identity, bob_reg_id);
    let mut bob_prekey_store = WasmInMemPreKeyStore::new();
    let mut bob_signed_prekey_store = WasmInMemSignedPreKeyStore::new();
    let mut bob_kyber_prekey_store = WasmInMemKyberPreKeyStore::new();
    let bob_address = WasmProtocolAddress::new(bob_uuid.to_string(), 1).unwrap();

    let bob_spk = generate_signed_pre_key(1, &bob_identity, &mut bob_signed_prekey_store)
        .await
        .expect("Bob signed prekey");
    let bob_kpk = generate_kyber_pre_key(1, &bob_identity, &mut bob_kyber_prekey_store)
        .await
        .expect("Bob kyber prekey");
    let bob_prekeys = generate_pre_keys(1, 1, &mut bob_prekey_store)
        .await
        .expect("Bob prekeys");
    let bob_prekey = &bob_prekeys[0];

    let alice_identity_pk =
        WasmPublicKey::deserialize(&alice_identity.public_key().serialize()).unwrap();
    let bob_identity_pk =
        WasmPublicKey::deserialize(&bob_identity.public_key().serialize()).unwrap();

    // Bob processes Alice's bundle and sends the first message.
    process_pre_key_bundle(
        &alice_address,
        &bob_address,
        alice_reg_id,
        &alice_identity_pk,
        alice_spk.id(),
        &WasmPublicKey::deserialize(&alice_spk.public_key()).unwrap(),
        &alice_spk.signature(),
        Some(alice_prekey.id()),
        Some(alice_prekey.public_key()),
        alice_kpk.id(),
        &alice_kpk.public_key(),
        &alice_kpk.signature(),
        &mut bob_session_store,
        &mut bob_identity_store,
    )
    .await
    .expect("Bob failed to process Alice's bundle");

    let bob_ciphertext = encrypt_message(
        b"from Bob",
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
    )
    .await
    .expect("Bob first encrypt failed");
    assert_eq!(bob_ciphertext.message_type(), 3); // PreKeyMessage

    let received_message = decrypt_message(
        &bob_ciphertext.body(),
        bob_ciphertext.message_type(),
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
        &mut alice_prekey_store,
        &alice_signed_prekey_store,
        &mut alice_kyber_prekey_store,
    )
    .await
    .expect("Alice failed to decrypt first message");
    assert_eq!(received_message.plaintext(), b"from Bob");

    // Alice processes Bob's bundle, establishing a new session and archiving the old one.
    process_pre_key_bundle(
        &bob_address,
        &alice_address,
        bob_reg_id,
        &bob_identity_pk,
        bob_spk.id(),
        &WasmPublicKey::deserialize(&bob_spk.public_key()).unwrap(),
        &bob_spk.signature(),
        Some(bob_prekey.id()),
        Some(bob_prekey.public_key()),
        bob_kpk.id(),
        &bob_kpk.public_key(),
        &bob_kpk.signature(),
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Alice failed to process Bob's bundle");

    // Illustrative message on the new session (not sent).
    let _unsent_alice_ciphertext = encrypt_message(
        b"from Alice",
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
    )
    .await
    .expect("Alice encrypt on new session failed");

    // A late message encrypted under Bob's old session must still decrypt,
    // promoting the archived session back to current.
    let bob_ciphertext_2 = encrypt_message(
        b"from Bob 2",
        &alice_address,
        &bob_address,
        &mut bob_session_store,
        &mut bob_identity_store,
    )
    .await
    .expect("Bob second encrypt failed");

    let received_message_2 = decrypt_message(
        &bob_ciphertext_2.body(),
        bob_ciphertext_2.message_type(),
        &bob_address,
        &alice_address,
        &mut alice_session_store,
        &mut alice_identity_store,
        &mut alice_prekey_store,
        &alice_signed_prekey_store,
        &mut alice_kyber_prekey_store,
    )
    .await
    .expect("Straggler decrypt after promote_state must succeed");
    assert_eq!(received_message_2.plaintext(), b"from Bob 2");
}

/// 0.6.4: `remove_kyber_pre_key` evicts a consumed one-time record (canonical
/// one-time deletion on `mark_kyber_pre_key_used`, Signal-iOS
/// `PreKeyStore.swift:199-225`); idempotent, last-resort records untouched
/// unless explicitly removed.
#[wasm_bindgen_test]
async fn test_remove_kyber_pre_key() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut store = WasmInMemKyberPreKeyStore::new();
    let _kpk = generate_kyber_pre_key(1, &identity_key_pair, &mut store)
        .await
        .expect("Failed to generate kyber key");

    assert!(store.export_kyber_pre_key(1).await.unwrap().is_some());
    assert!(store.remove_kyber_pre_key(1));
    assert!(store.export_kyber_pre_key(1).await.unwrap().is_none());
    // Idempotent: a second removal reports absence, not an error.
    assert!(!store.remove_kyber_pre_key(1));
}

/// 0.6.5: removing a one-time kyber pre-key also prunes its anti-replay
/// triples. Canonical clients delete a consumed one-time key outright and
/// record no use-triple for it.
#[wasm_bindgen_test]
async fn test_remove_kyber_pre_key_prunes_usage() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut store = WasmInMemKyberPreKeyStore::new();
    let _kpk = generate_kyber_pre_key(1, &identity_key_pair, &mut store)
        .await
        .expect("Failed to generate kyber key");

    // Seed a usage triple for kyber id 1.
    let base_key = WasmPrivateKey::generate()
        .get_public_key()
        .expect("Failed to derive base key");
    let signed_id: u32 = 2;
    let mut usage = vec![1u8, 0, 0, 0, 1]; // version (1) + count (4 BE)
    usage.extend_from_slice(&1u32.to_be_bytes()); // kyber id
    usage.extend_from_slice(&signed_id.to_be_bytes()); // signed prekey id
    usage.extend_from_slice(&base_key.serialize()); // 33-byte base key
    store.import_kyber_usage(&usage).expect("Import failed");

    assert_eq!(store.export_kyber_usage().len(), 46);
    assert!(store.remove_kyber_pre_key(1));
    // The evicted key's anti-replay entries are pruned.
    let remaining = store.export_kyber_usage();
    assert_eq!(remaining.len(), 5);
    assert_eq!(&remaining[0..5], &[1, 0, 0, 0, 0]);
}

/// 0.6.5: removing a one-time kyber pre-key leaves last-resort triples intact.
/// The prune must be keyed by kyber id; triples for a different (last-resort)
/// id must survive.
#[wasm_bindgen_test]
async fn test_remove_kyber_pre_key_keeps_last_resort_usage() {
    let (identity_key_pair, _registration_id) = create_test_identity();
    let mut store = WasmInMemKyberPreKeyStore::new();
    let _one_time = generate_kyber_pre_key(1, &identity_key_pair, &mut store)
        .await
        .expect("Failed to generate one-time kyber key");
    let _last_resort = generate_kyber_pre_key(42, &identity_key_pair, &mut store)
        .await
        .expect("Failed to generate last-resort kyber key");

    let base_key = WasmPrivateKey::generate()
        .get_public_key()
        .expect("Failed to derive base key");
    let signed_id: u32 = 2;

    // One triple for the one-time key, one for the last-resort key.
    let mut usage = vec![1u8, 0, 0, 0, 2]; // version (1) + count (4 BE)
    usage.extend_from_slice(&1u32.to_be_bytes());
    usage.extend_from_slice(&signed_id.to_be_bytes());
    usage.extend_from_slice(&base_key.serialize());
    usage.extend_from_slice(&42u32.to_be_bytes());
    usage.extend_from_slice(&signed_id.to_be_bytes());
    usage.extend_from_slice(&base_key.serialize());
    store.import_kyber_usage(&usage).expect("Import failed");

    assert_eq!(store.export_kyber_usage().len(), 87); // 5 + 2 * 41
    assert!(store.remove_kyber_pre_key(1));
    // The last-resort triple survives eviction of the one-time key.
    let remaining = store.export_kyber_usage();
    assert_eq!(remaining.len(), 46); // 5 + 1 * 41
    assert_eq!(&remaining[5..9], &[0, 0, 0, 42]);
}

#[wasm_bindgen_test]
async fn test_ratchet_key_of_ciphertext_prekey_and_whisper_arms() {
    let mut f = establish_prekey_session(true).await;

    // PreKey arm: alice's first ciphertext is a PreKeySignalMessage whose
    // embedded SignalMessage carries her initial ratchet key.
    let first = encrypt_message(
        b"retry-test-1",
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("encrypt failed");
    assert_eq!(first.message_type(), 3); // PreKeyMessage
    let alice_key = ratchet_key_of_ciphertext(&first.body(), first.message_type())
        .expect("ratchet key extraction failed")
        .expect("prekey ciphertext carries a ratchet key");
    assert_eq!(alice_key.len(), 33); // 0x05 || 32-byte X25519 public key

    // Whisper arm: bob's reply is a plain SignalMessage.
    decrypt_message(
        &first.body(),
        first.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
        &mut f.bob_prekey_store,
        &f.bob_signed_prekey_store,
        &mut f.bob_kyber_prekey_store,
    )
    .await
    .expect("bob decrypt failed");
    let reply = encrypt_message(
        b"ack",
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
    )
    .await
    .expect("reply encrypt failed");
    assert_eq!(reply.message_type(), 2); // SignalMessage
    let bob_key = ratchet_key_of_ciphertext(&reply.body(), reply.message_type())
        .expect("ratchet key extraction failed")
        .expect("whisper ciphertext carries a ratchet key");
    assert_eq!(bob_key.len(), 33);
    // Each direction's header carries its own party's current ratchet key.
    assert_ne!(alice_key, bob_key);
}

#[wasm_bindgen_test]
async fn test_session_current_ratchet_key_matches_lifecycle() {
    let mut f = establish_prekey_session(true).await;

    let first = encrypt_message(
        b"m1",
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("encrypt failed");
    let sent_key = ratchet_key_of_ciphertext(&first.body(), first.message_type())
        .expect("extraction failed")
        .expect("ratchet key present");

    // The key alice sent with is still her session's current ratchet key:
    // this is the sender-side archive-on-match check from
    // rust/protocol/src/session_management.rs:2266-2286 @ b056faa6d.
    assert!(
        f.alice_session_store
            .session_current_ratchet_key_matches(&f.bob_address, &sent_key)
            .await
            .expect("match check failed"),
        "current ratchet key must match before any ratchet advance"
    );

    // Bob replies; when alice processes the reply her session ratchets
    // forward, so the key she sent m1 with stops matching.
    decrypt_message(
        &first.body(),
        first.message_type(),
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
        &mut f.bob_prekey_store,
        &f.bob_signed_prekey_store,
        &mut f.bob_kyber_prekey_store,
    )
    .await
    .expect("bob decrypt failed");
    let reply = encrypt_message(
        b"ack",
        &f.alice_address,
        &f.bob_address,
        &mut f.bob_session_store,
        &mut f.bob_identity_store,
    )
    .await
    .expect("reply encrypt failed");
    decrypt_message(
        &reply.body(),
        reply.message_type(),
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
        &mut WasmInMemPreKeyStore::new(),
        &WasmInMemSignedPreKeyStore::new(),
        &mut WasmInMemKyberPreKeyStore::new(),
    )
    .await
    .expect("alice reply decrypt failed");
    assert!(
        !f.alice_session_store
            .session_current_ratchet_key_matches(&f.bob_address, &sent_key)
            .await
            .expect("match check failed"),
        "a superseded ratchet key must not match"
    );

    // Her new current key (from a fresh ciphertext) does match.
    let second = encrypt_message(
        b"m2",
        &f.bob_address,
        &f.alice_address,
        &mut f.alice_session_store,
        &mut f.alice_identity_store,
    )
    .await
    .expect("encrypt failed");
    let new_key = ratchet_key_of_ciphertext(&second.body(), second.message_type())
        .expect("extraction failed")
        .expect("ratchet key present");
    assert!(
        f.alice_session_store
            .session_current_ratchet_key_matches(&f.bob_address, &new_key)
            .await
            .expect("match check failed"),
        "the post-ratchet key must match"
    );

    // After archive (the retry-heal action), the record has no current
    // state: the check reports false rather than erroring.
    f.alice_session_store
        .archive_session(&f.bob_address)
        .await
        .expect("archive failed");
    assert!(
        !f.alice_session_store
            .session_current_ratchet_key_matches(&f.bob_address, &new_key)
            .await
            .expect("match check failed"),
        "an archived session must not match any key"
    );
}

#[wasm_bindgen_test]
async fn test_ratchet_key_of_ciphertext_sender_key_and_error_arms() {
    // SenderKey arm returns None without parsing: group messages carry no
    // Double-Ratchet key (group heal is SKDM re-serve, not archive-on-match).
    let none = ratchet_key_of_ciphertext(&[0x42, 0x00, 0x01], message_type_sender_key())
        .expect("sender key arm should not parse or fail");
    assert!(none.is_none());

    // Plaintext (type 8, CiphertextMessageType::Plaintext @
    // rust/protocol/src/protocol.rs:39 @ b056faa6d) has no ratchet key.
    assert!(ratchet_key_of_ciphertext(&[0x01], 8).is_err());

    // Unknown type byte and a corrupt Whisper payload both error.
    assert!(ratchet_key_of_ciphertext(&[0x01], 0x42).is_err());
    assert!(ratchet_key_of_ciphertext(&[0x01, 0x02], message_type_signal()).is_err());
}

#[wasm_bindgen_test]
async fn test_session_current_ratchet_key_matches_no_session_and_garbage() {
    let store = WasmInMemSessionStore::new();
    let (identity, _registration_id) = create_test_identity();
    let key = identity.public_key().serialize();
    let addr = WasmProtocolAddress::new("00000000-0000-0000-0000-0000000000CC".to_string(), 1)
        .expect("address");

    // No record at all reports false, never an error.
    assert!(
        !store
            .session_current_ratchet_key_matches(&addr, &key)
            .await
            .expect("match check failed"),
        "missing session must not match"
    );

    // Malformed key bytes surface as an error rather than a false negative.
    assert!(
        store
            .session_current_ratchet_key_matches(&addr, &[0x05, 0x00])
            .await
            .is_err(),
        "garbage key bytes must error"
    );
}
