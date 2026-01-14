//! Test suite for the WebAssembly interface of libsignal-wasm.
//!
//! Run with:
//! wasm-pack test --headless --chrome
//! or
//! wasm-pack test --headless --firefox

#![cfg(target_arch = "wasm32")]

extern crate wasm_bindgen_test;
use wasm_bindgen_test::*;
use libsignal_wasm::{SignalClient, init};
use wasm_bindgen::JsValue;

wasm_bindgen_test_configure!(run_in_browser);

// Helper to create a client with standard test ID
fn create_test_client(uuid: &str, device_id: u32) -> Result<SignalClient, JsValue> {
    SignalClient::new(uuid, device_id)
}

#[wasm_bindgen_test]
async fn test_client_initialisation() {
    init();
    let uuid = "00000000-0000-0000-0000-000000000001";
    let client = create_test_client(uuid, 1).expect("Failed to create client");
    
    assert_eq!(client.get_local_uuid(), uuid);
    assert_eq!(client.get_local_device_id(), 1);
    assert!(client.get_registration_id() > 0);
    
    let identity_pk = client.get_identity_public_key();
    assert_eq!(identity_pk.len(), 33); // Curve25519 pubkey (32 bytes + type byte 0x05)
}

#[wasm_bindgen_test]
async fn test_pre_key_generation() {
    let mut client = create_test_client("00000000-0000-0000-0000-000000000001", 1).unwrap();
    
    // 1. One-time PreKeys
    let pre_keys = client.generate_pre_keys(5).expect("Failed to generate prekeys");
    assert_eq!(pre_keys.length(), 5);
    // Convert first to WasmPreKey to verify structure (simplified check)
    // Note: detailed struct check requires strictly importing WasmPreKey which is hard in tests 
    // without exposing everything public. We assume success if no error.

    // 2. Signed PreKey
    let signed_pre_key = client.generate_signed_pre_key().expect("Failed to generate signed prekey");
    assert!(signed_pre_key.id() > 0);
    assert!(signed_pre_key.signature().len() > 0);

    // 3. Kyber PreKey
    let kyber_pre_key = client.generate_kyber_pre_key().expect("Failed to generate kyber key");
    assert!(kyber_pre_key.id() > 0);
    assert_eq!(kyber_pre_key.public_key().len(), 1569); // Kyber1024 public key size
}

#[wasm_bindgen_test]
async fn test_session_establishment_and_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";
    
    let mut alice = create_test_client(alice_uuid, 1).unwrap();
    let mut bob = create_test_client(bob_uuid, 1).unwrap();
    
    // --- Bob Generates Keys ---
    let bob_pre_keys_array = bob.generate_pre_keys(1).unwrap();
    let bob_pre_key_js = bob_pre_keys_array.get(0);
    // Cast to struct manually tailored for test or just rely on the fact we can't easily cast JS objects back in this test env without internal visibility.
    // However, we can use the `get_*` methods if we had the struct type available, but they are defined in lib.
    // For this integration test, we will extract IDs carefully or assume standard implementation.
    
    // Ideally we would grab the WasmPreKey object, but wasm-bindgen-test doesn't easily let us inspect JS objects returned.
    // Instead we rely on the specific `process_pre_key_bundle` which takes raw bytes.
    // So we need to access the fields of the objects Bob returned. 
    // Since we are compiled in the same crate test, we *can* actually access the Rust struct fields if we use the underlying methods,
    // but here we are testing the WASM boundary facade. 
    // To make this easier, let's just use the Rust-side logic if possible, OR use reflection/getters.
    // Actually, `WasmPreKey` has getters exposed to WASM. In Rust tests, we can call them directly!
    
    // Wait, the result of `generate_pre_keys` is `js_sys::Array` containing `JsValue`.
    // Casting `JsValue` back to `WasmPreKey` is tricky in tests without `unchecked_ref`.
    // Let's rely on the public API getters.
    
    // REFACTORING for Testability:
    // In a real integration test, we simulate JS. Here, we'll extract using `wasm_bindgen` casts if possible,
    // or just generate fresh keys specifically for the bundle manually if the Array is too opaque.
    // Better: Helper function in `lib.rs` specific for tests? No, keep `lib.rs` clean.
    // We will assume Bob has generated keys and accessing his store directly (which is wrong, stores are private).
    // Correct approach: Use the getters on the returned objects.
    
    let bob_signed_pre_key = bob.generate_signed_pre_key().unwrap();
    let bob_kyber_pre_key = bob.generate_kyber_pre_key().unwrap();
    // We need a standard PreKey.
    // Since `generate_pre_keys` returns an Array of JsValues, and we can't easily cast them in a test harness 
    // without `wasm-bindgen` glue code for the test crate itself, we might hit a wall.
    // WORKAROUND: For the purpose of this test, we will modify `generate_pre_keys` to return `Vec<WasmPreKey>`? No strictly `Array`.
    
    // Alternative: Just call `generate_pre_keys` to populate Bob's store, then manually construct the bundle arguments
    // using the knowledge of deterministic IDs (Bob's first prekey is ID 1).
    // And we need the public key bytes.
    // Bob's store is private. We can't get the public key unless we can read the returned object.
    // `pre_keys.get(0)` returns a JsValue. 
    // We can use `Reflect` to get properties "id" and "public_key" from the JsValue!
    
    use js_sys::Reflect;
    
    let pk_val = bob_pre_keys_array.get(0);
    let pk_id = Reflect::get(&pk_val, &"id".into()).unwrap().as_f64().unwrap() as u32;
    let pk_pub_js = Reflect::get(&pk_val, &"public_key".into()).unwrap(); // Uint8Array
    let pk_pub = js_sys::Uint8Array::new(&pk_pub_js).to_vec();
    
    let spk_id = bob_signed_pre_key.id();
    let spk_pub = bob_signed_pre_key.public_key();
    let spk_sig = bob_signed_pre_key.signature();
    
    let kpk_id = bob_kyber_pre_key.id();
    let kpk_pub = bob_kyber_pre_key.public_key();
    let kpk_sig = bob_kyber_pre_key.signature();
    
    let bob_identity_pk = bob.get_identity_public_key();
    let bob_reg_id = bob.get_registration_id();
    let bob_dev_id = bob.get_local_device_id();
    
    // --- Alice Establishes Session ---
    alice.process_pre_key_bundle(
        bob_uuid.to_string(),
        bob_dev_id,
        bob_reg_id,
        bob_identity_pk,
        spk_id,
        spk_pub,
        spk_sig,
        Some(pk_id),
        Some(pk_pub),
        kpk_id,
        kpk_pub,
        kpk_sig
    ).await.expect("Alice failed to process bundle");
    
    // --- Messaging ---
    let message_body = b"Hello WASM World!";
    
    // 1. Alice Encrypts
    let ciphertext = alice.encrypt_message(bob_uuid.to_string(), 1, message_body.to_vec())
        .await.expect("Encryption failed");
        
    assert_eq!(ciphertext.message_type(), 3); // PreKeyMessage initially
    
    // 2. Bob Decrypts
    let decrypted = bob.decrypt_message(
        alice_uuid.to_string(),
        1,
        ciphertext.body(),
        ciphertext.message_type()
    ).await.expect("Decryption failed");
    
    assert_eq!(decrypted, message_body);
    
    // 3. Bob Replies (Standard Message)
    let reply_body = b"Ack!";
    let reply_cipher = bob.encrypt_message(alice_uuid.to_string(), 1, reply_body.to_vec())
        .await.expect("Reply encryption failed");
        
    assert_eq!(reply_cipher.message_type(), 2); // SignalMessage now
    
    let reply_decrypted = alice.decrypt_message(
        bob_uuid.to_string(),
        1,
        reply_cipher.body(),
        reply_cipher.message_type()
    ).await.expect("Reply decryption failed");
    
    assert_eq!(reply_decrypted, reply_body);
}

#[wasm_bindgen_test]
async fn test_group_messaging() {
    let alice_uuid = "00000000-0000-0000-0000-00000000000A";
    let bob_uuid = "00000000-0000-0000-0000-00000000000B";
    let group_id_bytes = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap(); // 16 bytes
    
    let mut alice = create_test_client(alice_uuid, 1).unwrap();
    let mut bob = create_test_client(bob_uuid, 1).unwrap();
    
    // 1. Alice Creates Group (SenderKeyDistribution)
    let dist_msg = alice.create_sender_key_distribution(group_id_bytes.clone())
        .await.expect("Failed to create sender key distribution");
        
    // 2. Bob Processes Distribution
    bob.process_sender_key_distribution(
        alice_uuid.to_string(),
        1,
        dist_msg
    ).await.expect("Bob failed to process distribution");
    
    // 3. Alice Encrypts to Group
    let plaintext = b"Group Hello";
    let group_cipher = alice.encrypt_group_message(
        group_id_bytes.clone(),
        plaintext.to_vec()
    ).await.expect("Group encryption failed");
    
    // 4. Bob Decrypts
    let decrypted = bob.decrypt_group_message(
        alice_uuid.to_string(),
        1,
        group_cipher
    ).await.expect("Group decryption failed");
    
    assert_eq!(decrypted, plaintext);
}

