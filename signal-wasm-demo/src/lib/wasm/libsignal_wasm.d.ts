/* tslint:disable */
/* eslint-disable */
/**
 * Convert UUID bytes to string.
 */
export function uuid_to_string(bytes: Uint8Array): string;
/**
 * Log a message to the browser console (for debugging)
 */
export function log_to_console(message: string): void;
/**
 * Get message type for SignalMessage (normal message)
 */
export function message_type_signal(): number;
/**
 * Get message type for PreKeySignalMessage (first message establishing session)
 */
export function message_type_prekey(): number;
/**
 * Initialize the WASM module. Called automatically when the module loads.
 */
export function init(): void;
/**
 * Get message type for SenderKeyMessage (group message)
 */
export function message_type_sender_key(): number;
/**
 * Parse UUID string to bytes.
 */
export function uuid_from_string(s: string): Uint8Array;
/**
 * Generate random bytes (returns error if CSPRNG fails).
 */
export function generate_random_bytes(length: number): Uint8Array;
/**
 * Generate a random attachment key (64 bytes).
 */
export function generate_attachment_key(): Uint8Array;
/**
 * Generate a random UUID v4.
 */
export function generate_uuid(): Uint8Array;
/**
 * The main Signal Protocol client.
 *
 * Holds all cryptographic state for E2EE messaging.
 * Create one instance when your app starts.
 */
export class SignalClient {
  free(): void;
  /**
   * Check if a session exists.
   */
  has_session(recipient_uuid: string, device_id: number): Promise<boolean>;
  /**
   * Export a PreKey.
   */
  export_prekey(id: number): Promise<Uint8Array | undefined>;
  /**
   * Import a PreKey.
   */
  import_prekey(id: number, record_bytes: Uint8Array): Promise<void>;
  /**
   * Export a session.
   */
  export_session(contact_uuid: string, device_id: number): Promise<Uint8Array | undefined>;
  get_local_uuid(): string;
  /**
   * Import a session.
   */
  import_session(contact_uuid: string, device_id: number, session_bytes: Uint8Array): Promise<void>;
  /**
   * Archive a session.
   */
  archive_session(contact_uuid: string, device_id: number): Promise<void>;
  /**
   * Decrypt a message.
   */
  decrypt_message(sender_uuid: string, sender_device_id: number, ciphertext: Uint8Array, message_type: number): Promise<Uint8Array>;
  /**
   * Encrypt a message.
   */
  encrypt_message(recipient_uuid: string, device_id: number, plaintext: Uint8Array): Promise<WasmCiphertext>;
  /**
   * Generate a batch of one-time PreKeys.
   */
  generate_prekeys(count: number): Array<any>;
  /**
   * Export a sender key.
   */
  export_sender_key(group_member_uuid: string, device_id: number, distribution_id: Uint8Array): Promise<Uint8Array | undefined>;
  /**
   * Import a sender key.
   */
  import_sender_key(group_member_uuid: string, device_id: number, distribution_id: Uint8Array, record_bytes: Uint8Array): Promise<void>;
  get_next_prekey_id(): number;
  /**
   * Export a Kyber PreKey.
   */
  export_kyber_prekey(id: number): Promise<Uint8Array | undefined>;
  get_local_device_id(): number;
  get_registration_id(): number;
  /**
   * Import a Kyber PreKey.
   */
  import_kyber_prekey(id: number, record_bytes: Uint8Array): Promise<void>;
  /**
   * Export a Signed PreKey.
   */
  export_signed_prekey(id: number): Promise<Uint8Array | undefined>;
  /**
   * Import a Signed PreKey.
   */
  import_signed_prekey(id: number, record_bytes: Uint8Array): Promise<void>;
  /**
   * Verify a scanned safety number.
   */
  verify_safety_number(scanned: Uint8Array, contact_uuid: string, contact_identity_key: Uint8Array): boolean;
  /**
   * Decrypt a group message.
   */
  decrypt_group_message(sender_uuid: string, sender_device_id: number, ciphertext: Uint8Array): Promise<Uint8Array>;
  /**
   * Encrypt a group message.
   */
  encrypt_group_message(distribution_id: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  /**
   * Generate a Kyber PreKey for post-quantum security.
   * Uses Kyber1024 (Signal production default).
   * NOTE: Manual implementation because KyberPreKeyRecord::generate has a bug
   * (OsRng.unwrap_err()) that panics in WASM.
   */
  generate_kyber_prekey(): WasmKyberPreKey;
  get_identity_key_pair(): WasmIdentityKeyPair;
  /**
   * Process a PreKeyBundle to establish a session.
   */
  process_prekey_bundle(recipient_uuid: string, recipient_device_id: number, registration_id: number, identity_key: Uint8Array, signed_prekey_id: number, signed_prekey: Uint8Array, signed_prekey_signature: Uint8Array, prekey_id: number | null | undefined, prekey: Uint8Array | null | undefined, kyber_prekey_id: number, kyber_prekey: Uint8Array, kyber_prekey_signature: Uint8Array): Promise<void>;
  /**
   * Generate multiple Kyber PreKeys.
   */
  generate_kyber_prekeys(count: number): Array<any>;
  /**
   * Generate a safety number.
   * NOTE: We clone identity_key upfront to avoid wasm_bindgen aliasing issues.
   */
  generate_safety_number(contact_uuid: string, contact_identity_key: Uint8Array): WasmSafetyNumber;
  /**
   * Generate a signed PreKey.
   */
  generate_signed_prekey(): WasmSignedPreKey;
  get_identity_public_key(): Uint8Array;
  get_next_kyber_prekey_id(): number;
  get_next_signed_prekey_id(): number;
  /**
   * Create a sender key distribution message.
   */
  create_sender_key_distribution(distribution_id: Uint8Array): Promise<Uint8Array>;
  /**
   * Process a sender key distribution message.
   */
  process_sender_key_distribution(sender_uuid: string, sender_device_id: number, distribution_message: Uint8Array): Promise<void>;
  /**
   * Create a new SignalClient with a fresh identity.
   */
  constructor(local_uuid: string, local_device_id: number);
  /**
   * Restore a SignalClient from previously saved state.
   */
  static restore(identity_public_key: Uint8Array, identity_private_key: Uint8Array, registration_id: number, local_uuid: string, local_device_id: number, next_prekey_id: number, next_signed_prekey_id: number, next_kyber_prekey_id: number): SignalClient;
}
/**
 * Encrypted message result
 */
export class WasmCiphertext {
  private constructor();
  free(): void;
  readonly message_type: number;
  readonly body: Uint8Array;
}
/**
 * Represents a generated identity key pair
 */
export class WasmIdentityKeyPair {
  private constructor();
  free(): void;
  readonly public_key: Uint8Array;
  /**
   * Get the private key bytes (zeroized on drop)
   */
  readonly private_key: Uint8Array;
}
/**
 * A Kyber (post-quantum) PreKey for upload to the server
 */
export class WasmKyberPreKey {
  private constructor();
  free(): void;
  readonly public_key: Uint8Array;
  readonly id: number;
  readonly signature: Uint8Array;
  readonly timestamp: bigint;
}
/**
 * A single PreKey for upload to the server
 */
export class WasmPreKey {
  private constructor();
  free(): void;
  readonly public_key: Uint8Array;
  readonly id: number;
}
/**
 * Safety number for identity verification
 */
export class WasmSafetyNumber {
  private constructor();
  free(): void;
  readonly displayable: string;
  readonly scannable: Uint8Array;
}
/**
 * A signed PreKey for upload to the server
 */
export class WasmSignedPreKey {
  private constructor();
  free(): void;
  readonly public_key: Uint8Array;
  readonly id: number;
  readonly signature: Uint8Array;
  readonly timestamp: bigint;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_signalclient_free: (a: number, b: number) => void;
  readonly __wbg_wasmciphertext_free: (a: number, b: number) => void;
  readonly __wbg_wasmidentitykeypair_free: (a: number, b: number) => void;
  readonly __wbg_wasmkyberprekey_free: (a: number, b: number) => void;
  readonly __wbg_wasmprekey_free: (a: number, b: number) => void;
  readonly __wbg_wasmsafetynumber_free: (a: number, b: number) => void;
  readonly __wbg_wasmsignedprekey_free: (a: number, b: number) => void;
  readonly generate_attachment_key: () => [number, number, number, number];
  readonly generate_random_bytes: (a: number) => [number, number, number, number];
  readonly generate_uuid: () => [number, number];
  readonly log_to_console: (a: number, b: number) => void;
  readonly message_type_prekey: () => number;
  readonly message_type_sender_key: () => number;
  readonly message_type_signal: () => number;
  readonly signalclient_archive_session: (a: number, b: number, c: number, d: number) => any;
  readonly signalclient_create_sender_key_distribution: (a: number, b: number, c: number) => any;
  readonly signalclient_decrypt_group_message: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly signalclient_decrypt_message: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => any;
  readonly signalclient_encrypt_group_message: (a: number, b: number, c: number, d: number, e: number) => any;
  readonly signalclient_encrypt_message: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly signalclient_export_kyber_prekey: (a: number, b: number) => any;
  readonly signalclient_export_prekey: (a: number, b: number) => any;
  readonly signalclient_export_sender_key: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly signalclient_export_session: (a: number, b: number, c: number, d: number) => any;
  readonly signalclient_export_signed_prekey: (a: number, b: number) => any;
  readonly signalclient_generate_kyber_prekey: (a: number) => [number, number, number];
  readonly signalclient_generate_kyber_prekeys: (a: number, b: number) => [number, number, number];
  readonly signalclient_generate_prekeys: (a: number, b: number) => [number, number, number];
  readonly signalclient_generate_safety_number: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly signalclient_generate_signed_prekey: (a: number) => [number, number, number];
  readonly signalclient_get_identity_key_pair: (a: number) => number;
  readonly signalclient_get_identity_public_key: (a: number) => [number, number];
  readonly signalclient_get_local_device_id: (a: number) => number;
  readonly signalclient_get_local_uuid: (a: number) => [number, number];
  readonly signalclient_get_next_kyber_prekey_id: (a: number) => number;
  readonly signalclient_get_next_prekey_id: (a: number) => number;
  readonly signalclient_get_next_signed_prekey_id: (a: number) => number;
  readonly signalclient_get_registration_id: (a: number) => number;
  readonly signalclient_has_session: (a: number, b: number, c: number, d: number) => any;
  readonly signalclient_import_kyber_prekey: (a: number, b: number, c: number, d: number) => any;
  readonly signalclient_import_prekey: (a: number, b: number, c: number, d: number) => any;
  readonly signalclient_import_sender_key: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => any;
  readonly signalclient_import_session: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly signalclient_import_signed_prekey: (a: number, b: number, c: number, d: number) => any;
  readonly signalclient_new: (a: number, b: number, c: number) => [number, number, number];
  readonly signalclient_process_prekey_bundle: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number, p: number, q: number, r: number, s: number, t: number) => any;
  readonly signalclient_process_sender_key_distribution: (a: number, b: number, c: number, d: number, e: number, f: number) => any;
  readonly signalclient_restore: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number];
  readonly signalclient_verify_safety_number: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
  readonly uuid_from_string: (a: number, b: number) => [number, number, number, number];
  readonly uuid_to_string: (a: number, b: number) => [number, number, number, number];
  readonly wasmciphertext_body: (a: number) => [number, number];
  readonly wasmciphertext_message_type: (a: number) => number;
  readonly wasmidentitykeypair_private_key: (a: number) => [number, number];
  readonly wasmidentitykeypair_public_key: (a: number) => [number, number];
  readonly wasmkyberprekey_id: (a: number) => number;
  readonly wasmkyberprekey_public_key: (a: number) => [number, number];
  readonly wasmkyberprekey_signature: (a: number) => [number, number];
  readonly wasmkyberprekey_timestamp: (a: number) => bigint;
  readonly wasmprekey_id: (a: number) => number;
  readonly wasmprekey_public_key: (a: number) => [number, number];
  readonly wasmsafetynumber_displayable: (a: number) => [number, number];
  readonly wasmsafetynumber_scannable: (a: number) => [number, number];
  readonly wasmsignedprekey_public_key: (a: number) => [number, number];
  readonly wasmsignedprekey_signature: (a: number) => [number, number];
  readonly init: () => void;
  readonly wasmsignedprekey_id: (a: number) => number;
  readonly wasmsignedprekey_timestamp: (a: number) => bigint;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_6: WebAssembly.Table;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly closure157_externref_shim: (a: number, b: number, c: any) => void;
  readonly closure290_externref_shim: (a: number, b: number, c: any, d: any) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
