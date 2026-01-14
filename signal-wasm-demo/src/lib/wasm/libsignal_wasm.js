let wasm;

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

let cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );

if (typeof TextDecoder !== 'undefined') { cachedTextDecoder.decode(); };

const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = (typeof TextDecoder !== 'undefined' ? new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }) : { decode: () => { throw Error('TextDecoder not available') } } );
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(ptr, len);
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let WASM_VECTOR_LEN = 0;

const cachedTextEncoder = (typeof TextEncoder !== 'undefined' ? new TextEncoder('utf-8') : { encode: () => { throw Error('TextEncoder not available') } } );

const encodeString = (typeof cachedTextEncoder.encodeInto === 'function'
    ? function (arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
}
    : function (arg, view) {
    const buf = cachedTextEncoder.encode(arg);
    view.set(buf);
    return {
        read: arg.length,
        written: buf.length
    };
});

function passStringToWasm0(arg, malloc, realloc) {

    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }

    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = encodeString(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

const CLOSURE_DTORS = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(
state => {
    wasm.__wbindgen_export_6.get(state.dtor)(state.a, state.b);
}
);

function makeMutClosure(arg0, arg1, dtor, f) {
    const state = { a: arg0, b: arg1, cnt: 1, dtor };
    const real = (...args) => {

        // First up with a closure we increment the internal reference
        // count. This ensures that the Rust closure environment won't
        // be deallocated while we're invoking it.
        state.cnt++;
        const a = state.a;
        state.a = 0;
        try {
            return f(a, state.b, ...args);
        } finally {
            if (--state.cnt === 0) {
                wasm.__wbindgen_export_6.get(state.dtor)(a, state.b);
                CLOSURE_DTORS.unregister(state);
            } else {
                state.a = a;
            }
        }
    };
    real.original = state;
    CLOSURE_DTORS.register(real, state, state);
    return real;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_export_2.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}
/**
 * Convert UUID bytes to string.
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function uuid_to_string(bytes) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passArray8ToWasm0(bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.uuid_to_string(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * Log a message to the browser console (for debugging)
 * @param {string} message
 */
export function log_to_console(message) {
    const ptr0 = passStringToWasm0(message, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    wasm.log_to_console(ptr0, len0);
}

/**
 * Get message type for SignalMessage (normal message)
 * @returns {number}
 */
export function message_type_signal() {
    const ret = wasm.message_type_signal();
    return ret;
}

/**
 * Get message type for PreKeySignalMessage (first message establishing session)
 * @returns {number}
 */
export function message_type_prekey() {
    const ret = wasm.message_type_prekey();
    return ret;
}

/**
 * Initialize the WASM module. Called automatically when the module loads.
 */
export function init() {
    wasm.init();
}

/**
 * Get message type for SenderKeyMessage (group message)
 * @returns {number}
 */
export function message_type_sender_key() {
    const ret = wasm.message_type_sender_key();
    return ret;
}

/**
 * Parse UUID string to bytes.
 * @param {string} s
 * @returns {Uint8Array}
 */
export function uuid_from_string(s) {
    const ptr0 = passStringToWasm0(s, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.uuid_from_string(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * Generate random bytes (returns error if CSPRNG fails).
 * @param {number} length
 * @returns {Uint8Array}
 */
export function generate_random_bytes(length) {
    const ret = wasm.generate_random_bytes(length);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Generate a random attachment key (64 bytes).
 * @returns {Uint8Array}
 */
export function generate_attachment_key() {
    const ret = wasm.generate_attachment_key();
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

/**
 * Generate a random UUID v4.
 * @returns {Uint8Array}
 */
export function generate_uuid() {
    const ret = wasm.generate_uuid();
    var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v1;
}

function __wbg_adapter_6(arg0, arg1, arg2) {
    wasm.closure157_externref_shim(arg0, arg1, arg2);
}

function __wbg_adapter_104(arg0, arg1, arg2, arg3) {
    wasm.closure290_externref_shim(arg0, arg1, arg2, arg3);
}

const SignalClientFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_signalclient_free(ptr >>> 0, 1));
/**
 * The main Signal Protocol client.
 *
 * Holds all cryptographic state for E2EE messaging.
 * Create one instance when your app starts.
 */
export class SignalClient {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SignalClient.prototype);
        obj.__wbg_ptr = ptr;
        SignalClientFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SignalClientFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signalclient_free(ptr, 0);
    }
    /**
     * Check if a session exists.
     * @param {string} recipient_uuid
     * @param {number} device_id
     * @returns {Promise<boolean>}
     */
    has_session(recipient_uuid, device_id) {
        const ptr0 = passStringToWasm0(recipient_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_has_session(this.__wbg_ptr, ptr0, len0, device_id);
        return ret;
    }
    /**
     * Export a PreKey.
     * @param {number} id
     * @returns {Promise<Uint8Array | undefined>}
     */
    export_prekey(id) {
        const ret = wasm.signalclient_export_prekey(this.__wbg_ptr, id);
        return ret;
    }
    /**
     * Import a PreKey.
     * @param {number} id
     * @param {Uint8Array} record_bytes
     * @returns {Promise<void>}
     */
    import_prekey(id, record_bytes) {
        const ptr0 = passArray8ToWasm0(record_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_import_prekey(this.__wbg_ptr, id, ptr0, len0);
        return ret;
    }
    /**
     * Export a session.
     * @param {string} contact_uuid
     * @param {number} device_id
     * @returns {Promise<Uint8Array | undefined>}
     */
    export_session(contact_uuid, device_id) {
        const ptr0 = passStringToWasm0(contact_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_export_session(this.__wbg_ptr, ptr0, len0, device_id);
        return ret;
    }
    /**
     * @returns {string}
     */
    get_local_uuid() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.signalclient_get_local_uuid(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * Import a session.
     * @param {string} contact_uuid
     * @param {number} device_id
     * @param {Uint8Array} session_bytes
     * @returns {Promise<void>}
     */
    import_session(contact_uuid, device_id, session_bytes) {
        const ptr0 = passStringToWasm0(contact_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(session_bytes, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_import_session(this.__wbg_ptr, ptr0, len0, device_id, ptr1, len1);
        return ret;
    }
    /**
     * Archive a session.
     * @param {string} contact_uuid
     * @param {number} device_id
     * @returns {Promise<void>}
     */
    archive_session(contact_uuid, device_id) {
        const ptr0 = passStringToWasm0(contact_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_archive_session(this.__wbg_ptr, ptr0, len0, device_id);
        return ret;
    }
    /**
     * Decrypt a message.
     * @param {string} sender_uuid
     * @param {number} sender_device_id
     * @param {Uint8Array} ciphertext
     * @param {number} message_type
     * @returns {Promise<Uint8Array>}
     */
    decrypt_message(sender_uuid, sender_device_id, ciphertext, message_type) {
        const ptr0 = passStringToWasm0(sender_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_decrypt_message(this.__wbg_ptr, ptr0, len0, sender_device_id, ptr1, len1, message_type);
        return ret;
    }
    /**
     * Encrypt a message.
     * @param {string} recipient_uuid
     * @param {number} device_id
     * @param {Uint8Array} plaintext
     * @returns {Promise<WasmCiphertext>}
     */
    encrypt_message(recipient_uuid, device_id, plaintext) {
        const ptr0 = passStringToWasm0(recipient_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_encrypt_message(this.__wbg_ptr, ptr0, len0, device_id, ptr1, len1);
        return ret;
    }
    /**
     * Generate a batch of one-time PreKeys.
     * @param {number} count
     * @returns {Array<any>}
     */
    generate_prekeys(count) {
        const ret = wasm.signalclient_generate_prekeys(this.__wbg_ptr, count);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Export a sender key.
     * @param {string} group_member_uuid
     * @param {number} device_id
     * @param {Uint8Array} distribution_id
     * @returns {Promise<Uint8Array | undefined>}
     */
    export_sender_key(group_member_uuid, device_id, distribution_id) {
        const ptr0 = passStringToWasm0(group_member_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(distribution_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_export_sender_key(this.__wbg_ptr, ptr0, len0, device_id, ptr1, len1);
        return ret;
    }
    /**
     * Import a sender key.
     * @param {string} group_member_uuid
     * @param {number} device_id
     * @param {Uint8Array} distribution_id
     * @param {Uint8Array} record_bytes
     * @returns {Promise<void>}
     */
    import_sender_key(group_member_uuid, device_id, distribution_id, record_bytes) {
        const ptr0 = passStringToWasm0(group_member_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(distribution_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(record_bytes, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_import_sender_key(this.__wbg_ptr, ptr0, len0, device_id, ptr1, len1, ptr2, len2);
        return ret;
    }
    /**
     * @returns {number}
     */
    get_next_prekey_id() {
        const ret = wasm.signalclient_get_next_prekey_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Export a Kyber PreKey.
     * @param {number} id
     * @returns {Promise<Uint8Array | undefined>}
     */
    export_kyber_prekey(id) {
        const ret = wasm.signalclient_export_kyber_prekey(this.__wbg_ptr, id);
        return ret;
    }
    /**
     * @returns {number}
     */
    get_local_device_id() {
        const ret = wasm.signalclient_get_local_device_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get_registration_id() {
        const ret = wasm.signalclient_get_registration_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Import a Kyber PreKey.
     * @param {number} id
     * @param {Uint8Array} record_bytes
     * @returns {Promise<void>}
     */
    import_kyber_prekey(id, record_bytes) {
        const ptr0 = passArray8ToWasm0(record_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_import_kyber_prekey(this.__wbg_ptr, id, ptr0, len0);
        return ret;
    }
    /**
     * Export a Signed PreKey.
     * @param {number} id
     * @returns {Promise<Uint8Array | undefined>}
     */
    export_signed_prekey(id) {
        const ret = wasm.signalclient_export_signed_prekey(this.__wbg_ptr, id);
        return ret;
    }
    /**
     * Import a Signed PreKey.
     * @param {number} id
     * @param {Uint8Array} record_bytes
     * @returns {Promise<void>}
     */
    import_signed_prekey(id, record_bytes) {
        const ptr0 = passArray8ToWasm0(record_bytes, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_import_signed_prekey(this.__wbg_ptr, id, ptr0, len0);
        return ret;
    }
    /**
     * Verify a scanned safety number.
     * @param {Uint8Array} scanned
     * @param {string} contact_uuid
     * @param {Uint8Array} contact_identity_key
     * @returns {boolean}
     */
    verify_safety_number(scanned, contact_uuid, contact_identity_key) {
        const ptr0 = passArray8ToWasm0(scanned, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(contact_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(contact_identity_key, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_verify_safety_number(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return ret[0] !== 0;
    }
    /**
     * Decrypt a group message.
     * @param {string} sender_uuid
     * @param {number} sender_device_id
     * @param {Uint8Array} ciphertext
     * @returns {Promise<Uint8Array>}
     */
    decrypt_group_message(sender_uuid, sender_device_id, ciphertext) {
        const ptr0 = passStringToWasm0(sender_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_decrypt_group_message(this.__wbg_ptr, ptr0, len0, sender_device_id, ptr1, len1);
        return ret;
    }
    /**
     * Encrypt a group message.
     * @param {Uint8Array} distribution_id
     * @param {Uint8Array} plaintext
     * @returns {Promise<Uint8Array>}
     */
    encrypt_group_message(distribution_id, plaintext) {
        const ptr0 = passArray8ToWasm0(distribution_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_encrypt_group_message(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        return ret;
    }
    /**
     * Generate a Kyber PreKey for post-quantum security.
     * Uses Kyber1024 (Signal production default).
     * NOTE: Manual implementation because KyberPreKeyRecord::generate has a bug
     * (OsRng.unwrap_err()) that panics in WASM.
     * @returns {WasmKyberPreKey}
     */
    generate_kyber_prekey() {
        const ret = wasm.signalclient_generate_kyber_prekey(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmKyberPreKey.__wrap(ret[0]);
    }
    /**
     * @returns {WasmIdentityKeyPair}
     */
    get_identity_key_pair() {
        const ret = wasm.signalclient_get_identity_key_pair(this.__wbg_ptr);
        return WasmIdentityKeyPair.__wrap(ret);
    }
    /**
     * Process a PreKeyBundle to establish a session.
     * @param {string} recipient_uuid
     * @param {number} recipient_device_id
     * @param {number} registration_id
     * @param {Uint8Array} identity_key
     * @param {number} signed_prekey_id
     * @param {Uint8Array} signed_prekey
     * @param {Uint8Array} signed_prekey_signature
     * @param {number | null | undefined} prekey_id
     * @param {Uint8Array | null | undefined} prekey
     * @param {number} kyber_prekey_id
     * @param {Uint8Array} kyber_prekey
     * @param {Uint8Array} kyber_prekey_signature
     * @returns {Promise<void>}
     */
    process_prekey_bundle(recipient_uuid, recipient_device_id, registration_id, identity_key, signed_prekey_id, signed_prekey, signed_prekey_signature, prekey_id, prekey, kyber_prekey_id, kyber_prekey, kyber_prekey_signature) {
        const ptr0 = passStringToWasm0(recipient_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(identity_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(signed_prekey, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(signed_prekey_signature, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        var ptr4 = isLikeNone(prekey) ? 0 : passArray8ToWasm0(prekey, wasm.__wbindgen_malloc);
        var len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(kyber_prekey, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passArray8ToWasm0(kyber_prekey_signature, wasm.__wbindgen_malloc);
        const len6 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_process_prekey_bundle(this.__wbg_ptr, ptr0, len0, recipient_device_id, registration_id, ptr1, len1, signed_prekey_id, ptr2, len2, ptr3, len3, isLikeNone(prekey_id) ? 0x100000001 : (prekey_id) >>> 0, ptr4, len4, kyber_prekey_id, ptr5, len5, ptr6, len6);
        return ret;
    }
    /**
     * Generate multiple Kyber PreKeys.
     * @param {number} count
     * @returns {Array<any>}
     */
    generate_kyber_prekeys(count) {
        const ret = wasm.signalclient_generate_kyber_prekeys(this.__wbg_ptr, count);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return takeFromExternrefTable0(ret[0]);
    }
    /**
     * Generate a safety number.
     * NOTE: We clone identity_key upfront to avoid wasm_bindgen aliasing issues.
     * @param {string} contact_uuid
     * @param {Uint8Array} contact_identity_key
     * @returns {WasmSafetyNumber}
     */
    generate_safety_number(contact_uuid, contact_identity_key) {
        const ptr0 = passStringToWasm0(contact_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(contact_identity_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_generate_safety_number(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmSafetyNumber.__wrap(ret[0]);
    }
    /**
     * Generate a signed PreKey.
     * @returns {WasmSignedPreKey}
     */
    generate_signed_prekey() {
        const ret = wasm.signalclient_generate_signed_prekey(this.__wbg_ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return WasmSignedPreKey.__wrap(ret[0]);
    }
    /**
     * @returns {Uint8Array}
     */
    get_identity_public_key() {
        const ret = wasm.signalclient_get_identity_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    get_next_kyber_prekey_id() {
        const ret = wasm.signalclient_get_next_kyber_prekey_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {number}
     */
    get_next_signed_prekey_id() {
        const ret = wasm.signalclient_get_next_signed_prekey_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * Create a sender key distribution message.
     * @param {Uint8Array} distribution_id
     * @returns {Promise<Uint8Array>}
     */
    create_sender_key_distribution(distribution_id) {
        const ptr0 = passArray8ToWasm0(distribution_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_create_sender_key_distribution(this.__wbg_ptr, ptr0, len0);
        return ret;
    }
    /**
     * Process a sender key distribution message.
     * @param {string} sender_uuid
     * @param {number} sender_device_id
     * @param {Uint8Array} distribution_message
     * @returns {Promise<void>}
     */
    process_sender_key_distribution(sender_uuid, sender_device_id, distribution_message) {
        const ptr0 = passStringToWasm0(sender_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(distribution_message, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_process_sender_key_distribution(this.__wbg_ptr, ptr0, len0, sender_device_id, ptr1, len1);
        return ret;
    }
    /**
     * Create a new SignalClient with a fresh identity.
     * @param {string} local_uuid
     * @param {number} local_device_id
     */
    constructor(local_uuid, local_device_id) {
        const ptr0 = passStringToWasm0(local_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_new(ptr0, len0, local_device_id);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0] >>> 0;
        SignalClientFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * Restore a SignalClient from previously saved state.
     * @param {Uint8Array} identity_public_key
     * @param {Uint8Array} identity_private_key
     * @param {number} registration_id
     * @param {string} local_uuid
     * @param {number} local_device_id
     * @param {number} next_prekey_id
     * @param {number} next_signed_prekey_id
     * @param {number} next_kyber_prekey_id
     * @returns {SignalClient}
     */
    static restore(identity_public_key, identity_private_key, registration_id, local_uuid, local_device_id, next_prekey_id, next_signed_prekey_id, next_kyber_prekey_id) {
        const ptr0 = passArray8ToWasm0(identity_public_key, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(identity_private_key, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(local_uuid, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.signalclient_restore(ptr0, len0, ptr1, len1, registration_id, ptr2, len2, local_device_id, next_prekey_id, next_signed_prekey_id, next_kyber_prekey_id);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return SignalClient.__wrap(ret[0]);
    }
}

const WasmCiphertextFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmciphertext_free(ptr >>> 0, 1));
/**
 * Encrypted message result
 */
export class WasmCiphertext {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmCiphertext.prototype);
        obj.__wbg_ptr = ptr;
        WasmCiphertextFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmCiphertextFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmciphertext_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    get message_type() {
        const ret = wasm.wasmciphertext_message_type(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {Uint8Array}
     */
    get body() {
        const ret = wasm.wasmciphertext_body(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}

const WasmIdentityKeyPairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmidentitykeypair_free(ptr >>> 0, 1));
/**
 * Represents a generated identity key pair
 */
export class WasmIdentityKeyPair {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmIdentityKeyPair.prototype);
        obj.__wbg_ptr = ptr;
        WasmIdentityKeyPairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmIdentityKeyPairFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmidentitykeypair_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.wasmidentitykeypair_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Get the private key bytes (zeroized on drop)
     * @returns {Uint8Array}
     */
    get private_key() {
        const ret = wasm.wasmidentitykeypair_private_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}

const WasmKyberPreKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmkyberprekey_free(ptr >>> 0, 1));
/**
 * A Kyber (post-quantum) PreKey for upload to the server
 */
export class WasmKyberPreKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmKyberPreKey.prototype);
        obj.__wbg_ptr = ptr;
        WasmKyberPreKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmKyberPreKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmkyberprekey_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.wasmkyberprekey_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    get id() {
        const ret = wasm.wasmkyberprekey_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    get signature() {
        const ret = wasm.wasmkyberprekey_signature(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {bigint}
     */
    get timestamp() {
        const ret = wasm.wasmkyberprekey_timestamp(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
}

const WasmPreKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmprekey_free(ptr >>> 0, 1));
/**
 * A single PreKey for upload to the server
 */
export class WasmPreKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmPreKey.prototype);
        obj.__wbg_ptr = ptr;
        WasmPreKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmPreKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmprekey_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.wasmprekey_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    get id() {
        const ret = wasm.wasmprekey_id(this.__wbg_ptr);
        return ret >>> 0;
    }
}

const WasmSafetyNumberFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmsafetynumber_free(ptr >>> 0, 1));
/**
 * Safety number for identity verification
 */
export class WasmSafetyNumber {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmSafetyNumber.prototype);
        obj.__wbg_ptr = ptr;
        WasmSafetyNumberFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmSafetyNumberFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmsafetynumber_free(ptr, 0);
    }
    /**
     * @returns {string}
     */
    get displayable() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.wasmsafetynumber_displayable(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    get scannable() {
        const ret = wasm.wasmsafetynumber_scannable(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}

const WasmSignedPreKeyFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_wasmsignedprekey_free(ptr >>> 0, 1));
/**
 * A signed PreKey for upload to the server
 */
export class WasmSignedPreKey {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(WasmSignedPreKey.prototype);
        obj.__wbg_ptr = ptr;
        WasmSignedPreKeyFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        WasmSignedPreKeyFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_wasmsignedprekey_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    get public_key() {
        const ret = wasm.wasmsignedprekey_public_key(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {number}
     */
    get id() {
        const ret = wasm.wasmkyberprekey_id(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    get signature() {
        const ret = wasm.wasmsignedprekey_signature(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {bigint}
     */
    get timestamp() {
        const ret = wasm.wasmkyberprekey_timestamp(this.__wbg_ptr);
        return BigInt.asUintN(64, ret);
    }
}

const EXPECTED_RESPONSE_TYPES = new Set(['basic', 'cors', 'default']);

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);

            } catch (e) {
                const validResponse = module.ok && EXPECTED_RESPONSE_TYPES.has(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else {
                    throw e;
                }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);

    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };

        } else {
            return instance;
        }
    }
}

function __wbg_get_imports() {
    const imports = {};
    imports.wbg = {};
    imports.wbg.__wbg_call_2f8d426a20a307fe = function() { return handleError(function (arg0, arg1) {
        const ret = arg0.call(arg1);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_call_f53f0647ceb9c567 = function() { return handleError(function (arg0, arg1, arg2) {
        const ret = arg0.call(arg1, arg2);
        return ret;
    }, arguments) };
    imports.wbg.__wbg_error_7534b8e9a36f1ab4 = function(arg0, arg1) {
        let deferred0_0;
        let deferred0_1;
        try {
            deferred0_0 = arg0;
            deferred0_1 = arg1;
            console.error(getStringFromWasm0(arg0, arg1));
        } finally {
            wasm.__wbindgen_free(deferred0_0, deferred0_1, 1);
        }
    };
    imports.wbg.__wbg_getRandomValues_38a1ff1ea09f6cc7 = function() { return handleError(function (arg0, arg1) {
        globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
    }, arguments) };
    imports.wbg.__wbg_getRandomValues_3c9c0d586e575a16 = function() { return handleError(function (arg0, arg1) {
        globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
    }, arguments) };
    imports.wbg.__wbg_log_f3c04200b995730f = function(arg0) {
        console.log(arg0);
    };
    imports.wbg.__wbg_new_8a6f238a6ece86ea = function() {
        const ret = new Error();
        return ret;
    };
    imports.wbg.__wbg_new_d5e3800b120e37e1 = function(arg0, arg1) {
        try {
            var state0 = {a: arg0, b: arg1};
            var cb0 = (arg0, arg1) => {
                const a = state0.a;
                state0.a = 0;
                try {
                    return __wbg_adapter_104(a, state0.b, arg0, arg1);
                } finally {
                    state0.a = a;
                }
            };
            const ret = new Promise(cb0);
            return ret;
        } finally {
            state0.a = state0.b = 0;
        }
    };
    imports.wbg.__wbg_new_e969dc3f68d25093 = function() {
        const ret = new Array();
        return ret;
    };
    imports.wbg.__wbg_newnoargs_a81330f6e05d8aca = function(arg0, arg1) {
        const ret = new Function(getStringFromWasm0(arg0, arg1));
        return ret;
    };
    imports.wbg.__wbg_now_e3057dd824ca0191 = function() {
        const ret = Date.now();
        return ret;
    };
    imports.wbg.__wbg_push_cd3ac7d5b094565d = function(arg0, arg1) {
        const ret = arg0.push(arg1);
        return ret;
    };
    imports.wbg.__wbg_queueMicrotask_bcc6e26d899696db = function(arg0) {
        const ret = arg0.queueMicrotask;
        return ret;
    };
    imports.wbg.__wbg_queueMicrotask_f24a794d09c42640 = function(arg0) {
        queueMicrotask(arg0);
    };
    imports.wbg.__wbg_resolve_5775c0ef9222f556 = function(arg0) {
        const ret = Promise.resolve(arg0);
        return ret;
    };
    imports.wbg.__wbg_stack_0ed75d68575b0f3c = function(arg0, arg1) {
        const ret = arg1.stack;
        const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
        getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_1f13249cc3acc96d = function() {
        const ret = typeof global === 'undefined' ? null : global;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_GLOBAL_THIS_df7ae94b1e0ed6a3 = function() {
        const ret = typeof globalThis === 'undefined' ? null : globalThis;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_SELF_6265471db3b3c228 = function() {
        const ret = typeof self === 'undefined' ? null : self;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_static_accessor_WINDOW_16fb482f8ec52863 = function() {
        const ret = typeof window === 'undefined' ? null : window;
        return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
    };
    imports.wbg.__wbg_then_9cc266be2bf537b6 = function(arg0, arg1) {
        const ret = arg0.then(arg1);
        return ret;
    };
    imports.wbg.__wbg_wasmciphertext_new = function(arg0) {
        const ret = WasmCiphertext.__wrap(arg0);
        return ret;
    };
    imports.wbg.__wbg_wasmkyberprekey_new = function(arg0) {
        const ret = WasmKyberPreKey.__wrap(arg0);
        return ret;
    };
    imports.wbg.__wbg_wasmprekey_new = function(arg0) {
        const ret = WasmPreKey.__wrap(arg0);
        return ret;
    };
    imports.wbg.__wbg_wbindgencbdrop_a85ed476c6a370b9 = function(arg0) {
        const obj = arg0.original;
        if (obj.cnt-- == 1) {
            obj.a = 0;
            return true;
        }
        const ret = false;
        return ret;
    };
    imports.wbg.__wbg_wbindgenisfunction_ea72b9d66a0e1705 = function(arg0) {
        const ret = typeof(arg0) === 'function';
        return ret;
    };
    imports.wbg.__wbg_wbindgenisundefined_71f08a6ade4354e7 = function(arg0) {
        const ret = arg0 === undefined;
        return ret;
    };
    imports.wbg.__wbg_wbindgenthrow_4c11a24fca429ccf = function(arg0, arg1) {
        throw new Error(getStringFromWasm0(arg0, arg1));
    };
    imports.wbg.__wbindgen_cast_2241b6af4c4b2941 = function(arg0, arg1) {
        // Cast intrinsic for `Ref(String) -> Externref`.
        const ret = getStringFromWasm0(arg0, arg1);
        return ret;
    };
    imports.wbg.__wbindgen_cast_77bc3e92745e9a35 = function(arg0, arg1) {
        var v0 = getArrayU8FromWasm0(arg0, arg1).slice();
        wasm.__wbindgen_free(arg0, arg1 * 1, 1);
        // Cast intrinsic for `Vector(U8) -> Externref`.
        const ret = v0;
        return ret;
    };
    imports.wbg.__wbindgen_cast_e8a172ac6c6e4a4a = function(arg0, arg1) {
        // Cast intrinsic for `Closure(Closure { dtor_idx: 156, function: Function { arguments: [Externref], shim_idx: 157, ret: Unit, inner_ret: Some(Unit) }, mutable: true }) -> Externref`.
        const ret = makeMutClosure(arg0, arg1, 156, __wbg_adapter_6);
        return ret;
    };
    imports.wbg.__wbindgen_init_externref_table = function() {
        const table = wasm.__wbindgen_export_2;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
        ;
    };

    return imports;
}

function __wbg_init_memory(imports, memory) {

}

function __wbg_finalize_init(instance, module) {
    wasm = instance.exports;
    __wbg_init.__wbindgen_wasm_module = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;


    wasm.__wbindgen_start();
    return wasm;
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (typeof module !== 'undefined') {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();

    __wbg_init_memory(imports);

    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }

    const instance = new WebAssembly.Instance(module, imports);

    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (typeof module_or_path !== 'undefined') {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (typeof module_or_path === 'undefined') {
        module_or_path = new URL('libsignal_wasm_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    __wbg_init_memory(imports);

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync };
export default __wbg_init;
