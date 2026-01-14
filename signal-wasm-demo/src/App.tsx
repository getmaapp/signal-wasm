import { useCallback, useRef, useState } from "react";
import "./App.css";
import {
  clearStorage,
  initDB,
  loadIdentity,
  loadKyberPreKeys,
  loadPreKeys,
  loadSignedPreKeys,
  saveIdentity,
  saveKyberPreKey,
  savePreKey,
  saveSenderKey,
  saveSession,
  saveSignedPreKey,
} from "./lib/storage";
import init, {
  generate_random_bytes,
  generate_uuid,
  message_type_prekey,
  message_type_signal,
  SignalClient,
  uuid_to_string,
  WasmKyberPreKey,
  WasmPreKey,
  WasmSafetyNumber,
  WasmSignedPreKey,
} from "./lib/wasm/libsignal_wasm";

// Log entry type
interface LogEntry {
  id: number;
  time: string;
  type: "info" | "success" | "error" | "data";
  message: string;
  data?: string;
}

// Hex encoding helper
const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const toHexTruncated = (bytes: Uint8Array, maxLen = 32): string => {
  const hex = toHex(bytes);
  return hex.length > maxLen * 2 ? hex.slice(0, maxLen * 2) + "..." : hex;
};

function App() {
  const [wasmReady, setWasmReady] = useState(false);
  const [client, setClient] = useState<SignalClient | null>(null);
  const [bobClient, setBobClient] = useState<SignalClient | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  // Use ref for log ID to handle Strict Mode double-invocation correctly
  const logIdRef = useRef(0);

  // Add log entry
  const log = useCallback(
    (type: LogEntry["type"], message: string, data?: string) => {
      const newId = logIdRef.current + 1;
      logIdRef.current = newId;
      setLogs((prev) => [
        ...prev,
        {
          id: newId,
          time: new Date().toLocaleTimeString(),
          type,
          message,
          data,
        },
      ]);
    },
    []
  );

  // Initialise WASM & DB
  const initWasm = async () => {
    try {
      log("info", "Initialising WASM module...");
      await init();
      await initDB();
      setWasmReady(true);
      log("success", "✅ WASM module initialised & DB ready!");
    } catch (e) {
      log("error", `Failed to init: ${e}`);
    }
  };

  const persistIdentity = async (c: SignalClient) => {
    try {
      await saveIdentity({
        uuid: c.get_local_uuid(),
        deviceId: c.get_local_device_id(),
        registrationId: c.get_registration_id(),
        identityPublic: c.get_identity_public_key(),
        identityPrivate: c.get_identity_key_pair().private_key,
        nextPreKeyId: c.get_next_prekey_id(),
        nextSignedPreKeyId: c.get_next_signed_prekey_id(),
        nextKyberPreKeyId: c.get_next_kyber_prekey_id(),
      });
    } catch (e) {
      log("error", `Failed to save identity: ${e}`);
    }
  };

  // Create/Restore client (Alice)
  const createClient = async () => {
    const ALICE_UUID = "00000000-0000-4000-a000-000000000001"; // Fixed for demo
    try {
      let alice = await loadIdentity(ALICE_UUID);
      let newClient: SignalClient;

      if (alice) {
        log("info", "Restoring Alice from DB...");
        newClient = SignalClient.restore(
          alice.identityPublic,
          alice.identityPrivate,
          alice.registrationId,
          alice.uuid,
          alice.deviceId,
          alice.nextPreKeyId,
          alice.nextSignedPreKeyId,
          alice.nextKyberPreKeyId
        );
        log("success", "✅ Alice restored from storage");
        await ensureKeys(newClient);
      } else {
        log("info", "Creating new Alice client...");
        newClient = new SignalClient(ALICE_UUID, 1);
        await persistIdentity(newClient);
        log("success", "✅ Alice created & saved");
        await initializeKeys(newClient);
      }
      setClient(newClient);
    } catch (e) {
      log("error", `Failed to load Alice: ${e}`);
    }
  };

  // Create/Restore Bob
  const createBobClient = async () => {
    const BOB_UUID = "00000000-0000-4000-a000-000000000002"; // Fixed for demo
    try {
      let bob = await loadIdentity(BOB_UUID);
      let newClient: SignalClient;

      if (bob) {
        log("info", "Restoring Bob from DB...");
        newClient = SignalClient.restore(
          bob.identityPublic,
          bob.identityPrivate,
          bob.registrationId,
          bob.uuid,
          bob.deviceId,
          bob.nextPreKeyId,
          bob.nextSignedPreKeyId,
          bob.nextKyberPreKeyId
        );
        log("success", "✅ Bob restored from storage");
        await ensureKeys(newClient);
      } else {
        log("info", "Creating new Bob client...");
        newClient = new SignalClient(BOB_UUID, 1);
        await persistIdentity(newClient);
        log("success", "✅ Bob created & saved");
        await initializeKeys(newClient);
      }
      setBobClient(newClient);
    } catch (e) {
      log("error", `Failed to load Bob: ${e}`);
    }
  };

  const initializeKeys = async (c: SignalClient) => {
    await generatePreKeys(c);
    await generateSignedPreKey(c);
    await generateKyberPreKey(c);
  };

  const ensureKeys = async (c: SignalClient) => {
    const uuid = c.get_local_uuid();
    const pks = await loadPreKeys(uuid);
    const spks = await loadSignedPreKeys(uuid);
    const kpks = await loadKyberPreKeys(uuid);

    if (pks.length === 0 || spks.length === 0 || kpks.length === 0) {
      log("info", "Missing keys detected on restore. Generating...");
      await initializeKeys(c);
    }
  };

  // Get identity key pair
  const getIdentityKey = () => {
    if (!client) return;
    try {
      const keyPair = client.get_identity_key_pair();
      log(
        "data",
        "🔑 Identity Key Pair",
        JSON.stringify(
          {
            publicKey: toHexTruncated(keyPair.public_key),
            privateKey: toHexTruncated(keyPair.private_key),
            publicKeyLength: keyPair.public_key.length,
            privateKeyLength: keyPair.private_key.length,
          },
          null,
          2
        )
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Generate PreKeys
  const generatePreKeys = async (c?: SignalClient) => {
    const target = c || client;
    if (!target) return;
    try {
      log(
        "info",
        `Generating 10 PreKeys for ${target.get_local_uuid().slice(-4)}...`
      );
      const prekeys = target.generate_prekeys(10) as WasmPreKey[];

      // Persist
      const uuid = target.get_local_uuid();
      for (const pk of prekeys) {
        await savePreKey({
          uuid,
          id: pk.id,
          publicKey: pk.public_key,
        });
      }
      await persistIdentity(target); // Update counters

      log(
        "success",
        `✅ Generated ${prekeys.length} PreKeys`,
        JSON.stringify(
          prekeys.slice(0, 3).map((pk) => ({
            id: pk.id,
            publicKey: toHexTruncated(pk.public_key),
          })),
          null,
          2
        ) + `\n... and ${prekeys.length - 3} more`
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Generate Signed PreKey
  const generateSignedPreKey = async (c?: SignalClient) => {
    const target = c || client;
    if (!target) return;
    try {
      log("info", "Generating Signed PreKey...");
      const spk = target.generate_signed_prekey() as WasmSignedPreKey;

      await saveSignedPreKey({
        uuid: target.get_local_uuid(),
        id: spk.id,
        publicKey: spk.public_key,
        signature: spk.signature,
        timestamp: Number(spk.timestamp),
      });
      await persistIdentity(target); // Update counters

      log(
        "success",
        "✅ Signed PreKey generated",
        JSON.stringify(
          {
            id: spk.id,
            publicKey: toHexTruncated(spk.public_key),
            signature: toHexTruncated(spk.signature),
            timestamp: new Date(Number(spk.timestamp)).toISOString(),
          },
          null,
          2
        )
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Generate Kyber PreKey
  const generateKyberPreKey = async (c?: SignalClient) => {
    const target = c || client;
    if (!target) return;
    try {
      log("info", "Generating Kyber PreKey (PQXDH)...");
      const kpk = target.generate_kyber_prekey() as WasmKyberPreKey;

      await saveKyberPreKey({
        uuid: target.get_local_uuid(),
        id: kpk.id,
        publicKey: kpk.public_key,
        signature: kpk.signature,
        timestamp: Number(kpk.timestamp),
      });
      await persistIdentity(target);

      log(
        "success",
        "✅ Kyber PreKey generated (post-quantum)",
        JSON.stringify(
          {
            id: kpk.id,
            publicKeyLength: kpk.public_key.length,
            publicKey: toHexTruncated(kpk.public_key, 64),
            signatureLength: kpk.signature.length,
          },
          null,
          2
        )
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Generate Safety Number
  const generateSafetyNumber = () => {
    if (!client || !bobClient) {
      log("error", "Need both Alice and Bob clients");
      return;
    }
    try {
      log("info", "Generating safety number...");
      const bobPubKey = bobClient.get_identity_public_key();
      const bobUuid = bobClient.get_local_uuid();
      const safetyNumber = client.generate_safety_number(
        bobUuid,
        bobPubKey
      ) as WasmSafetyNumber;
      log(
        "success",
        "✅ Safety number generated",
        JSON.stringify(
          {
            displayable: safetyNumber.displayable,
            scannableLength: safetyNumber.scannable.length,
          },
          null,
          2
        )
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Random bytes demo
  const generateRandomBytes = () => {
    try {
      const bytes = generate_random_bytes(32);
      log("data", "🎲 Random bytes (32)", toHex(bytes));
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // UUID demo
  const generateUUID = () => {
    try {
      const uuidBytes = generate_uuid();
      const uuidStr = uuid_to_string(uuidBytes);
      log("data", "🆔 Generated UUID", uuidStr);
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Message type constants
  const showMessageTypes = () => {
    log(
      "data",
      "📨 Message Types",
      JSON.stringify(
        {
          SIGNAL_MESSAGE: message_type_signal(),
          PREKEY_MESSAGE: message_type_prekey(),
        },
        null,
        2
      )
    );
  };

  // Export/import session demo
  // Export/import session demo
  const exportImportDemo = async () => {
    if (!client) return;
    const BOB_UUID = "00000000-0000-4000-a000-000000000002";
    try {
      log("info", `Testing session export for Bob (${BOB_UUID.slice(-4)})...`);
      const exported = await client.export_session(BOB_UUID, 1);
      log(
        "data",
        "Session export result",
        exported
          ? `✅ ${exported.length} bytes exported`
          : "⚠️ null (No active session with Bob)"
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // ----------------------------------------------------------------------
  // 1:1 Messaging
  // ----------------------------------------------------------------------

  const establishSession = async () => {
    if (!client || !bobClient) {
      log("error", "Need both clients");
      return;
    }
    try {
      log("info", "Establishing session (Alice -> Bob)...");

      // 1. Alice fetches Bob's bundle (simulated from DB/Bob client)
      const bobUuid = bobClient.get_local_uuid();
      const bobDevId = bobClient.get_local_device_id();
      const bobRegId = bobClient.get_registration_id();
      const bobIdentity = bobClient.get_identity_public_key();

      const bobSignedPreKeys = await loadSignedPreKeys(bobUuid);
      const bobKyberPreKeys = await loadKyberPreKeys(bobUuid);
      const bobPreKeys = await loadPreKeys(bobUuid);

      if (
        !bobSignedPreKeys.length ||
        !bobKyberPreKeys.length ||
        !bobPreKeys.length
      ) {
        log("error", "Bob needs to generate keys first!");
        return;
      }

      const signedPreKey = bobSignedPreKeys[0]; // Just take first
      const kyberPreKey = bobKyberPreKeys[0];
      const oneTimePreKey = bobPreKeys[0];

      // 2. Alice processes bundle
      await client.process_prekey_bundle(
        bobUuid,
        bobDevId,
        bobRegId,
        bobIdentity,
        signedPreKey.id,
        signedPreKey.publicKey,
        signedPreKey.signature,
        oneTimePreKey.id,
        oneTimePreKey.publicKey,
        kyberPreKey.id,
        kyberPreKey.publicKey,
        kyberPreKey.signature
      );

      // 3. Persist Alice's session state
      const serializedSession = await client.export_session(bobUuid, bobDevId);
      if (serializedSession) {
        await saveSession({
          localUuid: client.get_local_uuid(),
          remoteUuid: bobUuid,
          remoteDeviceId: bobDevId,
          record: serializedSession,
        });
      }

      log("success", "✅ Session established!");
    } catch (e) {
      log("error", `Session failed: ${e}`);
    }
  };

  const encryptMessage = async () => {
    if (!client || !bobClient) return;
    try {
      const bobUuid = bobClient.get_local_uuid();
      const bobDevId = bobClient.get_local_device_id();
      const plaintext = new TextEncoder().encode("Hello Bob! 🔒");

      const ciphertext = await client.encrypt_message(
        bobUuid,
        bobDevId,
        plaintext
      );

      // Persist updated session
      const session = await client.export_session(bobUuid, bobDevId);
      if (session) {
        await saveSession({
          localUuid: client.get_local_uuid(),
          remoteUuid: bobUuid,
          remoteDeviceId: bobDevId,
          record: session,
        });
      }

      log(
        "data",
        `Encrypted to Bob (Type ${ciphertext.message_type})`,
        toHexTruncated(ciphertext.body)
      );

      // Store for Bob to pick up
      (window as any).__lastMessage = {
        ciphertext: ciphertext.body,
        type: ciphertext.message_type,
        senderUuid: client.get_local_uuid(),
        senderDeviceId: client.get_local_device_id(),
      };
    } catch (e) {
      log("error", `Encrypt failed: ${e}`);
    }
  };

  const decryptMessage = async () => {
    if (!bobClient) return;
    try {
      const msg = (window as any).__lastMessage;
      if (!msg) {
        log("error", "No message to decrypt");
        return;
      }

      const plaintext = await bobClient.decrypt_message(
        msg.senderUuid,
        msg.senderDeviceId,
        msg.ciphertext,
        msg.type
      );

      // Persist Bob's updated session
      const session = await bobClient.export_session(
        msg.senderUuid,
        msg.senderDeviceId
      );
      if (session) {
        await saveSession({
          localUuid: bobClient.get_local_uuid(),
          remoteUuid: msg.senderUuid,
          remoteDeviceId: msg.senderDeviceId,
          record: session,
        });
      }

      log(
        "success",
        `🔓 Decrypted from Alice`,
        new TextDecoder().decode(plaintext)
      );
    } catch (e) {
      log("error", `Decrypt failed: ${e}`);
    }
  };

  // ----------------------------------------------------------------------
  // Group Messaging
  // ----------------------------------------------------------------------

  const createGroupSession = async () => {
    if (!client) return;
    try {
      const groupDistId = generate_uuid(); // Unique ID for this group session (SenderKeyName)
      const skdm = await client.create_sender_key_distribution(groupDistId);

      // Persist Alice's SenderKey state
      const record = await client.export_sender_key(
        client.get_local_uuid(),
        1,
        groupDistId
      );
      if (record) {
        await saveSenderKey({
          localUuid: client.get_local_uuid(),
          remoteUuid: client.get_local_uuid(), // Self
          remoteDeviceId: 1,
          distributionId: uuid_to_string(groupDistId),
          record,
        });
      }

      log("data", "Created Group Distribution", toHexTruncated(skdm));
      (window as any).__groupDistId = groupDistId;
      (window as any).__lastInfoMessage = {
        senderUuid: client.get_local_uuid(),
        senderDeviceId: client.get_local_device_id(),
        distMessage: skdm,
      };
    } catch (e) {
      log("error", `Group init failed: ${e}`);
    }
  };

  const processGroupSession = async () => {
    if (!bobClient) return;
    try {
      const info = (window as any).__lastInfoMessage;
      const groupDistId = (window as any).__groupDistId;
      if (!info) {
        log("error", "No distribution message found");
        return;
      }

      await bobClient.process_sender_key_distribution(
        info.senderUuid,
        info.senderDeviceId,
        info.distMessage
      );

      // Persist Bob's sender key state
      const record = await bobClient.export_sender_key(
        info.senderUuid,
        info.senderDeviceId,
        groupDistId
      );
      if (record) {
        await saveSenderKey({
          localUuid: bobClient.get_local_uuid(),
          remoteUuid: info.senderUuid,
          remoteDeviceId: info.senderDeviceId,
          distributionId: uuid_to_string(groupDistId),
          record,
        });
      }

      log("success", "✅ Bob joined group session");
    } catch (e) {
      log("error", `Join group failed: ${e}`);
    }
  };

  const encryptGroupMessage = async () => {
    if (!client) return;
    try {
      const groupDistId = (window as any).__groupDistId;
      if (!groupDistId) {
        log("error", "No group session");
        return;
      }

      const plaintext = new TextEncoder().encode("Hello Group! 📢");
      const ciphertext = await client.encrypt_group_message(
        groupDistId,
        plaintext
      );

      // Persist Alice's updated state (chain advanced)
      const record = await client.export_sender_key(
        client.get_local_uuid(),
        1,
        groupDistId
      );
      if (record) {
        await saveSenderKey({
          localUuid: client.get_local_uuid(),
          remoteUuid: client.get_local_uuid(),
          remoteDeviceId: 1,
          distributionId: uuid_to_string(groupDistId),
          record,
        });
      }

      log("data", "Encrypted Group Msg", toHexTruncated(ciphertext));

      (window as any).__lastGroupMessage = {
        ciphertext,
        senderUuid: client.get_local_uuid(),
        senderDeviceId: 1,
      };
    } catch (e) {
      log("error", `Group encrypt failed: ${e}`);
    }
  };

  const decryptGroupMessage = async () => {
    if (!bobClient) return;
    try {
      const msg = (window as any).__lastGroupMessage;
      if (!msg) {
        log("error", "No group message");
        return;
      }

      const plaintext = await bobClient.decrypt_group_message(
        msg.senderUuid,
        msg.senderDeviceId,
        msg.ciphertext
      );

      // Persist Bob's state (don't usually need to for decrypt unless loose Ratchet, but good practice)
      // Note: Sender Keys don't ratchet on decrypt in the same way, but let's be safe.
      const groupDistId = (window as any).__groupDistId;
      const record = await bobClient.export_sender_key(
        msg.senderUuid,
        msg.senderDeviceId,
        groupDistId
      );
      if (record) {
        await saveSenderKey({
          localUuid: bobClient.get_local_uuid(),
          remoteUuid: msg.senderUuid,
          remoteDeviceId: msg.senderDeviceId,
          distributionId: uuid_to_string(groupDistId),
          record,
        });
      }

      log(
        "success",
        "📢 Group Msg Decrypted",
        new TextDecoder().decode(plaintext)
      );
    } catch (e) {
      log("error", `Group decrypt failed: ${e}`);
    }
  };

  // Clear logs
  // Reset storage
  const handleReset = async () => {
    if (confirm("Clear all persisted data?")) {
      await clearStorage();
      setClient(null);
      setBobClient(null);
      setLogs([]);
      log("success", "Storage cleared");
    }
  };

  const clearLogs = () => setLogs([]);

  return (
    <div className="app">
      <header>
        <h1>🔐 libsignal-wasm Demo</h1>
        <p>Signal Protocol in the browser via WebAssembly</p>
      </header>

      <main>
        <section className="controls">
          <h2>Controls</h2>

          <div className="button-group">
            <h3>Initialisation</h3>
            <button onClick={initWasm} disabled={wasmReady}>
              {wasmReady ? "✅ WASM Ready" : "1. Init WASM"}
            </button>
            <button onClick={createClient} disabled={!wasmReady || !!client}>
              {client ? "✅ Alice Ready" : "2. Create Alice"}
            </button>
            <button
              onClick={createBobClient}
              disabled={!wasmReady || !!bobClient}
            >
              {bobClient ? "✅ Bob Ready" : "3. Create Bob"}
            </button>
          </div>

          <div className="button-group">
            <h3>Key Operations</h3>
            <button onClick={getIdentityKey} disabled={!client}>
              Identity Key
            </button>
            <button onClick={() => generatePreKeys()} disabled={!client}>
              PreKeys (10)
            </button>
            <button onClick={() => generateSignedPreKey()} disabled={!client}>
              Signed PreKey
            </button>
            <button onClick={() => generateKyberPreKey()} disabled={!client}>
              Kyber PreKey
            </button>
          </div>

          <div className="button-group">
            <h3>Crypto Operations</h3>
            <button
              onClick={generateSafetyNumber}
              disabled={!client || !bobClient}
            >
              Safety Number
            </button>
            <button onClick={generateRandomBytes} disabled={!wasmReady}>
              Random Bytes
            </button>
            <button onClick={generateUUID} disabled={!wasmReady}>
              Generate UUID
            </button>
          </div>

          <div className="button-group">
            <h3>Utilities</h3>
            <button onClick={showMessageTypes} disabled={!wasmReady}>
              Message Types
            </button>
            <button onClick={exportImportDemo} disabled={!client}>
              Export Session
            </button>
          </div>

          <div className="button-group">
            <h3>1:1 Messaging</h3>
            <button onClick={establishSession} disabled={!client || !bobClient}>
              1. Alice→Bob Session
            </button>
            <button onClick={encryptMessage} disabled={!client || !bobClient}>
              2. Alice Encrypt
            </button>
            <button onClick={decryptMessage} disabled={!bobClient}>
              3. Bob Decrypt
            </button>
          </div>

          <div className="button-group">
            <h3>Group Messaging</h3>
            <button onClick={createGroupSession} disabled={!client}>
              1. Create Group
            </button>
            <button onClick={processGroupSession} disabled={!bobClient}>
              2. Bob Join
            </button>
            <button onClick={encryptGroupMessage} disabled={!client}>
              3. Alice Send
            </button>
            <button onClick={decryptGroupMessage} disabled={!bobClient}>
              4. Bob Read
            </button>
          </div>

          <div className="button-group">
            <h3>System</h3>
            <button onClick={handleReset} className="secondary">
              Reset Storage
            </button>
            <button onClick={clearLogs} className="secondary">
              Clear Logs
            </button>
          </div>
        </section>

        <section className="log-panel">
          <h2>Activity Log</h2>
          <div className="logs">
            {logs.length === 0 && (
              <div className="log-empty">Click "Init WASM" to start</div>
            )}
            {logs.map((entry) => (
              <div key={entry.id} className={`log-entry log-${entry.type}`}>
                <span className="log-time">{entry.time}</span>
                <span className="log-message">{entry.message}</span>
                {entry.data && <pre className="log-data">{entry.data}</pre>}
              </div>
            ))}
          </div>
        </section>
      </main>

      <footer>
        <p>libsignal v0.86.11 • WASM • React 19 • Vite • IndexedDB</p>
      </footer>
    </div>
  );
}

export default App;
