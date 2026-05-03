import { useCallback, useRef, useState } from "react";
import init, {
  generate_random_bytes,
  generate_uuid,
  message_type_pre_key,
  message_type_signal,
  PrivateKey,
  PublicKey,
  IdentityKeyPair,
  ProtocolAddress,
  InMemIdentityKeyStore,
  InMemSessionStore,
  InMemPreKeyStore,
  InMemSignedPreKeyStore,
  InMemKyberPreKeyStore,
  InMemSenderKeyStore,
  generatePreKeys,
  generateSignedPreKey,
  generateKyberPreKey,
  generateRegistrationId,
  generateSafetyNumber,
  verifySafetyNumber,
  processPreKeyBundle,
  encryptMessage,
  decryptMessage,
  createSenderKeyDistribution,
  processSenderKeyDistribution,
  encryptGroupMessage,
  decryptGroupMessage,
  WasmPreKey,
  WasmSignedPreKey,
  WasmKyberPreKey,
  WasmCiphertext,
  WasmSafetyNumber,
} from "signal-wasm";
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

interface LogEntry {
  id: number;
  time: string;
  type: "info" | "success" | "error" | "data";
  message: string;
  data?: string;
}

interface ClientState {
  uuid: string;
  deviceId: number;
  identityKeyPair: IdentityKeyPair;
  registrationId: number;
  sessionStore: InMemSessionStore;
  identityStore: InMemIdentityKeyStore;
  prekeyStore: InMemPreKeyStore;
  signedPrekeyStore: InMemSignedPreKeyStore;
  kyberPrekeyStore: InMemKyberPreKeyStore;
  senderKeyStore: InMemSenderKeyStore;
  nextPreKeyId: number;
  nextSignedPreKeyId: number;
  nextKyberPreKeyId: number;
}

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
  const [client, setClient] = useState<ClientState | null>(null);
  const [bobClient, setBobClient] = useState<ClientState | null>(null);
  const [aliceName, setAliceName] = useState("Alice");
  const [bobName, setBobName] = useState("Bob");
  const [logs, setLogs] = useState<LogEntry[]>([]);

  const logIdRef = useRef(0);

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
    [],
  );

  const getUuidForName = (name: string) => {
    // For this independent web app, identifiers can be any string
    // (Firebase UIDs, usernames, etc.). We use them directly.
    if (name === "Alice") return "alice_firebase_uid_123";
    if (name === "Bob") return "bob_firebase_uid_456";
    return name;
  };

  const createClientState = (
    uuid: string,
    deviceId: number,
    identityKeyPair: IdentityKeyPair,
    registrationId: number,
    nextPreKeyId: number,
    nextSignedPreKeyId: number,
    nextKyberPreKeyId: number,
  ): ClientState => {
    const identityStore = new InMemIdentityKeyStore(identityKeyPair, registrationId);
    return {
      uuid,
      deviceId,
      identityKeyPair,
      registrationId,
      sessionStore: new InMemSessionStore(),
      identityStore,
      prekeyStore: new InMemPreKeyStore(),
      signedPrekeyStore: new InMemSignedPreKeyStore(),
      kyberPrekeyStore: new InMemKyberPreKeyStore(),
      senderKeyStore: new InMemSenderKeyStore(),
      nextPreKeyId,
      nextSignedPreKeyId,
      nextKyberPreKeyId,
    };
  };

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

  const persistIdentity = async (c: ClientState) => {
    try {
      await saveIdentity({
        uuid: c.uuid,
        deviceId: c.deviceId,
        registrationId: c.registrationId,
        identityPublic: c.identityKeyPair.public_key().serialize(),
        identityPrivate: c.identityKeyPair.private_key().serialize(),
        nextPreKeyId: c.nextPreKeyId,
        nextSignedPreKeyId: c.nextSignedPreKeyId,
        nextKyberPreKeyId: c.nextKyberPreKeyId,
      });
    } catch (e) {
      log("error", `Failed to save identity: ${e}`);
    }
  };

  const createClient = async () => {
    const uuid = getUuidForName(aliceName);
    try {
      const alice = await loadIdentity(uuid);
      let newClient: ClientState;

      if (alice) {
        log("info", `Restoring ${aliceName} from DB...`);
        const publicKey = PublicKey.deserialize(alice.identityPublic);
        const privateKey = PrivateKey.deserialize(alice.identityPrivate);
        const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
        newClient = createClientState(
          alice.uuid,
          alice.deviceId,
          identityKeyPair,
          alice.registrationId,
          alice.nextPreKeyId,
          alice.nextSignedPreKeyId,
          alice.nextKyberPreKeyId,
        );
        log("success", `✅ ${aliceName} restored from storage`);
        await ensureKeys(newClient);
      } else {
        log("info", `Creating new ${aliceName} client...`);
        const privateKey = PrivateKey.generate();
        const publicKey = privateKey.getPublicKey();
        const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
        const registrationId = generateRegistrationId();
        newClient = createClientState(uuid, 1, identityKeyPair, registrationId, 1, 1, 1);
        await persistIdentity(newClient);
        log("success", `✅ ${aliceName} created & saved`);
        await initializeKeys(newClient);
      }
      setClient(newClient);
    } catch (e) {
      log("error", `Failed to load ${aliceName}: ${e}`);
    }
  };

  const createBobClient = async () => {
    const uuid = getUuidForName(bobName);
    try {
      const bob = await loadIdentity(uuid);
      let newClient: ClientState;

      if (bob) {
        log("info", `Restoring ${bobName} from DB...`);
        const publicKey = PublicKey.deserialize(bob.identityPublic);
        const privateKey = PrivateKey.deserialize(bob.identityPrivate);
        const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
        newClient = createClientState(
          bob.uuid,
          bob.deviceId,
          identityKeyPair,
          bob.registrationId,
          bob.nextPreKeyId,
          bob.nextSignedPreKeyId,
          bob.nextKyberPreKeyId,
        );
        log("success", `✅ ${bobName} restored from storage`);
        await ensureKeys(newClient);
      } else {
        log("info", `Creating new ${bobName} client...`);
        const privateKey = PrivateKey.generate();
        const publicKey = privateKey.getPublicKey();
        const identityKeyPair = new IdentityKeyPair(publicKey, privateKey);
        const registrationId = generateRegistrationId();
        newClient = createClientState(uuid, 1, identityKeyPair, registrationId, 1, 1, 1);
        await persistIdentity(newClient);
        log("success", `✅ ${bobName} created & saved`);
        await initializeKeys(newClient);
      }
      setBobClient(newClient);
    } catch (e) {
      log("error", `Failed to load ${bobName}: ${e}`);
    }
  };

  const initializeKeys = async (c: ClientState) => {
    await generatePreKeysForClient(c, 10);
    await generateSignedPreKeyForClient(c);
    await generateKyberPreKeyForClient(c);
  };

  const ensureKeys = async (c: ClientState) => {
    const pks = await loadPreKeys(c.uuid);
    const spks = await loadSignedPreKeys(c.uuid);
    const kpks = await loadKyberPreKeys(c.uuid);

    if (pks.length > 0) {
      log("info", `Restoring ${pks.length} PreKeys from IDB...`);
      for (const pk of pks) {
        if (pk.record) await c.prekeyStore.import_pre_key(pk.id, pk.record);
      }
    }

    if (spks.length > 0) {
      log("info", `Restoring ${spks.length} Signed PreKeys from IDB...`);
      for (const spk of spks) {
        if (spk.record) await c.signedPrekeyStore.import_signed_pre_key(spk.id, spk.record);
      }
    }

    if (kpks.length > 0) {
      log("info", `Restoring ${kpks.length} Kyber PreKeys from IDB...`);
      for (const kpk of kpks) {
        if (kpk.record) await c.kyberPrekeyStore.import_kyber_pre_key(kpk.id, kpk.record);
      }
    }

    if (pks.length === 0 || spks.length === 0 || kpks.length === 0) {
      log("info", "Missing keys detected on restore. Generating...");
      await initializeKeys(c);
    }
  };

  const getIdentityKey = () => {
    if (!client) return;
    try {
      const keyPair = client.identityKeyPair;
      log(
        "data",
        "🔑 Identity Key Pair",
        JSON.stringify(
          {
            publicKey: toHexTruncated(keyPair.public_key().serialize()),
            // SECURITY: Never log private keys in production. This is demo-only.
            privateKey: toHexTruncated(keyPair.private_key().serialize()),
            publicKeyLength: keyPair.public_key().serialize().length,
            privateKeyLength: keyPair.private_key().serialize().length,
          },
          null,
          2,
        ),
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const generatePreKeysForClient = async (c: ClientState, count: number) => {
    const startId = c.nextPreKeyId;
    const prekeys = (await generatePreKeys(startId, count, c.prekeyStore)) as WasmPreKey[];
    c.nextPreKeyId = startId + count;
    await persistIdentity(c);

    for (const pk of prekeys) {
      await savePreKey({
        uuid: c.uuid,
        id: pk.id,
        publicKey: pk.public_key,
        record: pk.record,
      });
    }
    return prekeys;
  };

  const handleGeneratePreKeys = async (c?: ClientState) => {
    const target = c || client;
    if (!target) return;
    try {
      log("info", `Generating 10 PreKeys for ${target.uuid.slice(-4)}...`);
      const prekeys = await generatePreKeysForClient(target, 10);

      log(
        "success",
        `✅ Generated ${prekeys.length} PreKeys`,
        JSON.stringify(
          prekeys.slice(0, 3).map((pk) => ({
            id: pk.id,
            publicKey: toHexTruncated(pk.public_key),
          })),
          null,
          2,
        ) + `\n... and ${prekeys.length - 3} more`,
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const generateSignedPreKeyForClient = async (c: ClientState) => {
    const keyId = c.nextSignedPreKeyId;
    const spk = (await generateSignedPreKey(keyId, c.identityKeyPair, c.signedPrekeyStore)) as WasmSignedPreKey;
    c.nextSignedPreKeyId = keyId + 1;
    await persistIdentity(c);

    await saveSignedPreKey({
      uuid: c.uuid,
      id: spk.id,
      publicKey: spk.public_key,
      signature: spk.signature,
      timestamp: Number(spk.timestamp),
      record: spk.record,
    });
    return spk;
  };

  const handleGenerateSignedPreKey = async (c?: ClientState) => {
    const target = c || client;
    if (!target) return;
    try {
      log("info", "Generating Signed PreKey...");
      const spk = await generateSignedPreKeyForClient(target);

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
          2,
        ),
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const generateKyberPreKeyForClient = async (c: ClientState) => {
    const keyId = c.nextKyberPreKeyId;
    const kpk = (await generateKyberPreKey(keyId, c.identityKeyPair, c.kyberPrekeyStore)) as WasmKyberPreKey;
    c.nextKyberPreKeyId = keyId + 1;
    await persistIdentity(c);

    await saveKyberPreKey({
      uuid: c.uuid,
      id: kpk.id,
      publicKey: kpk.public_key,
      signature: kpk.signature,
      timestamp: Number(kpk.timestamp),
      record: kpk.record,
    });
    return kpk;
  };

  const handleGenerateKyberPreKey = async (c?: ClientState) => {
    const target = c || client;
    if (!target) return;
    try {
      log("info", "Generating Kyber PreKey (PQXDH)...");
      const kpk = await generateKyberPreKeyForClient(target);

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
          2,
        ),
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const generateSafetyNumber = () => {
    if (!client || !bobClient) {
      log("error", "Need both Alice and Bob clients");
      return;
    }
    try {
      log("info", "Generating safety number...");
      const bobPubKey = PublicKey.deserialize(bobClient.identityKeyPair.public_key().serialize());
      const safetyNumber = generateSafetyNumber(
        client.uuid,
        client.identityKeyPair.public_key(),
        bobClient.uuid,
        bobPubKey,
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
          2,
        ),
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const generateRandomBytes = () => {
    try {
      const bytes = generate_random_bytes(32);
      log("data", "🎲 Random bytes (32)", toHex(bytes));
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const generateUUID = () => {
    try {
      const uuidBytes = generate_uuid();
      const uuidStr = toHex(uuidBytes);
      log("data", "🆔 Generated UUID", uuidStr);
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const showMessageTypes = () => {
    log(
      "data",
      "📨 Message Types",
      JSON.stringify(
        {
          SIGNAL_MESSAGE: message_type_signal(),
          PREKEY_MESSAGE: message_type_pre_key(),
        },
        null,
        2,
      ),
    );
  };

  const exportImportDemo = async () => {
    if (!client) return;
    const BOB_UUID = getUuidForName("Bob");
    try {
      log("info", `Testing session export for Bob (${BOB_UUID.slice(-4)})...`);
      const bobAddress = ProtocolAddress.new(BOB_UUID, 1);
      const exported = await client.sessionStore.export_session(bobAddress);
      log(
        "data",
        "Session export result",
        exported
          ? `✅ ${exported.length} bytes exported`
          : "⚠️ null (No active session with Bob)",
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  const establishSession = async () => {
    if (!client || !bobClient) {
      log("error", "Need both clients");
      return;
    }
    try {
      log("info", "Establishing session (Alice -> Bob)...");

      const bobUuid = bobClient.uuid;
      const bobDevId = bobClient.deviceId;
      const bobRegId = bobClient.registrationId;
      const bobIdentity = bobClient.identityKeyPair.public_key().serialize();

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

      const signedPreKey = bobSignedPreKeys[0];
      const kyberPreKey = bobKyberPreKeys[0];
      const oneTimePreKey = bobPreKeys[0];

      const bobAddress = ProtocolAddress.new(bobUuid, bobDevId);
      const aliceAddress = ProtocolAddress.new(client.uuid, client.deviceId);
      const bobIdentityKey = PublicKey.deserialize(bobIdentity);
      const signedPreKeyPub = PublicKey.deserialize(signedPreKey.publicKey);
      await processPreKeyBundle(
        bobAddress,
        aliceAddress,
        bobRegId,
        bobIdentityKey,
        signedPreKey.id,
        signedPreKeyPub,
        signedPreKey.signature,
        oneTimePreKey.id,
        oneTimePreKey.publicKey,
        kyberPreKey.id,
        kyberPreKey.publicKey,
        kyberPreKey.signature,
        client.sessionStore,
        client.identityStore,
      );
      const serializedSession = await client.sessionStore.export_session(bobAddress);
      if (serializedSession) {
        await saveSession({
          localUuid: client.uuid,
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

  const encryptMsg = async () => {
    if (!client || !bobClient) return;
    try {
      const bobUuid = bobClient.uuid;
      const bobDevId = bobClient.deviceId;
      const plaintext = new TextEncoder().encode("Hello Bob! 🔒");

      const bobAddress = ProtocolAddress.new(bobUuid, bobDevId);
      const aliceAddress = ProtocolAddress.new(client.uuid, client.deviceId);

      const ciphertext = await encryptMessage(
        plaintext,
        bobAddress,
        aliceAddress,
        client.sessionStore,
        client.identityStore,
      );

      const session = await client.sessionStore.export_session(bobAddress);
      if (session) {
        await saveSession({
          localUuid: client.uuid,
          remoteUuid: bobUuid,
          remoteDeviceId: bobDevId,
          record: session,
        });
      }

      log(
        "data",
        `Encrypted to Bob (Type ${ciphertext.message_type})`,
        toHexTruncated(ciphertext.body),
      );

      window.__lastMessage = {
        ciphertext: ciphertext.body,
        type: ciphertext.message_type,
        senderUuid: client.uuid,
        senderDeviceId: client.deviceId,
      };
    } catch (e) {
      log("error", `Encrypt failed: ${e}`);
    }
  };

  const decryptMsg = async () => {
    if (!bobClient) return;
    try {
      const msg = window.__lastMessage;
      if (!msg) {
        log("error", "No message to decrypt");
        return;
      }

      const aliceAddress = ProtocolAddress.new(msg.senderUuid, msg.senderDeviceId);
      const bobAddress = ProtocolAddress.new(bobClient.uuid, bobClient.deviceId);

      const plaintext = await decryptMessage(
        msg.ciphertext,
        msg.type,
        aliceAddress,
        bobAddress,
        bobClient.sessionStore,
        bobClient.identityStore,
        bobClient.prekeyStore,
        bobClient.signedPrekeyStore,
        bobClient.kyberPrekeyStore,
      );

      const session = await bobClient.sessionStore.export_session(aliceAddress);
      if (session) {
        await saveSession({
          localUuid: bobClient.uuid,
          remoteUuid: msg.senderUuid,
          remoteDeviceId: msg.senderDeviceId,
          record: session,
        });
      }

      log(
        "success",
        `🔓 Decrypted from Alice`,
        new TextDecoder().decode(plaintext),
      );
    } catch (e) {
      log("error", `Decrypt failed: ${e}`);
    }
  };

  const createGroupSession = async () => {
    if (!client) return;
    try {
      const groupDistId = "team:general-chat-1";
      const aliceAddress = ProtocolAddress.new(client.uuid, client.deviceId);

      const skdm = await createSenderKeyDistribution(
        aliceAddress,
        groupDistId,
        client.senderKeyStore,
      );

      const record = await client.senderKeyStore.export_sender_key(
        aliceAddress,
        groupDistId,
      );
      if (record) {
        await saveSenderKey({
          localUuid: client.uuid,
          remoteUuid: client.uuid,
          remoteDeviceId: 1,
          distributionId: groupDistId,
          record,
        });
      }

      log("data", "Created Group Distribution", toHexTruncated(skdm));
      window.__groupDistId = groupDistId;
      window.__lastInfoMessage = {
        senderUuid: client.uuid,
        senderDeviceId: client.deviceId,
        distMessage: skdm,
      };
    } catch (e) {
      log("error", `Group init failed: ${e}`);
    }
  };

  const processGroupSession = async () => {
    if (!bobClient) return;
    try {
      const info = window.__lastInfoMessage;
      const groupDistId = window.__groupDistId;
      if (!info || !groupDistId) {
        log("error", "No distribution message found");
        return;
      }

      const aliceAddress = ProtocolAddress.new(info.senderUuid, info.senderDeviceId);
      await processSenderKeyDistribution(
        aliceAddress,
        info.distMessage,
        bobClient.senderKeyStore,
      );

      const record = await bobClient.senderKeyStore.export_sender_key(
        aliceAddress,
        groupDistId,
      );
      if (record) {
        await saveSenderKey({
          localUuid: bobClient.uuid,
          remoteUuid: info.senderUuid,
          remoteDeviceId: info.senderDeviceId,
          distributionId: groupDistId,
          record,
        });
      }

      log("success", "✅ Bob joined group session");
    } catch (e) {
      log("error", `Join group failed: ${e}`);
    }
  };

  const encryptGroupMsg = async () => {
    if (!client) return;
    try {
      const groupDistId = window.__groupDistId;
      if (!groupDistId) {
        log("error", "No group session");
        return;
      }

      const plaintext = new TextEncoder().encode("Hello Group! 📢");
      const aliceAddress = ProtocolAddress.new(client.uuid, client.deviceId);

      const ciphertext = await encryptGroupMessage(
        aliceAddress,
        groupDistId,
        plaintext,
        client.senderKeyStore,
      );

      const record = await client.senderKeyStore.export_sender_key(
        aliceAddress,
        groupDistId,
      );
      if (record) {
        await saveSenderKey({
          localUuid: client.uuid,
          remoteUuid: client.uuid,
          remoteDeviceId: 1,
          distributionId: groupDistId,
          record,
        });
      }

      log("data", "Encrypted Group Msg", toHexTruncated(ciphertext));

      window.__lastGroupMessage = {
        ciphertext,
        senderUuid: client.uuid,
        senderDeviceId: 1,
      };
    } catch (e) {
      log("error", `Group encrypt failed: ${e}`);
    }
  };

  const decryptGroupMsg = async () => {
    if (!bobClient) return;
    try {
      const msg = window.__lastGroupMessage;
      if (!msg) {
        log("error", "No group message");
        return;
      }

      const aliceAddress = ProtocolAddress.new(msg.senderUuid, msg.senderDeviceId);
      const plaintext = await decryptGroupMessage(
        aliceAddress,
        msg.ciphertext,
        bobClient.senderKeyStore,
      );

      const groupDistId = window.__groupDistId;
      if (!groupDistId) {
        log("error", "No group session ID");
        return;
      }
      const record = await bobClient.senderKeyStore.export_sender_key(
        aliceAddress,
        groupDistId,
      );
      if (record) {
        await saveSenderKey({
          localUuid: bobClient.uuid,
          remoteUuid: msg.senderUuid,
          remoteDeviceId: msg.senderDeviceId,
          distributionId: groupDistId,
          record,
        });
      }

      log(
        "success",
        "📢 Group Msg Decrypted",
        new TextDecoder().decode(plaintext),
      );
    } catch (e) {
      log("error", `Group decrypt failed: ${e}`);
    }
  };

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
            <button
              onClick={initWasm}
              disabled={wasmReady}
              style={{ gridColumn: "1 / -1" }}
            >
              {wasmReady ? "✅ WASM Ready" : "1. Init WASM"}
            </button>

            <div style={{ display: "contents" }}>
              <input
                type="text"
                value={aliceName}
                onChange={(e) => setAliceName(e.target.value)}
                disabled={!!client}
                className="name-input"
                placeholder="Client A"
              />
              <button onClick={createClient} disabled={!wasmReady || !!client}>
                {client ? `✅ ${aliceName} Ready` : `2. Create ${aliceName}`}
              </button>
            </div>

            <div style={{ display: "contents" }}>
              <input
                type="text"
                value={bobName}
                onChange={(e) => setBobName(e.target.value)}
                disabled={!!bobClient}
                className="name-input"
                placeholder="Client B"
              />
              <button
                onClick={createBobClient}
                disabled={!wasmReady || !!bobClient}
              >
                {bobClient ? `✅ ${bobName} Ready` : `3. Create ${bobName}`}
              </button>
            </div>
          </div>

          <div className="button-group">
            <h3>Key Operations</h3>
            <button onClick={getIdentityKey} disabled={!client}>
              Identity Key
            </button>
            <button onClick={() => handleGeneratePreKeys()} disabled={!client}>
              PreKeys (10)
            </button>
            <button onClick={() => handleGenerateSignedPreKey()} disabled={!client}>
              Signed PreKey
            </button>
            <button onClick={() => handleGenerateKyberPreKey()} disabled={!client}>
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
            <button onClick={encryptMsg} disabled={!client || !bobClient}>
              2. Alice Encrypt
            </button>
            <button onClick={decryptMsg} disabled={!bobClient}>
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
            <button onClick={encryptGroupMsg} disabled={!client}>
              3. Alice Send
            </button>
            <button onClick={decryptGroupMsg} disabled={!bobClient}>
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
        <p>libsignal v0.93.1 • WASM • React 19 • Vite • IndexedDB</p>
      </footer>
    </div>
  );
}

export default App;
