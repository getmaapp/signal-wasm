import { useCallback, useState } from "react";
import "./App.css";
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
  const [, setLogId] = useState(0);

  // Add log entry
  const log = useCallback(
    (type: LogEntry["type"], message: string, data?: string) => {
      setLogId((prev) => {
        const newId = prev + 1;
        setLogs((logs) => [
          ...logs,
          {
            id: newId,
            time: new Date().toLocaleTimeString(),
            type,
            message,
            data,
          },
        ]);
        return newId;
      });
    },
    []
  );

  // Initialise WASM
  const initWasm = async () => {
    try {
      log("info", "Initialising WASM module...");
      await init();
      setWasmReady(true);
      log("success", "✅ WASM module initialised!");
    } catch (e) {
      log("error", `Failed to init WASM: ${e}`);
    }
  };

  // Create client (Alice)
  const createClient = () => {
    try {
      log("info", "Creating Alice client...");
      const uuid = uuid_to_string(generate_uuid());
      const newClient = new SignalClient(uuid, 1);
      setClient(newClient);
      log(
        "success",
        `✅ Alice client created`,
        JSON.stringify(
          {
            uuid,
            deviceId: 1,
            registrationId: newClient.get_registration_id(),
          },
          null,
          2
        )
      );
    } catch (e) {
      log("error", `Failed to create client: ${e}`);
    }
  };

  // Create Bob client for messaging demo
  const createBobClient = () => {
    try {
      log("info", "Creating Bob client...");
      const uuid = uuid_to_string(generate_uuid());
      const newClient = new SignalClient(uuid, 1);
      setBobClient(newClient);
      log(
        "success",
        `✅ Bob client created`,
        JSON.stringify(
          {
            uuid,
            deviceId: 1,
            registrationId: newClient.get_registration_id(),
          },
          null,
          2
        )
      );
    } catch (e) {
      log("error", `Failed to create Bob: ${e}`);
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
  const generatePreKeys = () => {
    if (!client) return;
    try {
      log("info", "Generating 10 PreKeys...");
      const prekeys = client.generate_prekeys(10) as WasmPreKey[];
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
  const generateSignedPreKey = () => {
    if (!client) return;
    try {
      log("info", "Generating Signed PreKey...");
      const spk = client.generate_signed_prekey() as WasmSignedPreKey;
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
  const generateKyberPreKey = () => {
    if (!client) return;
    try {
      log("info", "Generating Kyber PreKey (PQXDH)...");
      const kpk = client.generate_kyber_prekey() as WasmKyberPreKey;
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
  const exportImportDemo = async () => {
    if (!client) return;
    try {
      log("info", "Testing session export (no active session)...");
      const exported = await client.export_session("test-contact", 1);
      log(
        "data",
        "Session export result",
        exported ? `${exported.length} bytes` : "null (no session)"
      );
    } catch (e) {
      log("error", `Failed: ${e}`);
    }
  };

  // Clear logs
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
            <button onClick={generatePreKeys} disabled={!client}>
              PreKeys (10)
            </button>
            <button onClick={generateSignedPreKey} disabled={!client}>
              Signed PreKey
            </button>
            <button onClick={generateKyberPreKey} disabled={!client}>
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
        <p>libsignal v0.86.9 • WASM • React 19 • Vite</p>
      </footer>
    </div>
  );
}

export default App;
