import { type DBSchema, type IDBPDatabase, openDB } from "idb";

interface SignalWasmDemoDB extends DBSchema {
  identity: {
    key: string; // uuid
    value: {
      uuid: string;
      deviceId: number;
      registrationId: number;
      identityPublic: Uint8Array;
      identityPrivate: Uint8Array; // serialized Zeroizing<Vec<u8>>
      nextPreKeyId: number;
      nextSignedPreKeyId: number;
      nextKyberPreKeyId: number;
    };
  };
  prekeys: {
    key: [string, number]; // [uuid, id]
    value: {
      uuid: string;
      id: number;
      publicKey: Uint8Array;
    };
  };
  signed_prekeys: {
    key: [string, number]; // [uuid, id]
    value: {
      uuid: string;
      id: number;
      publicKey: Uint8Array;
      signature: Uint8Array;
      timestamp: number;
    };
  };
  kyber_prekeys: {
    key: [string, number]; // [uuid, id]
    value: {
      uuid: string;
      id: number;
      publicKey: Uint8Array;
      signature: Uint8Array;
      timestamp: number;
    };
  };
  sessions: {
    key: [string, string, number]; // [localUuid, remoteUuid, remoteDeviceId]
    value: {
      localUuid: string;
      remoteUuid: string;
      remoteDeviceId: number;
      record: Uint8Array; // Serialized SessionRecord
    };
  };
  sender_keys: {
    key: [string, string, number, string]; // [localUuid, remoteUuid, remoteDeviceId, distributionId]
    value: {
      localUuid: string;
      remoteUuid: string;
      remoteDeviceId: number;
      distributionId: string;
      record: Uint8Array; // Serialized SenderKeyRecord
    };
  };
}

const DB_NAME = "signal-wasm-demo-db";
const DB_VERSION = 1;

let dbPromise: Promise<IDBPDatabase<SignalWasmDemoDB>> | null = null;

export const initDB = () => {
  if (!dbPromise) {
    dbPromise = openDB<SignalWasmDemoDB>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains("identity")) {
          db.createObjectStore("identity", { keyPath: "uuid" });
        }
        if (!db.objectStoreNames.contains("prekeys")) {
          db.createObjectStore("prekeys", { keyPath: ["uuid", "id"] });
        }
        if (!db.objectStoreNames.contains("signed_prekeys")) {
          db.createObjectStore("signed_prekeys", { keyPath: ["uuid", "id"] });
        }
        if (!db.objectStoreNames.contains("kyber_prekeys")) {
          db.createObjectStore("kyber_prekeys", { keyPath: ["uuid", "id"] });
        }
        if (!db.objectStoreNames.contains("sessions")) {
          db.createObjectStore("sessions", {
            keyPath: ["localUuid", "remoteUuid", "remoteDeviceId"],
          });
        }
        if (!db.objectStoreNames.contains("sender_keys")) {
          db.createObjectStore("sender_keys", {
            keyPath: [
              "localUuid",
              "remoteUuid",
              "remoteDeviceId",
              "distributionId",
            ],
          });
        }
      },
    });
  }
  return dbPromise;
};

// --- Identity ---

export async function saveIdentity(
  data: SignalWasmDemoDB["identity"]["value"]
) {
  const db = await initDB();
  await db.put("identity", data);
}

export async function loadIdentity(uuid: string) {
  const db = await initDB();
  return db.get("identity", uuid);
}

export async function getAllIdentities() {
  const db = await initDB();
  return db.getAll("identity");
}

// --- PreKeys ---

export async function savePreKey(data: SignalWasmDemoDB["prekeys"]["value"]) {
  const db = await initDB();
  await db.put("prekeys", data);
}

export async function loadPreKeys(uuid: string) {
  const db = await initDB();
  // We can't query by just part of the key in idb without an index,
  // but for the demo we can just get all and filter or add an index.
  // Adding an index 'uuid' to each store is cleaner.
  // For now, let's just use getAll and filter in memory since dataset is small for demo.
  const all = await db.getAll("prekeys");
  return all.filter((pk) => pk.uuid === uuid);
}

// --- Signed PreKeys ---

export async function saveSignedPreKey(
  data: SignalWasmDemoDB["signed_prekeys"]["value"]
) {
  const db = await initDB();
  await db.put("signed_prekeys", data);
}

export async function loadSignedPreKeys(uuid: string) {
  const db = await initDB();
  const all = await db.getAll("signed_prekeys");
  return all.filter((pk) => pk.uuid === uuid);
}

// --- Kyber PreKeys ---

export async function saveKyberPreKey(
  data: SignalWasmDemoDB["kyber_prekeys"]["value"]
) {
  const db = await initDB();
  await db.put("kyber_prekeys", data);
}

export async function loadKyberPreKeys(uuid: string) {
  const db = await initDB();
  const all = await db.getAll("kyber_prekeys");
  return all.filter((pk) => pk.uuid === uuid);
}

// --- Sessions ---

export async function saveSession(data: SignalWasmDemoDB["sessions"]["value"]) {
  const db = await initDB();
  await db.put("sessions", data);
}

export async function loadSession(
  localUuid: string,
  remoteUuid: string,
  remoteDeviceId: number
) {
  const db = await initDB();
  return db.get("sessions", [localUuid, remoteUuid, remoteDeviceId]);
}

export async function clearStorage() {
  const db = await initDB();
  await db.clear("identity");
  await db.clear("prekeys");
  await db.clear("signed_prekeys");
  await db.clear("kyber_prekeys");
  await db.clear("sessions");
  await db.clear("sender_keys");
}

// --- Sender Keys ---

export async function saveSenderKey(
  data: SignalWasmDemoDB["sender_keys"]["value"]
) {
  const db = await initDB();
  await db.put("sender_keys", data);
}

export async function loadSenderKey(
  localUuid: string,
  remoteUuid: string,
  remoteDeviceId: number,
  distributionId: string
) {
  const db = await initDB();
  return db.get("sender_keys", [
    localUuid,
    remoteUuid,
    remoteDeviceId,
    distributionId,
  ]);
}
