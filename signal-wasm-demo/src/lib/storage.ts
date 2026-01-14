import { type DBSchema, type IDBPDatabase, openDB } from "idb";

interface SignalWasmDemoDB extends DBSchema {
  identity: {
    key: string; // uuid
    value: {
      uuid: string;
      deviceId: number;
      registrationId: number;
      identityPublic: Uint8Array;
      identityPrivate: Uint8Array;
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
      record: Uint8Array;
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
      record: Uint8Array;
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
      record: Uint8Array;
    };
  };
  sessions: {
    key: [string, string, number]; // [localUuid, remoteUuid, remoteDeviceId]
    value: {
      localUuid: string;
      remoteUuid: string;
      remoteDeviceId: number;
      record: Uint8Array;
    };
  };
  sender_keys: {
    key: [string, string, number, string]; // [localUuid, remoteUuid, remoteDeviceId, distributionId]
    value: {
      localUuid: string;
      remoteUuid: string;
      remoteDeviceId: number;
      distributionId: string;
      record: Uint8Array;
    };
  };
}

const MIGRATIONS: ((db: IDBPDatabase<SignalWasmDemoDB>) => void)[] = [
  // v1: Initial setup of identity, prekeys, and sessions
  (db) => {
    db.createObjectStore("identity", { keyPath: "uuid" });
    db.createObjectStore("prekeys", { keyPath: ["uuid", "id"] });
    db.createObjectStore("signed_prekeys", { keyPath: ["uuid", "id"] });
    db.createObjectStore("kyber_prekeys", { keyPath: ["uuid", "id"] });
    db.createObjectStore("sessions", {
      keyPath: ["localUuid", "remoteUuid", "remoteDeviceId"],
    });
  },
  // v2: Added support for group messaging (Sender Keys)
  (db) => {
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
  // v3: Breaking change to add 'record' field to prekeys (re-create stores)
  (db) => {
    ["prekeys", "signed_prekeys", "kyber_prekeys"].forEach((name) => {
      if (db.objectStoreNames.contains(name as any)) {
        db.deleteObjectStore(name as any);
      }
      db.createObjectStore(name as any, { keyPath: ["uuid", "id"] });
    });
  },
];

const DB_NAME = "signal-wasm-demo-db";
const DB_VERSION = MIGRATIONS.length;

let dbPromise: Promise<IDBPDatabase<SignalWasmDemoDB>> | null = null;

export const initDB = () => {
  if (!dbPromise) {
    dbPromise = openDB<SignalWasmDemoDB>(DB_NAME, DB_VERSION, {
      upgrade(db, oldVersion, newVersion) {
        console.log(`[DB] Upgrading from v${oldVersion} to v${newVersion}`);
        for (let v = oldVersion + 1; v <= (newVersion || DB_VERSION); v++) {
          const migrate = MIGRATIONS[v - 1];
          if (migrate) {
            console.log(`[DB] Running migration v${v}`);
            migrate(db);
          }
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
