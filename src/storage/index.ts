import { NativeModules } from 'react-native';
import type {
  BiometricOptions,
  SecureStorageOptions,
} from '../types/detection';

export type { BiometricOptions, SecureStorageOptions };

// ─── Key-lifecycle metadata schema ────────────────────────────────────────────

interface KeyMeta {
  version: number;
  createdAt: number;
  expiresAt?: number;
}

const META_SUFFIX = '__rss_meta__';

function metaKey(key: string): string {
  return key + META_SUFFIX;
}

function n(): any {
  // eslint-disable-line @typescript-eslint/no-explicit-any
  return NativeModules.SecuritySuite;
}

function wrapStorage<T>(op: string, promise: Promise<T>): Promise<T> {
  return promise.catch((err: unknown) => {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Secure storage operation failed (${op}): ${msg}`);
  });
}

// ─── SecureStorage namespace ───────────────────────────────────────────────────

/**
 * Hardware-backed encrypted storage (Keychain on iOS, EncryptedSharedPreferences on Android).
 * All keys are namespaced internally; you pass plain application keys.
 */
export const Storage = {
  // ── Standard CRUD ────────────────────────────────────────────────────────

  setItem(
    key: string,
    value: string,
    options?: SecureStorageOptions
  ): Promise<void> {
    if (options?.requireBiometric) {
      return wrapStorage<void>(
        'setItem',
        n().secureStorageSetItemBiometric(key, value, {
          prompt: options.prompt ?? 'Authenticate to save',
          subtitle: options.subtitle ?? '',
        })
      );
    }
    return wrapStorage<void>('setItem', n().secureStorageSetItem(key, value));
  },

  getItem(key: string, options?: SecureStorageOptions): Promise<string | null> {
    if (options?.requireBiometric) {
      return wrapStorage<string | null>(
        'getItem',
        n().secureStorageGetItemBiometric(key, {
          prompt: options.prompt ?? 'Authenticate to read',
          subtitle: options.subtitle ?? '',
        })
      );
    }
    return wrapStorage<string | null>('getItem', n().secureStorageGetItem(key));
  },

  removeItem(key: string): Promise<void> {
    return wrapStorage<void>('removeItem', n().secureStorageRemoveItem(key));
  },

  getAllKeys(): Promise<string[]> {
    return wrapStorage<string[]>(
      'getAllKeys',
      n().secureStorageGetAllKeys()
    ).then((keys: string[]) => keys.filter((k) => !k.endsWith(META_SUFFIX)));
  },

  clear(): Promise<void> {
    return wrapStorage<void>('clear', n().secureStorageClear());
  },

  multiSet(pairs: Array<[string, string]>): Promise<void> {
    return Promise.all(pairs.map(([k, v]) => Storage.setItem(k, v))).then(
      () => undefined
    );
  },

  multiGet(keys: string[]): Promise<ReadonlyArray<[string, string | null]>> {
    return Promise.all(
      keys.map(
        async (k) => [k, await Storage.getItem(k)] as [string, string | null]
      )
    );
  },

  multiRemove(keys: string[]): Promise<void> {
    return Promise.all(keys.map((k) => Storage.removeItem(k))).then(
      () => undefined
    );
  },

  // ── Biometric availability ────────────────────────────────────────────────

  /** Returns true if biometric authentication is available on this device. */
  biometricIsAvailable(): Promise<boolean> {
    return wrapStorage<boolean>(
      'biometricIsAvailable',
      n().secureStorageBiometricIsAvailable()
    );
  },

  // ── Key-lifecycle helpers ─────────────────────────────────────────────────

  /**
   * Store a value with an expiry date. Reading with `getItemIfValid` returns
   * `null` after the expiry without deleting the key.
   */
  async setItemWithExpiry(
    key: string,
    value: string,
    expiresAt: Date,
    options?: SecureStorageOptions
  ): Promise<void> {
    const meta: KeyMeta = {
      version: 1,
      createdAt: Date.now(),
      expiresAt: expiresAt.getTime(),
    };
    await Promise.all([
      Storage.setItem(key, value, options),
      Storage.setItem(metaKey(key), JSON.stringify(meta)),
    ]);
  },

  /**
   * Return the value if it exists and has not expired; `null` otherwise.
   * Does not remove the expired key — call `removeItem` explicitly if needed.
   */
  async getItemIfValid(
    key: string,
    options?: SecureStorageOptions
  ): Promise<string | null> {
    const [value, rawMeta] = await Promise.all([
      Storage.getItem(key, options),
      Storage.getItem(metaKey(key)),
    ]);

    if (value === null) return null;

    if (rawMeta) {
      try {
        const meta: KeyMeta = JSON.parse(rawMeta);
        if (meta.expiresAt != null && Date.now() > meta.expiresAt) {
          return null;
        }
      } catch {
        // malformed metadata — treat as no expiry
      }
    }

    return value;
  },

  /**
   * Remove a key only if it has expired. Returns true if the item was removed.
   */
  async removeIfExpired(key: string): Promise<boolean> {
    const rawMeta = await Storage.getItem(metaKey(key));
    if (!rawMeta) return false;

    try {
      const meta: KeyMeta = JSON.parse(rawMeta);
      if (meta.expiresAt != null && Date.now() > meta.expiresAt) {
        await Promise.all([
          Storage.removeItem(key),
          Storage.removeItem(metaKey(key)),
        ]);
        return true;
      }
    } catch {
      // ignore
    }
    return false;
  },

  /**
   * Replace a value and bump its version counter. The previous value is
   * overwritten atomically (both key and metadata in parallel).
   */
  async rotateItem(
    key: string,
    newValue: string,
    options?: SecureStorageOptions
  ): Promise<void> {
    const rawMeta = await Storage.getItem(metaKey(key));
    let version = 1;
    let expiresAt: number | undefined;

    if (rawMeta) {
      try {
        const meta: KeyMeta = JSON.parse(rawMeta);
        version = (meta.version ?? 0) + 1;
        expiresAt = meta.expiresAt;
      } catch {
        // ignore
      }
    }

    const newMeta: KeyMeta = { version, createdAt: Date.now(), expiresAt };
    await Promise.all([
      Storage.setItem(key, newValue, options),
      Storage.setItem(metaKey(key), JSON.stringify(newMeta)),
    ]);
  },

  /** Read the version and expiry metadata for a key, if available. */
  async getMetadata(key: string): Promise<KeyMeta | null> {
    const raw = await Storage.getItem(metaKey(key));
    if (!raw) return null;
    try {
      return JSON.parse(raw) as KeyMeta;
    } catch {
      return null;
    }
  },
};

export type { KeyMeta };
