import { NativeModules } from 'react-native';
import type {
  BiometricOptions,
  SecureStorageOptions,
} from '../types/detection';
import {
  assertKey,
  assertKeys,
  assertPairs,
  assertValue,
  checkInput,
  guardStorage,
} from './validate';

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

function wrapStorage<T>(op: string, call: () => Promise<T>): Promise<T> {
  return guardStorage(op, call);
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
    return wrapStorage<void>('setItem', () => {
      assertKey(key);
      assertValue(value);
      if (options?.requireBiometric) {
        return n().secureStorageSetItemBiometric(key, value, {
          prompt: options.prompt ?? 'Authenticate to save',
          subtitle: options.subtitle ?? '',
        });
      }
      return n().secureStorageSetItem(key, value);
    });
  },

  getItem(key: string, options?: SecureStorageOptions): Promise<string | null> {
    return wrapStorage<string | null>('getItem', () => {
      assertKey(key);
      if (options?.requireBiometric) {
        return n().secureStorageGetItemBiometric(key, {
          prompt: options.prompt ?? 'Authenticate to read',
          subtitle: options.subtitle ?? '',
        });
      }
      return n().secureStorageGetItem(key);
    });
  },

  removeItem(key: string): Promise<void> {
    return wrapStorage<void>('removeItem', () => {
      assertKey(key);
      return n().secureStorageRemoveItem(key);
    });
  },

  getAllKeys(): Promise<string[]> {
    return wrapStorage<string[]>('getAllKeys', () =>
      n().secureStorageGetAllKeys()
    ).then((keys: string[] | null) =>
      (keys ?? []).filter((k) => !k.endsWith(META_SUFFIX))
    );
  },

  clear(): Promise<void> {
    return wrapStorage<void>('clear', () => n().secureStorageClear());
  },

  async multiSet(pairs: Array<[string, string]>): Promise<void> {
    checkInput('multiSet', () => assertPairs(pairs));
    await Promise.all(pairs.map(([k, v]) => Storage.setItem(k, v)));
  },

  async multiGet(
    keys: string[]
  ): Promise<ReadonlyArray<[string, string | null]>> {
    checkInput('multiGet', () => assertKeys(keys));
    return Promise.all(
      keys.map(
        async (k) => [k, await Storage.getItem(k)] as [string, string | null]
      )
    );
  },

  async multiRemove(keys: string[]): Promise<void> {
    checkInput('multiRemove', () => assertKeys(keys));
    await Promise.all(keys.map((k) => Storage.removeItem(k)));
  },

  // ── Biometric availability ────────────────────────────────────────────────

  /** Returns true if biometric authentication is available on this device. */
  biometricIsAvailable(): Promise<boolean> {
    return wrapStorage<boolean>('biometricIsAvailable', () =>
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
    checkInput('setItemWithExpiry', () => {
      assertKey(key);
      assertValue(value);
    });
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
    checkInput('getItemIfValid', () => assertKey(key));
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
    checkInput('removeIfExpired', () => assertKey(key));
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
    checkInput('rotateItem', () => {
      assertKey(key);
      assertValue(newValue);
    });
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
    checkInput('getMetadata', () => assertKey(key));
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
