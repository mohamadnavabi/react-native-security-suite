import { ensureLegacyV09Initialized, resolveCryptoOptions } from '../config';
import { getNativeModule } from '../native/bridge';
import {
  toNativeCryptoOptions,
  type CryptoOptions,
} from '../legacy/cryptoOptions';

export interface EstablishSharedKeyOptions extends CryptoOptions {
  /** @deprecated Prefer native-only flow; set true only for legacy compatibility. */
  returnSharedKey?: boolean;
}

function withLegacyBootstrap<T>(
  cryptoOverrides: CryptoOptions | undefined,
  run: () => Promise<T>
): Promise<T> {
  return ensureLegacyV09Initialized(cryptoOverrides).then(run);
}

export const Crypto = {
  getPublicKey(options?: CryptoOptions): Promise<string> {
    return withLegacyBootstrap(options, () =>
      getNativeModule().getPublicKey(
        toNativeCryptoOptions(resolveCryptoOptions(options))
      )
    );
  },

  encrypt(input: string, options?: CryptoOptions): Promise<string> {
    if (!input || typeof input !== 'string') {
      return Promise.reject(new Error('Input must be a non-empty string'));
    }
    return withLegacyBootstrap(options, () =>
      getNativeModule().encrypt(
        input,
        toNativeCryptoOptions(resolveCryptoOptions(options))
      )
    );
  },

  decrypt(input: string, options?: CryptoOptions): Promise<string> {
    if (!input || typeof input !== 'string') {
      return Promise.reject(new Error('Input must be a non-empty string'));
    }
    return withLegacyBootstrap(options, () =>
      getNativeModule().decrypt(
        input,
        toNativeCryptoOptions(resolveCryptoOptions(options))
      )
    );
  },

  establishSharedKey(
    serverPublicKey: string,
    options?: EstablishSharedKeyOptions
  ): Promise<string | void> {
    return withLegacyBootstrap(options, () => {
      const native = getNativeModule();
      const nativeOptions = toNativeCryptoOptions(
        resolveCryptoOptions(options)
      );

      if (options?.returnSharedKey) {
        return native.getSharedKey(serverPublicKey, nativeOptions);
      }

      if (typeof native.establishSharedKey === 'function') {
        return native.establishSharedKey(serverPublicKey, nativeOptions);
      }

      return native
        .getSharedKey(serverPublicKey, nativeOptions)
        .then(() => undefined);
    });
  },
};

export type { CryptoOptions } from '../legacy/cryptoOptions';

export { CryptoManager } from './CryptoManager';
export type {
  HashAlgorithm,
  HkdfHmacAlgorithm,
  DerivedKeys,
  EphemeralDerivedKeys,
  KeyPair,
  HkdfDeriveParams,
  KeyExchangeComputeParams,
} from './types';
export { Hashing } from './hashing';
export { KDF } from './kdf';
export { KeyExchange } from './key_exchange';
export { Encryption } from './encryption';
export { Signatures } from './signatures';

// ─── CSPRNG ──────────────────────────────────────────────────────────────────

export const Random = {
  /**
   * Generate `count` cryptographically secure random bytes via the platform
   * hardware RNG. Returns a base64-encoded string.
   */
  randomBytes(count: number): Promise<string> {
    if (!Number.isInteger(count) || count < 1 || count > 65536) {
      return Promise.reject(
        new Error('count must be an integer between 1 and 65536')
      );
    }
    return getNativeModule().cryptoRandomBytes(count);
  },

  /**
   * Generate a cryptographically secure random UUID v4.
   */
  async randomUUID(): Promise<string> {
    const b64 = await Random.randomBytes(16);
    const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    // UUID v4: force version nibble to 4 and variant bits to 0b10xxxxxx
    bytes[6] = ((bytes[6]! >>> 0) % 16) + 0x40; // eslint-disable-line no-bitwise
    bytes[8] = ((bytes[8]! >>> 0) % 64) + 0x80; // eslint-disable-line no-bitwise
    const hex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  },
};
