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
  KeyPair,
  HkdfDeriveParams,
  KeyExchangeComputeParams,
} from './types';
export { Hashing } from './hashing';
export { KDF } from './kdf';
export { KeyExchange } from './key_exchange';
export { Encryption } from './encryption';
export { Signatures } from './signatures';
