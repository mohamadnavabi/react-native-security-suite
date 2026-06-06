import { getNativeModule } from '../native/bridge';
import {
  toNativeCryptoOptions,
  type CryptoOptions,
} from '../legacy/cryptoOptions';

export interface EstablishSharedKeyOptions extends CryptoOptions {
  /** @deprecated Prefer native-only flow; set true only for legacy compatibility. */
  returnSharedKey?: boolean;
}

export const Crypto = {
  getPublicKey(): Promise<string> {
    return getNativeModule().getPublicKey();
  },

  /**
   * Derives a shared encryption key natively without returning it to JavaScript.
   * Call `encryptBySharedKey` / `decryptBySharedKey` afterward (legacy bridge methods).
   */
  establishSharedKey(
    serverPublicKey: string,
    options?: EstablishSharedKeyOptions
  ): Promise<string | void> {
    const native = getNativeModule();
    const nativeOptions = toNativeCryptoOptions(options);

    if (options?.returnSharedKey) {
      return native.getSharedKey(serverPublicKey, nativeOptions);
    }

    if (typeof native.establishSharedKey === 'function') {
      return native.establishSharedKey(serverPublicKey, nativeOptions);
    }

    return native.getSharedKey(serverPublicKey, nativeOptions).then(() => undefined);
  },
};

export type { CryptoOptions } from '../legacy/cryptoOptions';
