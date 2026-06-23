import { getNativeModule } from '../../native/bridge';
import type { DerivedKeys, HkdfDeriveParams } from '../types';

export const KDF = {
  /**
   * Derives independent encryptionKey and macKey from a shared secret via HKDF-SHA256.
   * All fields in params are Base64-encoded.
   */
  deriveKeys(params: HkdfDeriveParams): Promise<DerivedKeys> {
    return getNativeModule().cryptoDeriveKeys(
      params as unknown as Record<string, unknown>
    );
  },
};
