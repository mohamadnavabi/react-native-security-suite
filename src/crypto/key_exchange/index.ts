import { getNativeModule } from '../../native/bridge';
import type { DerivedKeys, KeyExchangeComputeParams } from '../types';

export const KeyExchange = {
  /**
   * Returns the device's ECDH P-256 public key (DER/X.509, Base64).
   * The private key is hardware-backed (Android Keystore / iOS Keychain).
   */
  getEcdhPublicKey(): Promise<string> {
    return getNativeModule().cryptoGetEcdhPublicKey();
  },

  /**
   * Performs ECDH P-256 key agreement with the server public key, then derives
   * encryptionKey and macKey via HKDF. Server public key must be DER-encoded, Base64.
   */
  ecdhComputeAndDeriveKeys(
    params: KeyExchangeComputeParams
  ): Promise<DerivedKeys> {
    return getNativeModule().cryptoEcdhComputeAndDeriveKeys(
      params as unknown as Record<string, unknown>
    );
  },

  /**
   * Returns the device's X25519 public key (raw 32 bytes, Base64).
   * Requires Android API 31+ (Android 12); always available on iOS 13+.
   */
  getX25519PublicKey(): Promise<string> {
    return getNativeModule().cryptoGetX25519PublicKey();
  },

  /**
   * Performs X25519 key agreement then derives keys via HKDF.
   * Server public key may be raw 32 bytes or SPKI-wrapped, Base64.
   */
  x25519ComputeAndDeriveKeys(
    params: KeyExchangeComputeParams
  ): Promise<DerivedKeys> {
    return getNativeModule().cryptoX25519ComputeAndDeriveKeys(
      params as unknown as Record<string, unknown>
    );
  },
};
