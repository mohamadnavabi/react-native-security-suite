import { getNativeModule } from '../../native/bridge';
import type {
  DerivedKeys,
  EphemeralDerivedKeys,
  KeyExchangeComputeParams,
} from '../types';

export const KeyExchange = {
  // ─── Static (persisted) key pair ───────────────────────────────────────────

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
   * Rotates the persisted ECDH P-256 key pair (deletes the old key and generates a new
   * one). Returns the new public key (DER/X.509, Base64).
   */
  rotateEcdhKeyPair(): Promise<string> {
    return getNativeModule().cryptoRotateEcdhKeyPair();
  },

  /**
   * Permanently deletes the persisted ECDH P-256 key pair from secure storage.
   * Call on logout or security incident.
   */
  deleteEcdhKeyPair(): Promise<void> {
    return getNativeModule().cryptoDeleteEcdhKeyPair();
  },

  /**
   * Generates a one-time ephemeral P-256 key pair (never persisted), performs ECDH
   * with the server public key, and derives session keys via HKDF.
   *
   * Returns `devicePublicKey` — send this to your server so it can compute the same
   * shared secret. Provides forward secrecy: the ephemeral private key is discarded
   * immediately after the key agreement.
   */
  ecdhEphemeralComputeAndDeriveKeys(
    params: KeyExchangeComputeParams
  ): Promise<EphemeralDerivedKeys> {
    return getNativeModule().cryptoEcdhEphemeralComputeAndDeriveKeys(
      params as unknown as Record<string, unknown>
    );
  },

  // ─── X25519 ────────────────────────────────────────────────────────────────

  /**
   * Returns the device's X25519 public key (raw 32 bytes, Base64).
   * Requires Android API 31+ (Android 12); always available on iOS 13+.
   */
  getX25519PublicKey(): Promise<string> {
    return getNativeModule().cryptoGetX25519PublicKey();
  },

  /**
   * Performs X25519 key agreement then derives keys via HKDF.
   * Server public key must be raw 32 bytes or standard SPKI-wrapped (44 bytes), Base64.
   */
  x25519ComputeAndDeriveKeys(
    params: KeyExchangeComputeParams
  ): Promise<DerivedKeys> {
    return getNativeModule().cryptoX25519ComputeAndDeriveKeys(
      params as unknown as Record<string, unknown>
    );
  },

  /**
   * Rotates the persisted X25519 key pair. Returns the new public key (raw 32 bytes,
   * Base64). Requires Android API 31+.
   */
  rotateX25519KeyPair(): Promise<string> {
    return getNativeModule().cryptoRotateX25519KeyPair();
  },

  /**
   * Permanently deletes the persisted X25519 key pair from secure storage.
   */
  deleteX25519KeyPair(): Promise<void> {
    return getNativeModule().cryptoDeleteX25519KeyPair();
  },

  /**
   * Generates a one-time ephemeral X25519 key pair (never persisted), performs key
   * agreement with the server public key, and derives session keys via HKDF.
   *
   * Returns `devicePublicKey` (raw 32 bytes, Base64) — send this to your server.
   * Requires Android API 31+.
   */
  x25519EphemeralComputeAndDeriveKeys(
    params: KeyExchangeComputeParams
  ): Promise<EphemeralDerivedKeys> {
    return getNativeModule().cryptoX25519EphemeralComputeAndDeriveKeys(
      params as unknown as Record<string, unknown>
    );
  },
};
