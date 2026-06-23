import { getNativeModule } from '../../native/bridge';
import type { KeyPair } from '../types';

export const Signatures = {
  /**
   * Generates an Ed25519 key pair.
   * Keys are Base64-encoded raw 32-byte representations (iOS) / DER (Android).
   * Android requires API 33+; throws UnsupportedOperationException on older devices.
   */
  generateEd25519KeyPair(): Promise<KeyPair> {
    return getNativeModule().cryptoGenerateEd25519KeyPair();
  },

  /**
   * Signs a UTF-8 message with an Ed25519 private key (Base64).
   * Returns Base64-encoded raw 64-byte signature.
   */
  signEd25519(message: string, privateKey: string): Promise<string> {
    return getNativeModule().cryptoSignEd25519(message, privateKey);
  },

  /**
   * Verifies an Ed25519 signature.
   * message: UTF-8 string; signature and publicKey are Base64.
   */
  verifyEd25519(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean> {
    return getNativeModule().cryptoVerifyEd25519(message, signature, publicKey);
  },

  /**
   * Generates an ECDSA P-256 key pair.
   * Keys are DER-encoded, Base64 (compatible across Android and iOS).
   */
  generateEcdsaKeyPair(): Promise<KeyPair> {
    return getNativeModule().cryptoGenerateEcdsaKeyPair();
  },

  /**
   * Signs a UTF-8 message with an ECDSA P-256 private key (DER, Base64).
   * Returns Base64-encoded DER-encoded ASN.1 SEQUENCE signature.
   */
  signEcdsa(message: string, privateKey: string): Promise<string> {
    return getNativeModule().cryptoSignEcdsa(message, privateKey);
  },

  /**
   * Verifies an ECDSA P-256 signature.
   * message: UTF-8 string; signature (DER) and publicKey (DER) are Base64.
   */
  verifyEcdsa(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean> {
    return getNativeModule().cryptoVerifyEcdsa(message, signature, publicKey);
  },
};
