import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-security-suite' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';

import type {
  DerivedKeys,
  EphemeralDerivedKeys,
  KeyPair,
} from '../crypto/types';

export interface SecuritySuiteNativeModule {
  configure?(config: Record<string, unknown>): Promise<void>;
  getPublicKey(options?: Record<string, unknown> | null): Promise<string>;
  getSharedKey(
    serverPK: string,
    options: Record<string, unknown>
  ): Promise<string>;
  establishSharedKey?(
    serverPK: string,
    options: Record<string, unknown>
  ): Promise<void>;
  encrypt(input: string, options: Record<string, unknown>): Promise<string>;
  decrypt(input: string, options: Record<string, unknown>): Promise<string>;
  storageEncrypt(
    input: string,
    secretKey: string,
    hardEncryption: boolean
  ): Promise<string>;
  storageDecrypt(
    input: string,
    secretKey: string,
    hardEncryption: boolean
  ): Promise<string>;
  runtimeDetect(): Promise<Record<string, unknown>>;
  appIntegrityVerify(): Promise<Record<string, unknown>>;
  deviceGetEnvironment(): Promise<Record<string, unknown>>;
  deviceHasSecurityRisk(): Promise<boolean>;

  // ─── CryptoManager ───────────────────────────────────────────────────────
  cryptoHash(input: string, algorithm: string): Promise<string>;
  cryptoDeriveKeys(params: Record<string, unknown>): Promise<DerivedKeys>;
  cryptoEncryptAesGcm(plaintext: string, key: string): Promise<string>;
  cryptoDecryptAesGcm(ciphertext: string, key: string): Promise<string>;
  cryptoGetEcdhPublicKey(): Promise<string>;
  cryptoEcdhComputeAndDeriveKeys(
    params: Record<string, unknown>
  ): Promise<DerivedKeys>;
  cryptoRotateEcdhKeyPair(): Promise<string>;
  cryptoDeleteEcdhKeyPair(): Promise<void>;
  cryptoEcdhEphemeralComputeAndDeriveKeys(
    params: Record<string, unknown>
  ): Promise<EphemeralDerivedKeys>;
  cryptoGetX25519PublicKey(): Promise<string>;
  cryptoX25519ComputeAndDeriveKeys(
    params: Record<string, unknown>
  ): Promise<DerivedKeys>;
  cryptoRotateX25519KeyPair(): Promise<string>;
  cryptoDeleteX25519KeyPair(): Promise<void>;
  cryptoX25519EphemeralComputeAndDeriveKeys(
    params: Record<string, unknown>
  ): Promise<EphemeralDerivedKeys>;
  cryptoGenerateEd25519KeyPair(): Promise<KeyPair>;
  cryptoSignEd25519(message: string, privateKey: string): Promise<string>;
  cryptoVerifyEd25519(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean>;
  cryptoGenerateEcdsaKeyPair(): Promise<KeyPair>;
  cryptoSignEcdsa(message: string, privateKey: string): Promise<string>;
  cryptoVerifyEcdsa(
    message: string,
    signature: string,
    publicKey: string
  ): Promise<boolean>;

  // ─── CSPRNG ──────────────────────────────────────────────────────────────
  cryptoRandomBytes(count: number): Promise<string>;

  // ─── Asymmetric JWS ──────────────────────────────────────────────────────
  generateAsymmetricJWS(options: Record<string, unknown>): Promise<string>;

  // ─── Biometric SecureStorage ──────────────────────────────────────────────
  secureStorageSetItemBiometric(
    key: string,
    value: string,
    options: Record<string, unknown>
  ): Promise<void>;
  secureStorageGetItemBiometric(
    key: string,
    options: Record<string, unknown>
  ): Promise<string | null>;
  secureStorageBiometricIsAvailable(): Promise<boolean>;

  // ─── Background / window security ────────────────────────────────────────
  screenSetWindowSecure(enabled: boolean): Promise<void>;

  // ─── Device Attestation ──────────────────────────────────────────────────
  deviceAttestationIsSupported(): Promise<boolean>;
  deviceAttestationGenerateKey(): Promise<string>;
  deviceAttestationAttestKey(
    keyId: string,
    clientDataHash: string
  ): Promise<string>;
  deviceAttestationGenerateAssertion(
    keyId: string,
    clientDataHash: string
  ): Promise<string>;
  deviceAttestationGetPlayIntegrityToken(nonce: string): Promise<string>;

  [key: string]: unknown;
}

export function getNativeModule(): SecuritySuiteNativeModule {
  const module = NativeModules.SecuritySuite as
    | SecuritySuiteNativeModule
    | undefined;

  if (module) {
    return module;
  }

  return new Proxy({} as SecuritySuiteNativeModule, {
    get() {
      throw new Error(LINKING_ERROR);
    },
  });
}
