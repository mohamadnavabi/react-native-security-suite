import type { CryptoOptions } from '../legacy/cryptoOptions';
import type { ProtectionPolicy } from '../protection';
import type { JwsAlgorithm } from '../jws';

export type KeychainAccessibility =
  | 'whenUnlocked'
  | 'whenUnlockedThisDeviceOnly'
  | 'afterFirstUnlock'
  | 'whenPasscodeSetThisDeviceOnly';

/** HKDF derivation context — must match your backend when not using legacy mode. */
export interface HkdfConfig {
  /** Application-specific salt (≥16 bytes). Never reuse across apps. */
  salt: string;
  encryptionInfo: string;
  hmacInfo: string;
}

export interface SslPinningDefaults {
  validDomains: string[];
  /** Base64 SPKI SHA-256 hashes (with or without sha256/ prefix). */
  certificates: string[];
}

export interface JwsDefaults {
  algorithm: JwsAlgorithm;
  secret?: string;
  keyAlias?: string;
  headerName?: string;
}

export interface SecuritySuiteBehaviorConfig {
  protection?: ProtectionPolicy;
  secureNetwork?: {
    requireHttps?: boolean;
    logger?: {
      enabled?: boolean;
      redactHeaders?: string[];
      redactBodyFields?: string[];
    };
  };
  secureStorage?: {
    service?: string;
    requireAuthentication?: boolean;
    accessibility?: KeychainAccessibility;
  };
}

/**
 * Full initialization config. Call `SecuritySuite.initialize()` once at app startup.
 *
 * When `legacyV09Crypto` is true, HKDF is skipped and the raw ECDH shared secret
 * is used (v0.9 compatibility). `hkdf` is still recommended for forward migration.
 */
export interface SecuritySuiteInitConfig extends SecuritySuiteBehaviorConfig {
  crypto: CryptoOptions;
  hkdf?: HkdfConfig;
  /** v0.9 compatibility: ephemeral P-256 keys, no HKDF. */
  legacyV09Crypto?: boolean;
  sslPinning?: SslPinningDefaults;
  jws?: JwsDefaults;
  obfuscationSecret?: string;
}

export interface NativeConfigurePayload {
  hkdfSalt?: string;
  hkdfInfoEncryption?: string;
  hkdfInfoHmac?: string;
  legacyV09Crypto?: boolean;
  secureStorageService?: string;
}
