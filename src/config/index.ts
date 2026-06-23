import { SecurityError, SecurityErrorCode } from '../errors';
import type { CryptoOptions } from '../legacy/cryptoOptions';
import { getNativeModule } from '../native/bridge';
import type {
  NativeConfigurePayload,
  SecuritySuiteBehaviorConfig,
  SecuritySuiteInitConfig,
} from './types';

/** Default v0.9 ECDH/AES-GCM profile used when legacy APIs run without initialize(). */
export const DEFAULT_LEGACY_CRYPTO: CryptoOptions = {
  keyAgreementAlgorithm: 'X25519',
  keyType: 'OKP',
  encryptionKeyAlgorithm: 'AES',
  hmacAlgorithm: 'HmacSHA256',
  cipher: 'AES/GCM/NoPadding',
  tagLength: 128,
  ivLength: 12,
};

let frozenConfig: Readonly<SecuritySuiteInitConfig> | null = null;
let behaviorConfig: Readonly<SecuritySuiteBehaviorConfig> = {};
let legacyBootstrapPromise: Promise<void> | null = null;
let pendingLegacyCrypto: CryptoOptions | undefined;

function assertNonEmpty(value: unknown, field: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      `Missing required configuration: ${field}`
    );
  }
  return value.trim();
}

function validateHkdf(
  hkdf: SecuritySuiteInitConfig['hkdf'],
  field: string
): void {
  if (!hkdf) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      `Missing required configuration: ${field}`
    );
  }
  const salt = assertNonEmpty(hkdf.salt, `${field}.salt`);
  if (salt.length < 16) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      `${field}.salt must be at least 16 characters`
    );
  }
  assertNonEmpty(hkdf.encryptionInfo, `${field}.encryptionInfo`);
  assertNonEmpty(hkdf.hmacInfo, `${field}.hmacInfo`);
}

function validateInitConfig(config: SecuritySuiteInitConfig): void {
  if (!config.crypto) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      'Missing required configuration: crypto'
    );
  }

  const legacy = config.legacyV09Crypto === true;
  if (!legacy) {
    validateHkdf(config.hkdf, 'hkdf');
  }

  if (config.jws?.algorithm?.startsWith('HS')) {
    if (!config.jws.secret && !config.jws.keyAlias) {
      throw new SecurityError(
        SecurityErrorCode.CONFIGURATION_ERROR,
        'JWS HS* requires jws.secret or jws.keyAlias'
      );
    }
  }
}

function toNativeConfigurePayload(
  config: SecuritySuiteInitConfig
): NativeConfigurePayload {
  const payload: NativeConfigurePayload = {
    legacyV09Crypto: config.legacyV09Crypto === true,
    secureStorageService: config.secureStorage?.service,
  };

  if (config.hkdf) {
    payload.hkdfSalt = config.hkdf.salt.trim();
    payload.hkdfInfoEncryption = config.hkdf.encryptionInfo.trim();
    payload.hkdfInfoHmac = config.hkdf.hmacInfo.trim();
  }

  return payload;
}

export async function initializeSecuritySuite(
  config: SecuritySuiteInitConfig
): Promise<void> {
  if (frozenConfig) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      'SecuritySuite.initialize() must only be called once'
    );
  }

  validateInitConfig(config);
  frozenConfig = Object.freeze({ ...config });
  behaviorConfig = Object.freeze({
    protection: config.protection,
    secureNetwork: config.secureNetwork,
    secureStorage: config.secureStorage,
  });

  const native = getNativeModule();
  const payload = toNativeConfigurePayload(config);

  if (typeof native.configure === 'function') {
    await native.configure(payload as Record<string, unknown>);
  } else if (!config.legacyV09Crypto && config.hkdf) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      'Native configure() is unavailable. Rebuild the app after upgrading react-native-security-suite.'
    );
  }
}

export function configureSecuritySuiteBehavior(
  config: SecuritySuiteBehaviorConfig
): void {
  behaviorConfig = Object.freeze({ ...behaviorConfig, ...config });
}

export function requireSecuritySuiteConfig(): Readonly<SecuritySuiteInitConfig> {
  if (!frozenConfig) {
    throw new SecurityError(
      SecurityErrorCode.CONFIGURATION_ERROR,
      'Call SecuritySuite.initialize() before using security APIs'
    );
  }
  return frozenConfig;
}

/**
 * v0.9 compatibility: auto-configure legacy mode on first security API call.
 * Explicit `SecuritySuite.initialize()` at startup is still recommended.
 */
export function ensureLegacyV09Initialized(
  cryptoOverrides?: CryptoOptions
): Promise<void> {
  if (frozenConfig) {
    return Promise.resolve();
  }

  if (cryptoOverrides) {
    pendingLegacyCrypto = pendingLegacyCrypto
      ? { ...pendingLegacyCrypto, ...cryptoOverrides }
      : cryptoOverrides;
  }

  if (!legacyBootstrapPromise) {
    legacyBootstrapPromise = initializeSecuritySuite({
      legacyV09Crypto: true,
      crypto: pendingLegacyCrypto ?? DEFAULT_LEGACY_CRYPTO,
    }).catch((error) => {
      legacyBootstrapPromise = null;
      throw error;
    });
  }

  return legacyBootstrapPromise;
}

export function resolveCryptoOptions(overrides?: CryptoOptions): CryptoOptions {
  const config = requireSecuritySuiteConfig();
  if (!overrides) {
    return config.crypto;
  }
  return { ...config.crypto, ...overrides };
}

export function isSecuritySuiteInitialized(): boolean {
  return frozenConfig !== null;
}

/** @internal Reset module state between unit tests. */
export function __resetSecuritySuiteConfigForTests(): void {
  frozenConfig = null;
  behaviorConfig = {};
  legacyBootstrapPromise = null;
  pendingLegacyCrypto = undefined;
}

export function getSecuritySuiteBehaviorConfig(): Readonly<SecuritySuiteBehaviorConfig> {
  return behaviorConfig;
}

export type {
  HkdfConfig,
  JwsDefaults,
  KeychainAccessibility,
  NativeConfigurePayload,
  SecuritySuiteBehaviorConfig,
  SecuritySuiteInitConfig,
  SslPinningDefaults,
} from './types';
