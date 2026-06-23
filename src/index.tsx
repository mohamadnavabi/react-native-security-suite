import { NativeModules, Platform } from 'react-native';
import {
  ensureLegacyV09Initialized,
  isSecuritySuiteInitialized,
  requireSecuritySuiteConfig,
  resolveCryptoOptions,
} from './config';
import { jsonParse } from './helpers';
import {
  toNativeCryptoOptions,
  type CryptoOptions,
} from './legacy/cryptoOptions';
import {
  toNativeGenerateJWSOptions,
  toNativeJwsFetchOptions,
  type GenerateJWSOptions,
  type JwsFetchOptions,
} from './jws';

export * from './SecureView';
export type {
  GenerateJWSOptions,
  JwsAlgorithm,
  JwsFetchOptions,
  JwsHeaderValue,
  JwsHeaders,
  JwsPayload,
} from './jws';

export type {
  CryptoOptions,
  KeyAgreementAlgorithm,
  KeyType,
  EncryptionKeyAlgorithm,
  HmacAlgorithm,
  CipherAlgorithm,
} from './legacy/cryptoOptions';

export {
  SecurityError,
  SecurityErrorCode,
  mapNativeError,
  isSecurityError,
} from './errors';
export { DeviceSecurity } from './device';
export { RuntimeSecurity } from './runtime';
export { AppIntegrity } from './integrity';
export {
  Crypto,
  CryptoManager,
  Hashing,
  KDF,
  KeyExchange,
  Encryption,
  Signatures,
} from './crypto';
export type {
  HashAlgorithm,
  HkdfHmacAlgorithm,
  DerivedKeys,
  KeyPair,
  HkdfDeriveParams,
  KeyExchangeComputeParams,
} from './crypto';
export { SecuritySuite } from './securitySuite';
export type {
  SecuritySuiteInitConfig,
  SecuritySuiteBehaviorConfig,
  HkdfConfig,
  SslPinningDefaults,
  JwsDefaults,
} from './config';
export {
  DEFAULT_PROTECTION_POLICY,
  enforceProtection,
  isEmulatorEnvironment,
  isHooked,
} from './protection';
export type { ProtectionPolicy } from './protection';
export type {
  RuntimeThreatReport,
  AppIntegrityReport,
  DeviceEnvironment,
  DeviceSecurityReport,
  SecurityReport,
  RiskLevel,
  BuildType,
} from './types/detection';

/** @deprecated Use `JwsHeaders` (optional `Record<string, JwsHeaderValue>`) instead. */
export interface LegacyJwsHeaders {
  kid: string;
  request_id: string;
  [key: string]: string;
}

export interface SslPinningOptions {
  /** Base64-encoded SPKI SHA-256 hashes (with or without `sha256/` prefix). */
  certificates: string[];
  /** Allowed hostnames. Request host must match one of these before pinning is evaluated. */
  validDomains: string[];
}

interface Header {
  [key: string]: string;
}

export interface Options {
  body?: string | object;
  headers: Header;
  method?: 'DELETE' | 'GET' | 'POST' | 'PUT' | 'PATCH';
  timeout?: number;
  /** SSL pinning configuration. Both certificates and validDomains are required together. */
  certificates?: string[];
  validDomains?: string[];
  /** @deprecated Use `jws` instead. */
  keyId?: string;
  /** @deprecated Use `jws` instead. */
  requestId?: string;
  /**
   * @deprecated Legacy signing secret. Use `jws.secret` instead.
   */
  secret?: string;
  /** JWS request-signing configuration. */
  jws?: JwsFetchOptions;
}

interface Response {
  status: number;
  url: string;
  json: () => Promise<{ [key: string]: any }>;
  duration: string;
}

export interface SuccessResponse extends Response {
  response: string;
  responseJSON: Promise<{ [key: string]: any }>;
}

export interface ErrorResponse extends Response {
  error: string;
  path: string;
  message: string;
  code: string;
}

export interface FetchEventResponse {
  url: string;
  options: Options;
  response: {
    response: string;
    error: string;
    path: string;
    message: string;
    code: string;
    status: number;
    url: string;
    json: () => Promise<{ [key: string]: any }>;
    duration: string;
  };
}

const LINKING_ERROR =
  `The package 'react-native-security-suite' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';

const NativeSecuritySuiteModule = NativeModules.SecuritySuite
  ? NativeModules.SecuritySuite
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

function withLegacyBootstrap<T>(
  cryptoOverrides: CryptoOptions | undefined,
  run: () => Promise<T>
): Promise<T> {
  return ensureLegacyV09Initialized(cryptoOverrides).then(run);
}

export const getPublicKey = (options?: CryptoOptions): Promise<string> =>
  withLegacyBootstrap(options, () =>
    NativeSecuritySuiteModule.getPublicKey(
      toNativeCryptoOptions(resolveCryptoOptions(options))
    )
  );

/**
 * @deprecated Prefer `Crypto.establishSharedKey()` which keeps the derived key in native memory.
 */
export const getSharedKey = (
  serverPublicKey: string,
  options?: CryptoOptions
): Promise<string> =>
  withLegacyBootstrap(options, () =>
    NativeSecuritySuiteModule.getSharedKey(
      serverPublicKey,
      toNativeCryptoOptions(resolveCryptoOptions(options))
    )
  );

export const encryptBySharedKey = (
  input: string,
  options?: CryptoOptions
): Promise<string> => {
  if (!input || typeof input !== 'string') {
    return Promise.reject(new Error('Input must be a non-empty string'));
  }
  return withLegacyBootstrap(options, () =>
    NativeSecuritySuiteModule.encrypt(
      input,
      toNativeCryptoOptions(resolveCryptoOptions(options))
    )
  );
};

export const decryptBySharedKey = (
  input: string,
  options?: CryptoOptions
): Promise<string> => {
  if (!input || typeof input !== 'string') {
    return Promise.reject(new Error('Input must be a non-empty string'));
  }
  return withLegacyBootstrap(options, () =>
    NativeSecuritySuiteModule.decrypt(
      input,
      toNativeCryptoOptions(resolveCryptoOptions(options))
    )
  );
};

export const generateJWS = (options: GenerateJWSOptions): Promise<string> => {
  const run = (): Promise<string> => {
    const config = requireSecuritySuiteConfig();
    const merged: GenerateJWSOptions = {
      algorithm: options.algorithm ?? config.jws?.algorithm,
      secret: options.secret,
      headers: options.headers,
      payload: options.payload,
    };

    if (!merged.algorithm) {
      return Promise.reject(
        new Error(
          'JWS algorithm is required. Set jws.algorithm in SecuritySuite.initialize() or pass algorithm in options.'
        )
      );
    }

    const nativeOptions = toNativeGenerateJWSOptions(merged);
    return NativeSecuritySuiteModule.generateJWS(nativeOptions);
  };

  if (isSecuritySuiteInitialized()) {
    return run();
  }

  if (options.algorithm) {
    return ensureLegacyV09Initialized().then(run);
  }

  return Promise.reject(
    new Error(
      'JWS algorithm is required. Set jws.algorithm in SecuritySuite.initialize() or pass algorithm in options.'
    )
  );
};

function normalizeFetchOptions(options: Options): Options {
  if (!options.jws) {
    return options;
  }

  const nativeJws = toNativeJwsFetchOptions(options.jws);
  return {
    ...options,
    jws: {
      algorithm: nativeJws.algorithm,
      secret: nativeJws.secret,
      headers: nativeJws.headers,
      detached: nativeJws.detached,
      ...(options.jws.headerName ? { headerName: options.jws.headerName } : {}),
      ...(options.jws.payload !== undefined
        ? { payload: nativeJws.payload }
        : {}),
    },
  };
}

/**
 * Local obfuscation only — NOT secure encryption. Requires an explicit secret.
 * Never use for credentials, tokens, or PII at rest.
 */
export const obfuscate = (input: string, secret: string): Promise<string> =>
  NativeSecuritySuiteModule.obfuscate(input, secret);

export const deobfuscate = (input: string, secret: string): Promise<string> =>
  NativeSecuritySuiteModule.deobfuscate(input, secret);

export const getDeviceId = (): Promise<string> =>
  new Promise((resolve, reject) => {
    NativeSecuritySuiteModule.getDeviceId(
      (result: string | null, error: string | null) => {
        if (error !== null) reject(error);
        else if (result !== null) resolve(result);
        else reject(new Error('GET_DEVICE_ID_ERROR'));
      }
    );
  });

/**
 * @deprecated Use `obfuscate()` with an explicit secret, or `SecureStorage` for at-rest data.
 */
export const encrypt = (
  input: string,
  hardEncryption = true,
  secretKey: string | null = null
): Promise<string> => {
  if (!input) {
    return Promise.resolve(input);
  }
  if (!secretKey) {
    return Promise.reject(
      new Error(
        'secretKey is required. Device identifiers are not accepted as encryption keys.'
      )
    );
  }
  return NativeSecuritySuiteModule.storageEncrypt(
    input,
    secretKey,
    hardEncryption
  );
};

/**
 * @deprecated Use `deobfuscate()` with an explicit secret, or `SecureStorage` for at-rest data.
 */
export const decrypt = (
  input: string,
  hardEncryption = true,
  secretKey: string | null = null
): Promise<string> => {
  if (!input) {
    return Promise.resolve(input);
  }
  if (!secretKey) {
    return Promise.reject(
      new Error(
        'secretKey is required. Device identifiers are not accepted as encryption keys.'
      )
    );
  }
  return NativeSecuritySuiteModule.storageDecrypt(
    input,
    secretKey,
    hardEncryption
  );
};

const SECURE_STORAGE_FAILED = 'Secure storage operation failed';

function wrapSecureStorage<T>(
  operation: string,
  promise: Promise<T>
): Promise<T> {
  return promise.catch((error: unknown) => {
    const detail =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'Unknown error';
    throw new Error(`${SECURE_STORAGE_FAILED} (${operation}): ${detail}`);
  });
}

/** Hardware-backed encrypted storage (Keychain on iOS, EncryptedSharedPreferences on Android). */
export const SecureStorage = {
  setItem: (key: string, value: string): Promise<void> =>
    wrapSecureStorage(
      'setItem',
      NativeSecuritySuiteModule.secureStorageSetItem(key, value)
    ),

  getItem: (key: string): Promise<string | null> =>
    wrapSecureStorage(
      'getItem',
      NativeSecuritySuiteModule.secureStorageGetItem(key)
    ),

  removeItem: (key: string): Promise<void> =>
    wrapSecureStorage(
      'removeItem',
      NativeSecuritySuiteModule.secureStorageRemoveItem(key)
    ),

  getAllKeys: (): Promise<string[]> =>
    wrapSecureStorage(
      'getAllKeys',
      NativeSecuritySuiteModule.secureStorageGetAllKeys()
    ),

  clear: (): Promise<void> =>
    wrapSecureStorage('clear', NativeSecuritySuiteModule.secureStorageClear()),

  multiSet: async (keyValuePairs: Array<[string, string]>): Promise<void> => {
    await Promise.all(
      keyValuePairs.map(([key, value]) => SecureStorage.setItem(key, value))
    );
  },

  multiGet: async (
    keys: string[]
  ): Promise<readonly [string, string | null][]> =>
    Promise.all(
      keys.map(
        async (key): Promise<[string, string | null]> => [
          key,
          await SecureStorage.getItem(key),
        ]
      )
    ),

  multiRemove: async (keys: string[]): Promise<void> => {
    await Promise.all(keys.map((key) => SecureStorage.removeItem(key)));
  },

  /** @deprecated Use multiSet instead. */
  mergeItem: async (key: string, value: string): Promise<void> => {
    const existing = await SecureStorage.getItem(key);
    if (!existing) {
      await SecureStorage.setItem(key, value);
      return;
    }
    try {
      const merged = JSON.stringify({
        ...JSON.parse(existing),
        ...JSON.parse(value),
      });
      await SecureStorage.setItem(key, merged);
    } catch {
      throw new Error('mergeItem requires valid JSON strings');
    }
  },

  /** @deprecated Use multiSet instead. */
  multiMerge: async (keyValuePairs: Array<[string, string]>): Promise<void> => {
    await Promise.all(
      keyValuePairs.map(([key, value]) => SecureStorage.mergeItem(key, value))
    );
  },
};

export function fetch(
  url: string,
  options: Options,
  loggerIsEnabled = __DEV__
): Promise<SuccessResponse | ErrorResponse> {
  return ensureLegacyV09Initialized().then(
    () =>
      new Promise((resolve, reject) => {
        NativeSecuritySuiteModule.fetch(
          url,
          { ...normalizeFetchOptions(options), loggerIsEnabled },
          (result: SuccessResponse, error: ErrorResponse) => {
            if (error === null) {
              resolve({
                ...result,
                json: () => jsonParse(result.response),
              });
            } else {
              const errorJson = jsonParse(
                typeof error?.error === 'string'
                  ? error.error
                  : JSON.stringify(error)
              );
              reject({
                json: () => errorJson,
                error: error?.error ?? error,
                status: error?.status ?? 0,
                url: error?.url ?? url,
                path: errorJson?.path ?? '',
                message: errorJson?.message ?? String(error?.error ?? error),
                code: errorJson?.code ?? '',
                duration: error?.duration ?? '',
                ...errorJson,
              });
            }
          }
        );
      })
  );
}

export function deviceHasSecurityRisk(): Promise<boolean> {
  return NativeSecuritySuiteModule.deviceHasSecurityRisk();
}

export default NativeSecuritySuiteModule;
