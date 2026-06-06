export type JwsAlgorithm = 'HS256' | 'HS384' | 'HS512';

export type JwsPayload =
  | string
  | Record<string, unknown>
  | unknown[]
  | number
  | boolean
  | null
  | undefined;

export type JwsHeaderValue = string | number | boolean | null;

export type JwsHeaders = Record<string, JwsHeaderValue>;

export type KeyAgreementAlgorithm = 'X25519' | 'ECDH' | (string & {});

export type KeyType = 'OKP' | 'EC' | (string & {});

export type EncryptionKeyAlgorithm = 'AES-256' | 'AES' | (string & {});

export type HmacAlgorithm =
  | 'HMAC-SHA-256'
  | 'HMAC-SHA-384'
  | 'HMAC-SHA-512'
  | 'HmacSHA256'
  | 'HmacSHA384'
  | 'HmacSHA512'
  | (string & {});

export type CipherAlgorithm = 'AES-GCM' | 'AES/GCM/NoPadding' | (string & {});

export interface CryptoOptions {
  keyAgreementAlgorithm: KeyAgreementAlgorithm;
  encryptionKeyAlgorithm: EncryptionKeyAlgorithm;
  keyType?: KeyType;
  hmacAlgorithm?: HmacAlgorithm;
  cipher?: CipherAlgorithm;
  tagLength?: number;
  ivLength?: number;
  keyFactoryAlgorithm?: KeyType;
  hmacKeyAlgorithm?: HmacAlgorithm;
  cipherTransformation?: CipherAlgorithm;
  gcmTagLength?: number;
  gcmIvLength?: number;
}

export interface GenerateJWSOptions {
  payload?: JwsPayload;
  algorithm?: JwsAlgorithm;
  headers?: JwsHeaders;
  secret: string;
}

export interface JwsFetchOptions {
  algorithm?: JwsAlgorithm;
  headers?: JwsHeaders;
  secret: string;
  payload?: JwsPayload;
  detached?: boolean;
  headerName?: string;
}

export interface SslPinningOptions {
  certificates: string[];
  validDomains: string[];
}

export enum SecurityErrorCode {
  ROOT_DETECTED = 'ROOT_DETECTED',
  JAILBREAK_DETECTED = 'JAILBREAK_DETECTED',
  FRIDA_DETECTED = 'FRIDA_DETECTED',
  XPOSED_DETECTED = 'XPOSED_DETECTED',
  SUBSTRATE_DETECTED = 'SUBSTRATE_DETECTED',
  MAGISK_DETECTED = 'MAGISK_DETECTED',
  DEBUGGER_DETECTED = 'DEBUGGER_DETECTED',
  EMULATOR_DETECTED = 'EMULATOR_DETECTED',
  SECURITY_RISK_THRESHOLD = 'SECURITY_RISK_THRESHOLD',
  SSL_PINNING_FAILED = 'SSL_PINNING_FAILED',
  SECURE_STORAGE_UNAVAILABLE = 'SECURE_STORAGE_UNAVAILABLE',
  CRYPTO_KEY_NOT_FOUND = 'CRYPTO_KEY_NOT_FOUND',
}

export declare class SecurityError extends Error {
  readonly code: SecurityErrorCode;
  readonly details?: Record<string, unknown>;
}

export interface RuntimeThreatReport {
  debuggerAttached: boolean;
  fridaDetected: boolean;
  xposedDetected?: boolean;
  substrateDetected?: boolean;
  magiskDetected?: boolean;
  suspiciousLibraries: string[];
  suspiciousPorts: number[];
}

export type BuildType = 'debug' | 'release' | 'testflight';

export interface AppIntegrityReport {
  validSignature: boolean;
  installerTrusted?: boolean;
  debuggable: boolean;
  tampered: boolean;
  buildType: BuildType;
  signingCertificateSha256?: string;
  installerPackage?: string | null;
  bundleIdentifier?: string;
}

export interface DeviceEnvironment {
  isEmulator: boolean;
  isSimulator: boolean;
  indicators: string[];
}

export type RiskLevel = 'low' | 'medium' | 'high';

export interface ProtectionPolicy {
  blockEmulator?: boolean;
  blockDebugger?: boolean;
  blockHooking?: boolean;
  blockRoot?: boolean;
  minRiskLevel?: RiskLevel;
}

export interface SecurityReport {
  device: {
    isRooted: boolean;
    isJailbroken: boolean;
    isEmulator: boolean;
    isSimulator: boolean;
    environmentIndicators: string[];
  };
  runtime: RuntimeThreatReport;
  app: AppIntegrityReport;
  riskScore: number;
  riskLevel: RiskLevel;
}

interface SecureStorageInterface {
  setItem: (key: string, value: string) => Promise<void>;
  getItem: (key: string) => Promise<string | null>;
  removeItem: (key: string) => Promise<void>;
  getAllKeys: () => Promise<string[]>;
  clear: () => Promise<void>;
  multiGet: (keys: string[]) => Promise<readonly [string, string | null][]>;
  multiSet: (keyValuePairs: Array<[string, string]>) => Promise<void>;
  multiRemove: (keys: string[]) => Promise<void>;
  mergeItem: (key: string, value: string) => Promise<void>;
  multiMerge: (keyValuePairs: Array<[string, string]>) => Promise<void>;
}

declare module 'react-native-security-suite' {
  function getPublicKey(): Promise<string>;
  function getSharedKey(
    serverPublicKey: string,
    options?: CryptoOptions
  ): Promise<string>;
  function encryptBySharedKey(
    input: string,
    options?: CryptoOptions
  ): Promise<string>;
  function decryptBySharedKey(
    input: string,
    options?: CryptoOptions
  ): Promise<string>;
  function generateJWS(options: GenerateJWSOptions): Promise<string>;
  function obfuscate(input: string, secret: string): Promise<string>;
  function deobfuscate(input: string, secret: string): Promise<string>;
  function encrypt(
    input: string,
    hardEncryption?: boolean,
    secretKey?: string | null
  ): Promise<string>;
  function decrypt(
    input: string,
    hardEncryption?: boolean,
    secretKey?: string | null
  ): Promise<string>;
  function getDeviceId(): Promise<string>;
  function fetch(
    url: string,
    options: {
      body?: string | object;
      headers: { [key: string]: string };
      method?: 'DELETE' | 'GET' | 'POST' | 'PUT' | 'PATCH';
      timeout?: number;
      certificates?: string[];
      validDomains?: string[];
      keyId?: string;
      requestId?: string;
      secret?: string;
      jws?: JwsFetchOptions;
    },
    loggerIsEnabled?: boolean
  ): Promise<any>;
  function deviceHasSecurityRisk(): Promise<boolean>;
  function mapNativeError(error: unknown): SecurityError | Error;
  function isSecurityError(error: unknown): error is SecurityError;

  const SecureStorage: SecureStorageInterface;
  const DeviceSecurity: {
    hasSecurityRisk(): Promise<boolean>;
    isCompromised(): Promise<boolean>;
    isRooted(): Promise<boolean>;
    isJailbroken(): Promise<boolean>;
    getEnvironment(): Promise<DeviceEnvironment>;
    isEmulator(): Promise<boolean>;
    protectEnvironment(
      policy?: Pick<ProtectionPolicy, 'blockEmulator'>
    ): Promise<DeviceEnvironment>;
  };
  const RuntimeSecurity: {
    detect(): Promise<RuntimeThreatReport>;
    isDebuggerAttached(): Promise<boolean>;
    isHooked(): Promise<boolean>;
    protect(
      policy?: Pick<ProtectionPolicy, 'blockDebugger' | 'blockHooking'>
    ): Promise<RuntimeThreatReport>;
  };
  const AppIntegrity: {
    verify(): Promise<AppIntegrityReport>;
  };
  const Crypto: {
    getPublicKey(): Promise<string>;
    establishSharedKey(
      serverPublicKey: string,
      options?: CryptoOptions & { returnSharedKey?: boolean }
    ): Promise<string | void>;
  };
  const SecuritySuite: {
    getSecurityReport(): Promise<SecurityReport>;
    protect(policy?: ProtectionPolicy): Promise<SecurityReport>;
  };

  const DEFAULT_PROTECTION_POLICY: Required<
    Pick<
      ProtectionPolicy,
      'blockEmulator' | 'blockDebugger' | 'blockHooking' | 'blockRoot'
    >
  >;
  function enforceProtection(
    report: SecurityReport,
    policy?: ProtectionPolicy
  ): void;
  function isEmulatorEnvironment(environment: {
    isEmulator: boolean;
    isSimulator: boolean;
  }): boolean;
  function isHooked(runtime: RuntimeThreatReport): boolean;
}
