/**
 * Proposed v1.0 TypeScript API — reference implementation for integrators.
 * This file documents the target public surface; not yet wired to native code.
 */

// ─── Error handling ─────────────────────────────────────────────────────────

export enum SecurityErrorCode {
  ROOT_DETECTED = 'ROOT_DETECTED',
  JAILBREAK_DETECTED = 'JAILBREAK_DETECTED',
  FRIDA_DETECTED = 'FRIDA_DETECTED',
  EMULATOR_DETECTED = 'EMULATOR_DETECTED',
  APP_TAMPERED = 'APP_TAMPERED',
  SSL_PINNING_FAILED = 'SSL_PINNING_FAILED',
  SECURE_STORAGE_UNAVAILABLE = 'SECURE_STORAGE_UNAVAILABLE',
  CRYPTO_KEY_NOT_FOUND = 'CRYPTO_KEY_NOT_FOUND',
  BIOMETRIC_AUTH_FAILED = 'BIOMETRIC_AUTH_FAILED',
  JWS_SIGNING_FAILED = 'JWS_SIGNING_FAILED',
}

export class SecurityError extends Error {
  constructor(
    public readonly code: SecurityErrorCode,
    message: string,
    public readonly details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'SecurityError';
  }
}

// ─── Device security ──────────────────────────────────────────────────────────

export interface DeviceEnvironment {
  isEmulator: boolean;
  isSimulator: boolean;
  indicators: string[];
}

export interface DeviceSecurityNamespace {
  /** @deprecated alias — use isCompromised() */
  hasSecurityRisk(): Promise<boolean>;
  isCompromised(): Promise<boolean>;
  isRooted(): Promise<boolean>; // Android
  isJailbroken(): Promise<boolean>; // iOS
  getEnvironment(): Promise<DeviceEnvironment>;
}

// ─── Runtime security ─────────────────────────────────────────────────────────

export interface RuntimeThreatReport {
  debuggerAttached: boolean;
  fridaDetected: boolean;
  xposedDetected?: boolean;
  substrateDetected?: boolean;
  suspiciousLibraries: string[];
  suspiciousPorts: number[];
}

export interface RuntimeSecurityNamespace {
  detect(): Promise<RuntimeThreatReport>;
}

// ─── App integrity ────────────────────────────────────────────────────────────

export type BuildType = 'debug' | 'release' | 'testflight';

export interface AppIntegrityReport {
  validSignature: boolean;
  installerTrusted?: boolean;
  debuggable: boolean;
  tampered: boolean;
  buildType: BuildType;
}

export interface AppIntegrityNamespace {
  verify(): Promise<AppIntegrityReport>;
  requestPlayIntegrity?(options: { nonce: string }): Promise<{ token: string }>;
  requestAppAttest?(options: { challenge: string }): Promise<{
    keyId: string;
    attestationObject: string;
  }>;
}

// ─── Secure storage ───────────────────────────────────────────────────────────

export type KeychainAccessibility =
  | 'whenUnlocked'
  | 'whenUnlockedThisDeviceOnly'
  | 'afterFirstUnlock'
  | 'whenPasscodeSetThisDeviceOnly';

export interface SecureStorageOptions {
  service?: string;
  requireAuthentication?: boolean;
  accessibility?: KeychainAccessibility;
  useStrongBox?: boolean;
  authenticationPrompt?: string;
}

export interface SecureStorageNamespace {
  setItem(key: string, value: string, options?: SecureStorageOptions): Promise<void>;
  getItem(key: string, options?: SecureStorageOptions): Promise<string | null>;
  removeItem(key: string, options?: SecureStorageOptions): Promise<void>;
  getAllKeys(options?: Pick<SecureStorageOptions, 'service'>): Promise<string[]>;
  clear(options?: Pick<SecureStorageOptions, 'service'>): Promise<void>;
  multiSet(pairs: Array<[string, string]>, options?: SecureStorageOptions): Promise<void>;
  multiGet(keys: string[], options?: SecureStorageOptions): Promise<readonly [string, string | null][]>;
  multiRemove(keys: string[], options?: SecureStorageOptions): Promise<void>;
}

// ─── Crypto ───────────────────────────────────────────────────────────────────

export interface CryptoNamespace {
  randomBytes(length: number): Promise<string>; // base64
  randomUUID(): Promise<string>;
  getPublicKey(options?: { alias?: string; algorithm?: 'X25519' | 'P-256' }): Promise<string>;
  establishSharedKey(
    serverPublicKey: string,
    options?: { alias?: string; ephemeral?: boolean; returnSharedKey?: boolean }
  ): Promise<string | void>;
  encrypt(plaintext: string, options?: { alias?: string }): Promise<string>;
  decrypt(ciphertext: string, options?: { alias?: string }): Promise<string>;
  generateKeyPair(options: { alias: string; algorithm: 'X25519' | 'P-256' | 'Ed25519' }): Promise<void>;
  rotateKey(alias: string): Promise<void>;
  deleteKey(alias: string): Promise<void>;
}

// ─── JWS ──────────────────────────────────────────────────────────────────────

export type JwsAlgorithm = 'HS256' | 'HS384' | 'HS512' | 'ES256' | 'EdDSA';

export interface ReplayProtectedHeaders {
  timestamp: number;
  nonce: string;
  request_id: string;
}

export interface JWSNamespace {
  createReplayProtectedHeaders(): Promise<ReplayProtectedHeaders>;
  generate(options: {
    algorithm?: JwsAlgorithm;
    secret?: string;
    keyAlias?: string;
    payload?: string | Record<string, unknown>;
    headers?: Record<string, string | number | boolean | null>;
    detached?: boolean;
    canonical?: boolean;
  }): Promise<string>;
  generateKeyPair(options: { alias: string; algorithm: 'ES256' | 'EdDSA' }): Promise<void>;
  exportPublicKey(alias: string): Promise<string>;
}

// ─── Secure network ───────────────────────────────────────────────────────────

export interface SslPinningConfig {
  validDomains: string[];
  pins: {
    primary: string[];
    backup?: string[];
  };
  certificateTransparency?: boolean;
}

export interface NetworkLoggerConfig {
  enabled: boolean;
  redactHeaders?: string[];
  redactBodyFields?: string[];
}

export interface SecureNetworkNamespace {
  fetch(
    url: string,
    options: {
      method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
      headers?: Record<string, string>;
      body?: string | Record<string, unknown>;
      timeout?: number;
      sslPinning?: SslPinningConfig;
      /** @deprecated use sslPinning */
      certificates?: string[];
      /** @deprecated use sslPinning */
      validDomains?: string[];
      jws?: Parameters<JWSNamespace['generate']>[0] & { headerName?: string };
    }
  ): Promise<{
    status: number;
    response: string;
    json(): Promise<unknown>;
    duration: string;
  }>;
}

// ─── Screen security ──────────────────────────────────────────────────────────

export interface ScreenSecurityOptions {
  screenshots?: boolean;
  screenRecording?: boolean;
  appSwitcherBlur?: boolean;
}

export interface ScreenSecurityNamespace {
  enable(options: ScreenSecurityOptions): Promise<void>;
  disable(): Promise<void>;
  isScreenRecording(): Promise<boolean>; // iOS
}

// ─── Secure clipboard ─────────────────────────────────────────────────────────

export interface SecureClipboardNamespace {
  setString(value: string, options?: { expiresInMs?: number }): Promise<void>;
  clear(): Promise<void>;
}

// ─── Unified report ───────────────────────────────────────────────────────────

export type RiskLevel = 'low' | 'medium' | 'high';

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

export interface SecuritySuiteConfig {
  secureNetwork?: { requireHttps?: boolean; logger?: NetworkLoggerConfig };
  secureStorage?: { accessibility?: KeychainAccessibility; requireAuthentication?: boolean };
  crypto?: { returnSharedKey?: boolean };
}

export interface SecuritySuiteNamespace {
  configure(config: SecuritySuiteConfig): void;
  getSecurityReport(): Promise<SecurityReport>;
}

// ─── Backward-compatible flat exports ─────────────────────────────────────────
// deviceHasSecurityRisk, fetch, getPublicKey, getSharedKey, encryptBySharedKey,
// decryptBySharedKey, generateJWS, obfuscate, deobfuscate, SecureStorage, SecureView
