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

export interface DeviceSecurityReport {
  isRooted: boolean;
  isJailbroken: boolean;
  isEmulator: boolean;
  isSimulator: boolean;
  environmentIndicators: string[];
}

export type RiskLevel = 'low' | 'medium' | 'high';

export interface SecurityReport {
  device: DeviceSecurityReport;
  runtime: RuntimeThreatReport;
  app: AppIntegrityReport;
  riskScore: number;
  riskLevel: RiskLevel;
}

export interface AttestationResult {
  /** Platform: 'app-attest' (iOS) | 'play-integrity' (Android) */
  platform: 'app-attest' | 'play-integrity';
  /** Base64-encoded attestation object for server-side verification. */
  attestation: string;
  /** Key identifier used for subsequent assertions (iOS) or nonce echo (Android). */
  keyId?: string;
}

export interface AttestationAssertion {
  /** Base64-encoded assertion for server-side verification. */
  assertion: string;
  /** The key identifier used to produce this assertion. */
  keyId: string;
}

export interface BiometricOptions {
  /** Prompt shown to the user during biometric authentication. */
  prompt?: string;
  /** Android: subtitle for the biometric dialog. */
  subtitle?: string;
}

export interface SecureStorageOptions extends BiometricOptions {
  /** If true, reading this item requires biometric authentication. Default: false */
  requireBiometric?: boolean;
}

export interface ThreatEvent {
  type:
    | 'root'
    | 'jailbreak'
    | 'emulator'
    | 'debugger'
    | 'hooking'
    | 'tamper'
    | 'risk-threshold';
  report: SecurityReport;
  timestamp: number;
}
