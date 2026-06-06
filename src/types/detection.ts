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
