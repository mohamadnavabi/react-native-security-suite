import { Platform } from 'react-native';

import { SecurityError, SecurityErrorCode } from '../errors';
import type {
  RiskLevel,
  RuntimeThreatReport,
  SecurityReport,
} from '../types/detection';

export interface ProtectionPolicy {
  /** Block emulator (Android) and simulator (iOS) environments. Default: true */
  blockEmulator?: boolean;
  /** Block when a debugger is attached. Default: true */
  blockDebugger?: boolean;
  /** Block Frida, Xposed, Substrate, Magisk, and related instrumentation. Default: true */
  blockHooking?: boolean;
  /** Block rooted (Android) or jailbroken (iOS) devices. Default: false */
  blockRoot?: boolean;
  /** Throw when computed risk level meets or exceeds this threshold. Default: undefined (disabled) */
  minRiskLevel?: RiskLevel;
}

export const DEFAULT_PROTECTION_POLICY: Required<
  Pick<
    ProtectionPolicy,
    'blockEmulator' | 'blockDebugger' | 'blockHooking' | 'blockRoot'
  >
> = {
  blockEmulator: true,
  blockDebugger: true,
  blockHooking: true,
  blockRoot: false,
};

const RISK_LEVEL_ORDER: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
};

export function isEmulatorEnvironment(environment: {
  isEmulator: boolean;
  isSimulator: boolean;
}): boolean {
  return environment.isEmulator || environment.isSimulator;
}

export function isHooked(runtime: RuntimeThreatReport): boolean {
  return (
    runtime.fridaDetected ||
    Boolean(runtime.xposedDetected) ||
    Boolean(runtime.substrateDetected) ||
    Boolean(runtime.magiskDetected)
  );
}

function resolveHookingError(runtime: RuntimeThreatReport): SecurityError {
  if (runtime.xposedDetected) {
    return new SecurityError(
      SecurityErrorCode.XPOSED_DETECTED,
      'Xposed or LSPosed instrumentation detected',
      { runtime }
    );
  }

  if (runtime.substrateDetected) {
    return new SecurityError(
      SecurityErrorCode.SUBSTRATE_DETECTED,
      'Substrate or substitute hooking framework detected',
      { runtime }
    );
  }

  if (runtime.magiskDetected) {
    return new SecurityError(
      SecurityErrorCode.MAGISK_DETECTED,
      'Magisk or Zygisk environment detected',
      { runtime }
    );
  }

  return new SecurityError(
    SecurityErrorCode.FRIDA_DETECTED,
    'Frida or runtime instrumentation detected',
    { runtime }
  );
}

export function enforceProtection(
  report: SecurityReport,
  policy: ProtectionPolicy = DEFAULT_PROTECTION_POLICY
): void {
  const resolved = {
    ...DEFAULT_PROTECTION_POLICY,
    ...policy,
  };

  if (resolved.blockEmulator && isEmulatorEnvironment(report.device)) {
    throw new SecurityError(
      SecurityErrorCode.EMULATOR_DETECTED,
      'Emulator or simulator environment detected',
      {
        isEmulator: report.device.isEmulator,
        isSimulator: report.device.isSimulator,
        indicators: report.device.environmentIndicators,
      }
    );
  }

  if (resolved.blockDebugger && report.runtime.debuggerAttached) {
    throw new SecurityError(
      SecurityErrorCode.DEBUGGER_DETECTED,
      'Debugger attached to the application process',
      { runtime: report.runtime }
    );
  }

  if (resolved.blockHooking && isHooked(report.runtime)) {
    throw resolveHookingError(report.runtime);
  }

  if (resolved.blockRoot) {
    const isCompromised =
      Platform.OS === 'android'
        ? report.device.isRooted
        : report.device.isJailbroken;

    if (isCompromised) {
      throw new SecurityError(
        Platform.OS === 'android'
          ? SecurityErrorCode.ROOT_DETECTED
          : SecurityErrorCode.JAILBREAK_DETECTED,
        Platform.OS === 'android'
          ? 'Rooted Android device detected'
          : 'Jailbroken iOS device detected',
        { device: report.device }
      );
    }
  }

  if (policy.minRiskLevel) {
    const current = RISK_LEVEL_ORDER[report.riskLevel];
    const minimum = RISK_LEVEL_ORDER[policy.minRiskLevel];

    if (current >= minimum) {
      throw new SecurityError(
        SecurityErrorCode.SECURITY_RISK_THRESHOLD,
        `Security risk level ${report.riskLevel} meets policy threshold ${policy.minRiskLevel}`,
        {
          riskScore: report.riskScore,
          riskLevel: report.riskLevel,
          minRiskLevel: policy.minRiskLevel,
        }
      );
    }
  }
}
