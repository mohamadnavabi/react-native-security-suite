import { SecurityError, SecurityErrorCode } from '../errors';
import {
  DEFAULT_PROTECTION_POLICY,
  enforceProtection,
  isEmulatorEnvironment,
  isHooked,
} from '../protection';
import type { SecurityReport } from '../types/detection';

const cleanReport: SecurityReport = {
  device: {
    isRooted: false,
    isJailbroken: false,
    isEmulator: false,
    isSimulator: false,
    environmentIndicators: [],
  },
  runtime: {
    debuggerAttached: false,
    fridaDetected: false,
    suspiciousLibraries: [],
    suspiciousPorts: [],
  },
  app: {
    validSignature: true,
    debuggable: false,
    tampered: false,
    buildType: 'release',
  },
  riskScore: 0,
  riskLevel: 'low',
};

describe('protection helpers', () => {
  it('detects emulator environments', () => {
    expect(
      isEmulatorEnvironment({ isEmulator: true, isSimulator: false })
    ).toBe(true);
    expect(
      isEmulatorEnvironment({ isEmulator: false, isSimulator: true })
    ).toBe(true);
    expect(
      isEmulatorEnvironment({ isEmulator: false, isSimulator: false })
    ).toBe(false);
  });

  it('detects hooking signals', () => {
    expect(isHooked({ ...cleanReport.runtime, fridaDetected: true })).toBe(
      true
    );
    expect(isHooked({ ...cleanReport.runtime, xposedDetected: true })).toBe(
      true
    );
    expect(isHooked({ ...cleanReport.runtime, substrateDetected: true })).toBe(
      true
    );
    expect(isHooked({ ...cleanReport.runtime, magiskDetected: true })).toBe(
      true
    );
    expect(isHooked(cleanReport.runtime)).toBe(false);
  });
});

describe('enforceProtection', () => {
  it('uses secure defaults', () => {
    expect(DEFAULT_PROTECTION_POLICY.blockEmulator).toBe(true);
    expect(DEFAULT_PROTECTION_POLICY.blockDebugger).toBe(true);
    expect(DEFAULT_PROTECTION_POLICY.blockHooking).toBe(true);
    expect(DEFAULT_PROTECTION_POLICY.blockRoot).toBe(false);
  });

  it('throws EMULATOR_DETECTED for simulator environments', () => {
    expect(() =>
      enforceProtection({
        ...cleanReport,
        device: {
          ...cleanReport.device,
          isSimulator: true,
          environmentIndicators: ['TARGET_OS_SIMULATOR'],
        },
      })
    ).toThrow(SecurityError);

    try {
      enforceProtection({
        ...cleanReport,
        device: {
          ...cleanReport.device,
          isSimulator: true,
          environmentIndicators: ['TARGET_OS_SIMULATOR'],
        },
      });
    } catch (error) {
      expect((error as SecurityError).code).toBe(
        SecurityErrorCode.EMULATOR_DETECTED
      );
    }
  });

  it('throws DEBUGGER_DETECTED when debugger is attached', () => {
    try {
      enforceProtection({
        ...cleanReport,
        runtime: { ...cleanReport.runtime, debuggerAttached: true },
      });
    } catch (error) {
      expect((error as SecurityError).code).toBe(
        SecurityErrorCode.DEBUGGER_DETECTED
      );
    }
  });

  it('throws XPOSED_DETECTED before generic frida errors', () => {
    try {
      enforceProtection({
        ...cleanReport,
        runtime: {
          ...cleanReport.runtime,
          fridaDetected: true,
          xposedDetected: true,
        },
      });
    } catch (error) {
      expect((error as SecurityError).code).toBe(
        SecurityErrorCode.XPOSED_DETECTED
      );
    }
  });

  it('throws SECURITY_RISK_THRESHOLD when configured', () => {
    try {
      enforceProtection(
        {
          ...cleanReport,
          riskScore: 40,
          riskLevel: 'medium',
        },
        {
          blockEmulator: false,
          blockDebugger: false,
          blockHooking: false,
          minRiskLevel: 'medium',
        }
      );
    } catch (error) {
      expect((error as SecurityError).code).toBe(
        SecurityErrorCode.SECURITY_RISK_THRESHOLD
      );
    }
  });
});
