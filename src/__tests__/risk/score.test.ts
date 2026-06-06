import { computeRiskScore } from '../../risk/score';
import type {
  AppIntegrityReport,
  DeviceEnvironment,
  RuntimeThreatReport,
} from '../../types/detection';

const baseRuntime: RuntimeThreatReport = {
  debuggerAttached: false,
  fridaDetected: false,
  suspiciousLibraries: [],
  suspiciousPorts: [],
};

const baseApp: AppIntegrityReport = {
  validSignature: true,
  debuggable: false,
  tampered: false,
  buildType: 'release',
};

const baseEnvironment: DeviceEnvironment = {
  isEmulator: false,
  isSimulator: false,
  indicators: [],
};

describe('computeRiskScore', () => {
  it('returns low risk for a clean device', () => {
    const result = computeRiskScore({
      isRooted: false,
      isJailbroken: false,
      runtime: baseRuntime,
      app: baseApp,
      environment: baseEnvironment,
    });

    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe('low');
  });

  it('adds root/jailbreak weight', () => {
    const result = computeRiskScore({
      isRooted: true,
      isJailbroken: false,
      runtime: baseRuntime,
      app: baseApp,
      environment: baseEnvironment,
    });

    expect(result.riskScore).toBe(40);
    expect(result.riskLevel).toBe('medium');
  });

  it('adds magisk weight', () => {
    const result = computeRiskScore({
      isRooted: false,
      isJailbroken: false,
      runtime: {
        ...baseRuntime,
        magiskDetected: true,
      },
      app: baseApp,
      environment: baseEnvironment,
    });

    expect(result.riskScore).toBe(40);
    expect(result.riskLevel).toBe('medium');
  });

  it('adds frida and debugger weights', () => {
    const result = computeRiskScore({
      isRooted: false,
      isJailbroken: false,
      runtime: {
        ...baseRuntime,
        fridaDetected: true,
        debuggerAttached: true,
      },
      app: baseApp,
      environment: baseEnvironment,
    });

    expect(result.riskScore).toBe(60);
    expect(result.riskLevel).toBe('medium');
  });

  it('caps score at 100 and marks high risk', () => {
    const result = computeRiskScore({
      isRooted: true,
      isJailbroken: true,
      runtime: {
        ...baseRuntime,
        fridaDetected: true,
        xposedDetected: true,
        debuggerAttached: true,
      },
      app: { ...baseApp, tampered: true },
      environment: {
        isEmulator: true,
        isSimulator: false,
        indicators: ['qemu'],
      },
    });

    expect(result.riskScore).toBe(100);
    expect(result.riskLevel).toBe('high');
  });
});
