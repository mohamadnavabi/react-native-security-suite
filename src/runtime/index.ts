import { getNativeModule } from '../native/bridge';
import {
  DEFAULT_PROTECTION_POLICY,
  enforceProtection,
  isHooked,
  type ProtectionPolicy,
} from '../protection';
import type { RuntimeThreatReport, SecurityReport } from '../types/detection';

function parseRuntimeReport(raw: Record<string, unknown>): RuntimeThreatReport {
  const report: RuntimeThreatReport = {
    debuggerAttached: Boolean(raw.debuggerAttached),
    fridaDetected: Boolean(raw.fridaDetected),
    suspiciousLibraries: Array.isArray(raw.suspiciousLibraries)
      ? raw.suspiciousLibraries.filter(
          (item): item is string => typeof item === 'string'
        )
      : [],
    suspiciousPorts: Array.isArray(raw.suspiciousPorts)
      ? raw.suspiciousPorts.filter(
          (item): item is number => typeof item === 'number'
        )
      : [],
  };

  if (raw.xposedDetected !== undefined) {
    report.xposedDetected = Boolean(raw.xposedDetected);
  }

  if (raw.substrateDetected !== undefined) {
    report.substrateDetected = Boolean(raw.substrateDetected);
  }

  if (raw.magiskDetected !== undefined) {
    report.magiskDetected = Boolean(raw.magiskDetected);
  }

  return report;
}

export const RuntimeSecurity = {
  detect(): Promise<RuntimeThreatReport> {
    return getNativeModule()
      .runtimeDetect()
      .then((result) => parseRuntimeReport(result));
  },

  async isDebuggerAttached(): Promise<boolean> {
    const report = await RuntimeSecurity.detect();
    return report.debuggerAttached;
  },

  async isHooked(): Promise<boolean> {
    const report = await RuntimeSecurity.detect();
    return isHooked(report);
  },

  async protect(
    policy: Pick<ProtectionPolicy, 'blockDebugger' | 'blockHooking'> = {}
  ): Promise<RuntimeThreatReport> {
    const runtime = await RuntimeSecurity.detect();
    const resolved = {
      ...DEFAULT_PROTECTION_POLICY,
      ...policy,
    };

    enforceProtection(
      {
        device: {
          isRooted: false,
          isJailbroken: false,
          isEmulator: false,
          isSimulator: false,
          environmentIndicators: [],
        },
        runtime,
        app: {
          validSignature: true,
          debuggable: false,
          tampered: false,
          buildType: 'release',
        },
        riskScore: 0,
        riskLevel: 'low',
      } satisfies SecurityReport,
      {
        blockEmulator: false,
        blockRoot: false,
        blockDebugger: resolved.blockDebugger,
        blockHooking: resolved.blockHooking,
      }
    );

    return runtime;
  },
};

export type { RuntimeThreatReport };
