import { getNativeModule } from '../native/bridge';
import type { RuntimeThreatReport } from '../types/detection';

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
};

export type { RuntimeThreatReport };
