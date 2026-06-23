import { SecuritySuite } from '../securitySuite';
import type {
  RiskLevel,
  SecurityReport,
  ThreatEvent,
} from '../types/detection';

export type { ThreatEvent };

export interface ThreatMonitorOptions {
  /** How often to poll for threats, in milliseconds. Default: 30 000 */
  intervalMs?: number;
  /** Fire `onThreat` only when risk meets or exceeds this level. Default: 'medium' */
  minRiskLevel?: RiskLevel;
  /** Called each time a threat at or above `minRiskLevel` is detected. */
  onThreat?: (event: ThreatEvent) => void;
  /** Called when a poll cycle throws. */
  onError?: (error: unknown) => void;
  /** Run once immediately on start before the first interval fires. Default: true */
  runImmediately?: boolean;
}

export interface ThreatMonitorHandle {
  stop(): void;
}

const RISK_ORDER: Record<RiskLevel, number> = { low: 0, medium: 1, high: 2 };

function buildEvent(report: SecurityReport): ThreatEvent | null {
  const { device, runtime, app } = report;

  if (device.isRooted) return { type: 'root', report, timestamp: Date.now() };
  if (device.isJailbroken)
    return { type: 'jailbreak', report, timestamp: Date.now() };
  if (device.isEmulator || device.isSimulator)
    return { type: 'emulator', report, timestamp: Date.now() };
  if (runtime.debuggerAttached)
    return { type: 'debugger', report, timestamp: Date.now() };
  if (
    runtime.fridaDetected ||
    runtime.xposedDetected ||
    runtime.substrateDetected ||
    runtime.magiskDetected
  )
    return { type: 'hooking', report, timestamp: Date.now() };
  if (app.tampered) return { type: 'tamper', report, timestamp: Date.now() };

  return null;
}

export const ThreatMonitor = {
  /**
   * Start polling `SecuritySuite.getSecurityReport()` on an interval.
   * Returns a handle with a `stop()` method.
   */
  start(options: ThreatMonitorOptions = {}): ThreatMonitorHandle {
    const {
      intervalMs = 30_000,
      minRiskLevel = 'medium',
      onThreat,
      onError,
      runImmediately = true,
    } = options;

    let active = true;
    let timer: ReturnType<typeof setTimeout> | null = null;

    const poll = async () => {
      if (!active) return;
      try {
        const report = await SecuritySuite.getSecurityReport();
        const score = RISK_ORDER[report.riskLevel];
        const threshold = RISK_ORDER[minRiskLevel];

        if (score >= threshold && onThreat) {
          const event = buildEvent(report) ?? {
            type: 'risk-threshold' as const,
            report,
            timestamp: Date.now(),
          };
          onThreat(event);
        }
      } catch (err) {
        onError?.(err);
      }

      if (active) {
        timer = setTimeout(poll, intervalMs);
      }
    };

    if (runImmediately) {
      poll();
    } else {
      timer = setTimeout(poll, intervalMs);
    }

    return {
      stop() {
        active = false;
        if (timer !== null) {
          clearTimeout(timer);
          timer = null;
        }
      },
    };
  },
};
