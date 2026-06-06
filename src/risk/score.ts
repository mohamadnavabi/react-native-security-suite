import type {
  AppIntegrityReport,
  DeviceEnvironment,
  RiskLevel,
  RuntimeThreatReport,
} from '../types/detection';

export function computeRiskScore(input: {
  isRooted: boolean;
  isJailbroken: boolean;
  runtime: RuntimeThreatReport;
  app: AppIntegrityReport;
  environment: DeviceEnvironment;
}): { riskScore: number; riskLevel: RiskLevel } {
  let riskScore = 0;

  if (input.isRooted || input.isJailbroken) {
    riskScore += 40;
  }

  if (input.runtime.fridaDetected) {
    riskScore += 40;
  }

  if (input.runtime.xposedDetected) {
    riskScore += 40;
  }

  if (input.runtime.substrateDetected) {
    riskScore += 40;
  }

  if (input.runtime.magiskDetected) {
    riskScore += 40;
  }

  if (input.runtime.debuggerAttached) {
    riskScore += 20;
  }

  if (input.environment.isEmulator || input.environment.isSimulator) {
    riskScore += 20;
  }

  if (input.app.tampered) {
    riskScore += 50;
  }

  const riskLevel: RiskLevel =
    riskScore >= 70 ? 'high' : riskScore >= 30 ? 'medium' : 'low';

  return { riskScore: Math.min(100, riskScore), riskLevel };
}
