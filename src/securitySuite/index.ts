import { Platform } from 'react-native';

import { AppIntegrity } from '../integrity';
import { DeviceSecurity } from '../device';
import { NetworkSecurity } from '../network';
import { RuntimeSecurity } from '../runtime';
import {
  configureSecuritySuiteBehavior,
  initializeSecuritySuite,
  isSecuritySuiteInitialized,
  requireSecuritySuiteConfig,
  type SecuritySuiteBehaviorConfig,
  type SecuritySuiteInitConfig,
} from '../config';
import { enforceProtection, type ProtectionPolicy } from '../protection';
import { computeRiskScore } from '../risk/score';
import type { SecurityReport } from '../types/detection';

export const SecuritySuite = {
  initialize(config: SecuritySuiteInitConfig): Promise<void> {
    return initializeSecuritySuite(config);
  },

  configure(config: SecuritySuiteBehaviorConfig): void {
    configureSecuritySuiteBehavior(config);
  },

  isInitialized(): boolean {
    return isSecuritySuiteInitialized();
  },

  requireConfig(): Readonly<SecuritySuiteInitConfig> {
    return requireSecuritySuiteConfig();
  },

  async getSecurityReport(): Promise<SecurityReport> {
    const [runtime, app, environment, isCompromised, network] =
      await Promise.all([
        RuntimeSecurity.detect(),
        AppIntegrity.verify(),
        DeviceSecurity.getEnvironment(),
        DeviceSecurity.isCompromised(),
        NetworkSecurity.getEnvironment(),
      ]);

    const isRooted = Platform.OS === 'android' && isCompromised;
    const isJailbroken = Platform.OS === 'ios' && isCompromised;

    const { riskScore, riskLevel } = computeRiskScore({
      isRooted,
      isJailbroken,
      runtime,
      app,
      environment,
    });

    return {
      device: {
        isRooted,
        isJailbroken,
        isEmulator: environment.isEmulator,
        isSimulator: environment.isSimulator,
        environmentIndicators: environment.indicators,
      },
      runtime,
      app,
      network,
      riskScore,
      riskLevel,
    };
  },

  async protect(policy?: ProtectionPolicy): Promise<SecurityReport> {
    const report = await SecuritySuite.getSecurityReport();
    enforceProtection(report, policy);
    return report;
  },
};

export type { SecurityReport };
export type {
  SecuritySuiteInitConfig,
  SecuritySuiteBehaviorConfig,
  HkdfConfig,
  SslPinningDefaults,
  JwsDefaults,
} from '../config';
