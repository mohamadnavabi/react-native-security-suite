import { Platform } from 'react-native';

import { AppIntegrity } from '../integrity';
import { DeviceSecurity } from '../device';
import { RuntimeSecurity } from '../runtime';
import { computeRiskScore } from '../risk/score';
import type { SecurityReport } from '../types/detection';

export const SecuritySuite = {
  async getSecurityReport(): Promise<SecurityReport> {
    const [runtime, app, environment, isCompromised] = await Promise.all([
      RuntimeSecurity.detect(),
      AppIntegrity.verify(),
      DeviceSecurity.getEnvironment(),
      DeviceSecurity.isCompromised(),
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
      riskScore,
      riskLevel,
    };
  },
};

export type { SecurityReport };
