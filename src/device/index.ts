import { Platform } from 'react-native';

import { getNativeModule } from '../native/bridge';
import {
  DEFAULT_PROTECTION_POLICY,
  enforceProtection,
  isEmulatorEnvironment,
  type ProtectionPolicy,
} from '../protection';
import type { DeviceEnvironment, SecurityReport } from '../types/detection';

function parseEnvironment(raw: Record<string, unknown>): DeviceEnvironment {
  return {
    isEmulator: Boolean(raw.isEmulator),
    isSimulator: Boolean(raw.isSimulator),
    indicators: Array.isArray(raw.indicators)
      ? raw.indicators.filter(
          (item): item is string => typeof item === 'string'
        )
      : [],
  };
}

export const DeviceSecurity = {
  /** @deprecated Use `isCompromised()` or `SecuritySuite.getSecurityReport()`. */
  hasSecurityRisk(): Promise<boolean> {
    return getNativeModule().deviceHasSecurityRisk();
  },

  isCompromised(): Promise<boolean> {
    return getNativeModule().deviceHasSecurityRisk();
  },

  isRooted(): Promise<boolean> {
    if (Platform.OS !== 'android') {
      return Promise.resolve(false);
    }
    return getNativeModule().deviceHasSecurityRisk();
  },

  isJailbroken(): Promise<boolean> {
    if (Platform.OS !== 'ios') {
      return Promise.resolve(false);
    }
    return getNativeModule().deviceHasSecurityRisk();
  },

  getEnvironment(): Promise<DeviceEnvironment> {
    return getNativeModule()
      .deviceGetEnvironment()
      .then((result) => parseEnvironment(result));
  },

  async isEmulator(): Promise<boolean> {
    const environment = await DeviceSecurity.getEnvironment();
    return isEmulatorEnvironment(environment);
  },

  async protectEnvironment(
    policy: Pick<ProtectionPolicy, 'blockEmulator'> = {}
  ): Promise<DeviceEnvironment> {
    const environment = await DeviceSecurity.getEnvironment();
    const resolved = {
      ...DEFAULT_PROTECTION_POLICY,
      ...policy,
    };

    enforceProtection(
      {
        device: {
          isRooted: false,
          isJailbroken: false,
          isEmulator: environment.isEmulator,
          isSimulator: environment.isSimulator,
          environmentIndicators: environment.indicators,
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
      } satisfies SecurityReport,
      {
        blockDebugger: false,
        blockHooking: false,
        blockRoot: false,
        blockEmulator: resolved.blockEmulator,
      }
    );

    return environment;
  },
};

export type { DeviceEnvironment };
