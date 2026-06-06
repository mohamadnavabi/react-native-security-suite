import { Platform } from 'react-native';

import { getNativeModule } from '../native/bridge';
import type { DeviceEnvironment } from '../types/detection';

function parseEnvironment(raw: Record<string, unknown>): DeviceEnvironment {
  return {
    isEmulator: Boolean(raw.isEmulator),
    isSimulator: Boolean(raw.isSimulator),
    indicators: Array.isArray(raw.indicators)
      ? raw.indicators.filter((item): item is string => typeof item === 'string')
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
};

export type { DeviceEnvironment };
