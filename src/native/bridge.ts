import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-security-suite' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';

export interface SecuritySuiteNativeModule {
  getPublicKey(): Promise<string>;
  getSharedKey(serverPK: string, options: Record<string, unknown>): Promise<string>;
  establishSharedKey?(
    serverPK: string,
    options: Record<string, unknown>
  ): Promise<void>;
  runtimeDetect(): Promise<Record<string, unknown>>;
  appIntegrityVerify(): Promise<Record<string, unknown>>;
  deviceGetEnvironment(): Promise<Record<string, unknown>>;
  deviceHasSecurityRisk(): Promise<boolean>;
  [key: string]: unknown;
}

export function getNativeModule(): SecuritySuiteNativeModule {
  const module = NativeModules.SecuritySuite as
    | SecuritySuiteNativeModule
    | undefined;

  if (module) {
    return module;
  }

  return new Proxy({} as SecuritySuiteNativeModule, {
    get() {
      throw new Error(LINKING_ERROR);
    },
  });
}
