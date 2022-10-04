import { NativeModules, Platform } from 'react-native';

const LINKING_ERROR =
  `The package 'react-native-security-suite' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo managed workflow\n';

const SecuritySuite = NativeModules.SecuritySuite
  ? NativeModules.SecuritySuite
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
  );
    
export function deviceHasSecurityRisk(): Promise<boolean> {
  return SecuritySuite.deviceHasSecurityRisk();
}

export default SecuritySuite;