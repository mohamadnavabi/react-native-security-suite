declare module 'react-native-security-suite' {
  export async function deviceHasSecurityRisk(): Promise<boolean>;

  export default SecuritySuite;
}
