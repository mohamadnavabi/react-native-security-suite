interface SecureStorage {
  setItem: (key: string, value: string) => Promise;
  getItem: (key: string) => Promise;
  mergeItem: (key: string, value: string) => Promise;
  removeItem: (key: string) => Promise;
  getAllKeys: () => Promise;
  multiGet: (keys: Array<string>) => Promise;
  multiSet: (keyValuePairs: Array<Array<string>>) => Promise;
  multiMerge: (keyValuePairs: Array<Array<string>>) => Promise;
  multiRemove: (keys: Array<string>) => Promise;
  clear: () => Promise;
}

declare module 'react-native-security-suite' {
  export async function getPublicKey(): Promise<string>;

  export async function getSharedKey(serverPublicKey: string): Promise<string>;

  export async function encryptBySharedKey(input: string): Promise<string>;

  export async function decryptBySharedKey(input: string): Promise<string>;

  export async function encrypt(
    input: string,
    hardEncryption?: boolean,
    secretKey?: string | null
  ): Promise<string>;

  export async function decrypt(
    input: string,
    hardEncryption?: boolean,
    secretKey?: string | null
  ): Promise<string>;

  export const SecureStorage: SecureStorage;

  export async function deviceHasSecurityRisk(): Promise<boolean>;

  export default SecuritySuite;
}
