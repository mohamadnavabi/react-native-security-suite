import { NativeModules, Platform } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { isJsonString, jsonParse } from './helpers';

export * from './SecureView';

/*
 * SSL Pinnning start
 */
interface Response {
  status: number;
  url: string;
  json: () => Promise<{ [key: string]: any }>;
  duration: string;
}

export interface SuccessResponse extends Response {
  response: string;
  responseJSON: Promise<{ [key: string]: any }>;
}

export interface ErrorResponse extends Response {
  error: string;
  path: string;
  message: string;
  code: string;
}

interface Header {
  [key: string]: string;
}

export interface Options {
  body?: string | object;
  headers: Header;
  method?: 'DELETE' | 'GET' | 'POST' | 'PUT';
  certificates?: string[];
  validDomains?: string[];
  timeout?: number;
}

export interface FetchEventResponse {
  url: string;
  options: Options;
  response: {
    response: string;
    error: string;
    path: string;
    message: string;
    code: string;
    status: number;
    url: string;
    json: () => Promise<{ [key: string]: any }>;
    duration: string;
  };
}

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

export const getPublicKey = (): Promise<string> => SecuritySuite.getPublicKey();

export const getSharedKey = (serverPublicKey: string): Promise<string> =>
  SecuritySuite.getSharedKey(serverPublicKey);

export const encryptBySharedKey = (input: string): Promise<string> =>
  input && typeof input === 'string' ? SecuritySuite.encrypt(input) : '';

export const decryptBySharedKey = (input: string) =>
  input && typeof input === 'string' ? SecuritySuite.decrypt(input) : '';

export const getDeviceId = (): Promise<string> =>
  new Promise((resolve: any, reject: any) => {
    SecuritySuite.getDeviceId((result: string | null, error: string | null) => {
      if (error !== null) reject(error);
      else resolve(result);
    });
  });

export const encrypt = (
  input: string,
  hardEncryption = true,
  secretKey = null
): Promise<string> =>
  new Promise((resolve: any, reject: any) => {
    if (!input) resolve(input);

    SecuritySuite.storageEncrypt(
      input,
      secretKey,
      hardEncryption,
      (result: string | null, error: string | null) => {
        if (error !== null) reject(error);
        else resolve(result);
      }
    );
  });

export const decrypt = (
  input: string,
  hardEncryption = true,
  secretKey = null
): Promise<string> =>
  new Promise((resolve: any, reject: any) => {
    if (!input) resolve(input);

    SecuritySuite.storageDecrypt(
      input,
      secretKey,
      hardEncryption,
      (result: string | null, error: string | null) => {
        if (error !== null) reject(error);
        else resolve(result);
      }
    );
  });

export const SecureStorage = {
  setItem: async (key: string, value: string): Promise<void> => {
    try {
      const encryptedKey = await encrypt(key, false);
      const encryptedValue = await encrypt(value);
      return AsyncStorage.setItem(encryptedKey, encryptedValue);
    } catch (e) {
      console.error('setItem error: ', e);
    }
  },
  getItem: async (key: string): Promise<string | null> => {
    try {
      const encryptedKey = await encrypt(key, false);
      const encryptedData = await AsyncStorage.getItem(encryptedKey);
      return decrypt(encryptedData ?? '');
    } catch (e) {
      console.error('getItem error: ', e);
      return '';
    }
  },
  mergeItem: async (key: string, value: string): Promise<void> => {
    try {
      const encryptedKey = await encrypt(key, false);
      const encryptedData = await AsyncStorage.getItem(encryptedKey);
      const data = await decrypt(encryptedData ?? '');
      if (!isJsonString(data) || !isJsonString(value)) return;
      const mergedData = await JSON.stringify(
        Object.assign(JSON.parse(data), JSON.parse(value))
      );
      const encryptedValue = await encrypt(mergedData);
      return AsyncStorage.setItem(encryptedKey, encryptedValue);
    } catch (e) {
      console.error('mergeItem error: ', e);
    }
  },
  removeItem: async (key: string): Promise<void> => {
    try {
      const encryptedKey = await encrypt(key, false);
      return AsyncStorage.removeItem(encryptedKey);
    } catch (e) {
      console.error('removeItem error: ', e);
    }
  },
  getAllKeys: async (): Promise<readonly string[]> => {
    try {
      const encryptedKeys = await AsyncStorage.getAllKeys();
      return await Promise.all(
        encryptedKeys.map(async (item: string): Promise<string> => {
          const decryptedKey = await decrypt(item, false);
          return decryptedKey ? decryptedKey : item;
        })
      );
    } catch (e) {
      console.error('getAllKeys error: ', e);
      return [];
    }
  },
  multiSet: async (keyValuePairs: Array<Array<string>>): Promise<void> => {
    try {
      const encryptedKeyValuePairs: any = await Promise.all(
        keyValuePairs.map(async (item: Array<string>) => {
          if (item.length === 2 && item[0] && item[1]) {
            const encryptedKey = await encrypt(item[0], false);
            const encryptedValue = await encrypt(item[1]);
            return [encryptedKey, encryptedValue];
          }

          return null;
        })
      );
      AsyncStorage.multiSet(encryptedKeyValuePairs);
    } catch (e) {
      console.error('multiSet error: ', e);
    }
  },
  multiGet: async (
    keys: Array<string>
  ): Promise<readonly [string, string | null][]> => {
    try {
      if (!Array.isArray(keys)) return [];
      const encryptedKeys = await Promise.all(
        keys.map(
          async (item: string): Promise<string> => await encrypt(item, false)
        )
      );
      const encryptedItems = await AsyncStorage.multiGet(encryptedKeys);
      return await Promise.all(
        encryptedItems && encryptedItems.length
          ? encryptedItems.map(async (item: any): Promise<[string, string]> => {
              const decryptedKey = await decrypt(item[0], false);
              const decryptedalue = await decrypt(item[1]);
              return [decryptedKey, decryptedalue];
            })
          : []
      );
    } catch (e) {
      console.error('multiGet error: ', e);
      return [];
    }
  },
  multiMerge: async (keyValuePairs: Array<Array<string>>): Promise<void> => {
    try {
      keyValuePairs.map(async (item: Array<string>) => {
        if (item.length === 2 && item[0] && item[1]) {
          const encryptedKey = await encrypt(item[0], false);
          const encryptedData = await AsyncStorage.getItem(item[0]);
          const data = await decrypt(encryptedData ?? '');
          if (!isJsonString(data) || !isJsonString(item[1])) return null;
          const mergedData = await JSON.stringify(
            Object.assign(JSON.parse(data), JSON.parse(item[1]))
          );
          const encryptedValue = await encrypt(mergedData, false);
          return AsyncStorage.setItem(encryptedKey, encryptedValue);
        }

        return null;
      });
    } catch (e) {
      console.error('multiMerge error: ', e);
    }
  },
  multiRemove: async (keys: Array<string>): Promise<void> => {
    try {
      if (!Array.isArray(keys)) return keys;
      const encryptedKeys = await Promise.all(
        keys.map(
          async (item: string): Promise<string> => await encrypt(item, false)
        )
      );
      return AsyncStorage.multiRemove(encryptedKeys);
    } catch (e) {
      console.error('multiRemove error: ', e);
    }
  },
  clear: async (): Promise<void> => {
    try {
      return AsyncStorage.clear();
    } catch (e) {
      console.error('clear error: ', e);
    }
  },
};

export function fetch(
  url: string,
  options: Options,
  loggerIsEnabled = false
): Promise<SuccessResponse | ErrorResponse> {
  return new Promise((resolve, reject) => {
    SecuritySuite.fetch(
      url,
      { ...options, loggerIsEnabled },
      (result: SuccessResponse, error: ErrorResponse) => {
        try {
          if (error === null) {
            resolve({
              ...result,
              json: () => jsonParse(result.response),
            });
          } else {
            const errorJson = jsonParse(error.error);
            reject({
              json: () => errorJson,
              error: error?.error ?? error,
              status: error?.status ?? '',
              url: error?.url ?? '',
              ...errorJson,
            });
          }
        } catch (e) {
          console.error('SSL Pinnning fetch error: ', e);
        }
      }
    );
  });
}

export function deviceHasSecurityRisk(): Promise<boolean> {
  return SecuritySuite.deviceHasSecurityRisk();
}

export default SecuritySuite;
