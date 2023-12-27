import { NativeModules, Platform } from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import _ from 'lodash';
import { isJsonString, jsonParse } from './helpers';
import { EventEmitter } from 'events';

/*
 * SSL Pinnning start
 */
interface Response {
  status: number;
  url: string;
  json: () => Promise<{ [key: string]: any }>;
  curl: string;
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
  response: SuccessResponse | ErrorResponse;
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
  setItem: async (key: string, value: string) => {
    try {
      const encryptedKey = await encrypt(key, false);
      const encryptedValue = await encrypt(value);
      return AsyncStorage.setItem(encryptedKey, encryptedValue);
    } catch (e) {
      return e;
    }
  },
  getItem: async (key: string) => {
    try {
      const encryptedKey = await encrypt(key, false);
      const encryptedData = await AsyncStorage.getItem(encryptedKey);
      return decrypt(encryptedData ?? '');
    } catch (e) {
      return e;
    }
  },
  mergeItem: async (key: string, value: string) => {
    try {
      const encryptedKey = await encrypt(key, false);
      const encryptedData = await AsyncStorage.getItem(encryptedKey);
      const data = await decrypt(encryptedData ?? '');
      if (!isJsonString(data) || !isJsonString(value)) return null;
      const mergedData = await JSON.stringify(
        _.merge(JSON.parse(data), JSON.parse(value))
      );
      const encryptedValue = await encrypt(mergedData);
      return AsyncStorage.setItem(encryptedKey, encryptedValue);
    } catch (e) {
      return e;
    }
  },
  removeItem: async (key: string) => {
    try {
      const encryptedKey = await encrypt(key, false);
      return AsyncStorage.removeItem(encryptedKey);
    } catch (e) {
      return e;
    }
  },
  getAllKeys: async () => {
    try {
      const encryptedKeys = await AsyncStorage.getAllKeys();
      return await Promise.all(
        encryptedKeys.map(async (item: string): Promise<string> => {
          const decryptedKey = await decrypt(item, false);
          return decryptedKey ? decryptedKey : item;
        })
      );
    } catch (e) {
      return e;
    }
  },
  multiSet: async (
    keyValuePairs: Array<Array<string>>
  ): Promise<void | string[][]> => {
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
  multiGet: async (keys: Array<string>) => {
    try {
      if (!Array.isArray(keys)) return null;
      const encryptedKeys = await Promise.all(
        keys.map(
          async (item: string): Promise<string> => await encrypt(item, false)
        )
      );
      const encryptedItems = await AsyncStorage.multiGet(encryptedKeys);
      return await Promise.all(
        encryptedItems && encryptedItems.length
          ? encryptedItems.map(async (item: any): Promise<string[]> => {
              const decryptedKey = await decrypt(item[0], false);
              const decryptedalue = await decrypt(item[1]);
              return [decryptedKey, decryptedalue];
            })
          : []
      );
    } catch (e) {
      return e;
    }
  },
  multiMerge: async (keyValuePairs: Array<Array<string>>) => {
    try {
      return keyValuePairs.map(async (item: Array<string>) => {
        if (item.length === 2 && item[0] && item[1]) {
          const encryptedKey = await encrypt(item[0], false);
          const encryptedData = await AsyncStorage.getItem(item[0]);
          const data = await decrypt(encryptedData ?? '');
          if (!isJsonString(data) || !isJsonString(item[1])) return null;
          const mergedData = await JSON.stringify(
            _.merge(JSON.parse(data), JSON.parse(item[1]))
          );
          const encryptedValue = await encrypt(mergedData, false);
          return AsyncStorage.setItem(encryptedKey, encryptedValue);
        }

        return null;
      });
    } catch (e) {
      return e;
    }
  },
  multiRemove: async (keys: Array<string>) => {
    try {
      if (!Array.isArray(keys)) return keys;
      const encryptedKeys = await Promise.all(
        keys.map(
          async (item: string): Promise<string> => await encrypt(item, false)
        )
      );
      return AsyncStorage.multiRemove(encryptedKeys);
    } catch (e) {
      return e;
    }
  },
  clear: async () => {
    try {
      return AsyncStorage.clear();
    } catch (e) {
      return e;
    }
  },
};

export function fetch(
  url: string,
  options: Options
): Promise<SuccessResponse | ErrorResponse> {
  return new Promise((resolve, reject) => {
    SecuritySuite.fetch(
      url,
      options,
      (result: SuccessResponse, error: ErrorResponse) => {
        SSEventEmitter.emit('fetch', {
          url,
          options,
          response: result || error,
        });

        try {
          if (error === null) {
            result.json = () => jsonParse(result.response);
            resolve(result);
          } else {
            const errorJson = jsonParse(error.error);
            reject({
              json: () => errorJson,
              error: error?.error,
              path: errorJson?.path,
              message: errorJson?.message,
              code: errorJson?.code,
              status: error?.status,
              url: error?.url,
              curl: error?.curl,
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

export const SSEventEmitter = new EventEmitter();

export default SecuritySuite;
