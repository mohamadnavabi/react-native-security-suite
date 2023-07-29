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

  /*
   * SSL Pinnning start
   */
  interface Response {
    status: number;
    url: string;
    json: () => Promise<{ [key: string]: any }>;
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
    [headerName: string]: string;
  }

  export interface Options {
    body?: string | object;
    headers?: Header;
    method?: 'DELETE' | 'GET' | 'POST' | 'PUT';
    certificates?: string[];
    validDomains?: string[];
    timeout?: number;
  }

  export async function fetch(
    url: string,
    options: Options
  ): Promise<SuccessResponse | ErrorResponse>;
  /*
   * SSL Pinnning end
   */

  export async function deviceHasSecurityRisk(): Promise<boolean>;

  export default SecuritySuite;
}
