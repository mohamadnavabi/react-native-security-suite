interface SecureStorage {
  setItem: (key: string, value: string) => Promise<void>;
  getItem: (key: string) => Promise<string | null>;
  mergeItem: (key: string, value: string) => Promise<void>;
  removeItem: (key: string) => Promise<void>;
  getAllKeys: () => Promise<readonly string[]>;
  multiGet: (
    keys: Array<string>
  ) => Promise<readonly [string, string | null][]>;
  multiSet: (keyValuePairs: Array<Array<string>>) => Promise<void>;
  multiMerge: (keyValuePairs: Array<Array<string>>) => Promise<void>;
  multiRemove: (keys: Array<string>) => Promise<void>;
  clear: () => Promise<void>;
}

declare module 'react-native-security-suite' {
  type EllipticCurveTypes = 'p256' | 'p384' | 'p512';

  function getPublicKey(ellipticCurve: EllipticCurveTypes): Promise<string>;

  function getSharedKey(serverPublicKey: string): Promise<string>;

  function encryptBySharedKey(input: string): Promise<string>;

  function decryptBySharedKey(input: string): Promise<string>;

  function encrypt(
    input: string,
    hardEncryption?: boolean,
    secretKey?: string | null
  ): Promise<string>;

  function decrypt(
    input: string,
    hardEncryption?: boolean,
    secretKey?: string | null
  ): Promise<string>;

  const SecureStorage: SecureStorage;

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

  interface SuccessResponse extends Response {
    response: string;
    responseJSON: Promise<{ [key: string]: any }>;
  }

  interface ErrorResponse extends Response {
    error: string;
    path: string;
    message: string;
    code: string;
  }

  interface Header {
    [key: string]: string;
  }

  interface Options {
    body?: string | object;
    headers: Header;
    method?: 'DELETE' | 'GET' | 'POST' | 'PUT';
    certificates?: string[];
    validDomains?: string[];
    timeout?: number;
  }

  interface FetchEventResponse {
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
      curl: string;
      duration: string;
    };
  }

  function fetch(
    url: string,
    options: Options,
    loggerIsEnabled?: boolean
  ): Promise<SuccessResponse | ErrorResponse>;
  /*
   * SSL Pinnning end
   */

  function deviceHasSecurityRisk(): Promise<boolean>;

  interface SecureViewProps {}

  declare const SecureView: React.ComponentType<SecureViewProps>;
}
