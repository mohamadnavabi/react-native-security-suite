import { NativeModules } from 'react-native';
import { jsonParse } from '../helpers';

export interface PinningConfig {
  /** Base64-encoded SPKI SHA-256 hashes (with or without the `sha256/` prefix). */
  certificates: string[];
  /** Allowed hostnames. Only requests whose host matches one of these are pinned. */
  validDomains: string[];
}

export interface NetworkFetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers?: Record<string, string>;
  body?: string | object;
  timeout?: number;
}

let _globalPinning: PinningConfig | null = null;
let _uninstall: (() => void) | null = null;

function nativeFetch(
  url: string,
  options: NetworkFetchOptions & {
    certificates?: string[];
    validDomains?: string[];
  }
): Promise<Response> {
  const native = NativeModules.SecuritySuite;
  return new Promise((resolve, reject) => {
    native.fetch(
      url,
      {
        method: options.method ?? 'GET',
        headers: options.headers ?? {},
        body: options.body,
        timeout: options.timeout ?? 60,
        certificates: options.certificates ?? [],
        validDomains: options.validDomains ?? [],
        loggerIsEnabled: false,
      },
      (result: any, error: any) => {
        if (error === null || error === undefined) {
          resolve({
            ok: result.status >= 200 && result.status < 300,
            status: result.status,
            url: result.url,
            json: () => jsonParse(result.response),
            text: () => Promise.resolve(result.response),
          } as unknown as Response);
        } else {
          reject(error);
        }
      }
    );
  });
}

export const NetworkSecurity = {
  /**
   * Store a global pinning config used by `installFetchInterceptor()` and
   * `createPinnedFetch()` when no per-call config is provided.
   */
  configurePinning(config: PinningConfig): void {
    _globalPinning = config;
  },

  /** Clear the stored global pinning config. */
  clearPinningConfig(): void {
    _globalPinning = null;
  },

  /**
   * Patch `global.fetch` so all outbound HTTPS calls are routed through the
   * native SSL-pinned transport. Non-HTTPS calls pass through unchanged.
   * Returns an uninstall function that restores the original `global.fetch`.
   */
  installFetchInterceptor(config?: PinningConfig): () => void {
    if (_uninstall) {
      _uninstall();
    }

    const pinning = config ?? _globalPinning;
    const original = global.fetch as typeof global.fetch;

    (global as any).fetch = (
      input: RequestInfo,
      init?: RequestInit
    ): Promise<Response> => {
      const url = typeof input === 'string' ? input : (input as Request).url;
      if (!pinning || !url.startsWith('https://')) {
        return original(input, init);
      }
      return nativeFetch(url, {
        method: (init?.method as NetworkFetchOptions['method']) ?? 'GET',
        headers: init?.headers as Record<string, string>,
        body: init?.body as string,
        timeout: 60,
        certificates: pinning.certificates,
        validDomains: pinning.validDomains,
      });
    };

    _uninstall = () => {
      (global as any).fetch = original;
      _uninstall = null;
    };

    return _uninstall;
  },

  /** Uninstall the global fetch interceptor (if installed). */
  uninstallFetchInterceptor(): void {
    _uninstall?.();
  },

  /**
   * Return a standalone `fetch`-compatible function that enforces the given
   * pinning config without touching `global.fetch`.
   */
  createPinnedFetch(
    config: PinningConfig
  ): (url: string, options?: NetworkFetchOptions) => Promise<Response> {
    return (url, options = {}) =>
      nativeFetch(url, {
        ...options,
        certificates: config.certificates,
        validDomains: config.validDomains,
      });
  },
};
