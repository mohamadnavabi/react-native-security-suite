import { NativeModules } from 'react-native';

import { NetworkSecurity } from '../network';

const API_PIN = 'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';
const CDN_PIN = 'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=';

const pinnedDomains = [
  { domain: 'api.example.com', pins: [API_PIN] },
  { domain: 'example.net', pins: [CDN_PIN], includeSubdomains: true },
];

describe('NetworkSecurity pinning', () => {
  let nativeFetch: jest.Mock;
  const originalFetch = global.fetch;

  beforeEach(() => {
    nativeFetch = jest.fn((_url, _options, callback) =>
      callback({ status: 200, url: _url, response: '{}' }, null)
    );
    NativeModules.SecuritySuite = { fetch: nativeFetch };
    NetworkSecurity.uninstallFetchInterceptor();
    NetworkSecurity.clearPinningConfig();
    global.fetch = originalFetch;
  });

  afterAll(() => {
    NetworkSecurity.uninstallFetchInterceptor();
    global.fetch = originalFetch;
  });

  it('passes per-domain pins to the native transport', async () => {
    const pinnedFetch = NetworkSecurity.createPinnedFetch({ pinnedDomains });

    await pinnedFetch('https://api.example.com/v1/me');

    const options = nativeFetch.mock.calls[0][1];
    expect(options.pinnedDomains).toEqual(pinnedDomains);
    expect(options).not.toHaveProperty('certificates');
    expect(options).not.toHaveProperty('validDomains');
  });

  it('still passes the legacy certificates + validDomains form', async () => {
    const pinnedFetch = NetworkSecurity.createPinnedFetch({
      certificates: [API_PIN, CDN_PIN],
      validDomains: ['api.example.com', 'cdn.example.net'],
    });

    await pinnedFetch('https://cdn.example.net/asset');

    const options = nativeFetch.mock.calls[0][1];
    expect(options.certificates).toEqual([API_PIN, CDN_PIN]);
    expect(options.validDomains).toEqual([
      'api.example.com',
      'cdn.example.net',
    ]);
    expect(options).not.toHaveProperty('pinnedDomains');
  });

  it('refuses a config without any pins instead of fetching unpinned', () => {
    expect(() => NetworkSecurity.createPinnedFetch({})).toThrow(TypeError);
    expect(() => NetworkSecurity.configurePinning({})).toThrow(TypeError);
    expect(() => NetworkSecurity.installFetchInterceptor({})).toThrow(
      TypeError
    );
    expect(nativeFetch).not.toHaveBeenCalled();
  });

  it('routes HTTPS calls through native pinning once the interceptor is installed', async () => {
    const passthrough = jest.fn().mockResolvedValue('plain');
    global.fetch = passthrough as unknown as typeof global.fetch;
    NetworkSecurity.configurePinning({ pinnedDomains });

    const uninstall = NetworkSecurity.installFetchInterceptor();
    await global.fetch('https://api.example.com/v1/me', { method: 'POST' });
    await global.fetch('http://localhost:8081/status');

    expect(nativeFetch).toHaveBeenCalledTimes(1);
    expect(nativeFetch.mock.calls[0][0]).toBe('https://api.example.com/v1/me');
    expect(nativeFetch.mock.calls[0][1]).toMatchObject({
      method: 'POST',
      pinnedDomains,
    });
    expect(passthrough).toHaveBeenCalledWith(
      'http://localhost:8081/status',
      undefined
    );

    uninstall();
    expect(global.fetch).toBe(passthrough);
  });

  it('surfaces native pinning failures as rejections', async () => {
    nativeFetch.mockImplementation((_url, _options, callback) =>
      callback(
        null,
        "Hostname 'evil.example.org' is not in the SSL pinning domains"
      )
    );
    const pinnedFetch = NetworkSecurity.createPinnedFetch({ pinnedDomains });

    await expect(pinnedFetch('https://evil.example.org/')).rejects.toMatch(
      'not in the SSL pinning domains'
    );
  });
});
