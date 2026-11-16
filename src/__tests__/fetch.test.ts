/// <reference types="jest" />

jest.mock('react-native', () => ({
  NativeModules: { SecuritySuite: { fetch: jest.fn() } },
  Platform: {
    OS: 'android',
    select: jest.fn(
      (options: { android?: unknown; default?: unknown }) => options.android
    ),
  },
  requireNativeComponent: jest.fn(() => 'SecureView'),
  UIManager: {
    getViewManagerConfig: jest.fn(),
    dispatchViewManagerCommand: jest.fn(),
  },
  findNodeHandle: jest.fn(),
}));

jest.mock('../config', () => ({
  ...jest.requireActual('../config'),
  ensureLegacyV09Initialized: () => Promise.resolve(),
}));

import { NativeModules } from 'react-native';
import { fetch } from '../index';

const nativeFetch = NativeModules.SecuritySuite.fetch as jest.Mock;

const failWith = (error: unknown) =>
  nativeFetch.mockImplementation((_url, _options, callback) =>
    callback(null, error)
  );

describe('fetch', () => {
  it('reports the transport failure type', async () => {
    failWith({
      error: 'Unable to resolve host "api.example.com"',
      networkError: 'UNKNOWN_HOST',
    });

    await expect(
      fetch('https://api.example.com/v1/me', { headers: {} }, false)
    ).rejects.toMatchObject({
      networkError: 'UNKNOWN_HOST',
      status: 0,
      url: 'https://api.example.com/v1/me',
      message: 'Unable to resolve host "api.example.com"',
    });
  });

  it('leaves networkError unset for HTTP errors, even if the body names one', async () => {
    failWith({
      status: 500,
      url: 'https://api.example.com/v1/me',
      error: JSON.stringify({ message: 'boom', networkError: 'UNKNOWN_HOST' }),
    });

    const error = await fetch(
      'https://api.example.com/v1/me',
      { headers: {} },
      false
    ).catch((e) => e);

    expect(error.status).toBe(500);
    expect(error.message).toBe('boom');
    expect(error.networkError).toBeUndefined();
  });

  it('reports a host outside the pinning domains as SSL_PEER_UNVERIFIED', async () => {
    failWith({
      error: "Hostname 'apim-qa.example.org' is not in the SSL pinning domains",
      networkError: 'SSL_PEER_UNVERIFIED',
    });

    const error = await fetch(
      'https://apim-qa.example.org/v1/app-config',
      { headers: {} },
      false
    ).catch((e) => e);

    expect(error.networkError).toBe('SSL_PEER_UNVERIFIED');
    expect(error.message).toBe(
      "Hostname 'apim-qa.example.org' is not in the SSL pinning domains"
    );
    expect(error).not.toHaveProperty('0');
    expect(error.json()).toEqual({});
  });

  it('leaves networkError unset for validation errors', async () => {
    failWith('Only HTTPS URLs are allowed');

    const error = await fetch(
      'http://api.example.com',
      { headers: {} },
      false
    ).catch((e) => e);

    expect(error.message).toBe('Only HTTPS URLs are allowed');
    expect(error.networkError).toBeUndefined();
    expect(error).not.toHaveProperty('0');
    expect(error.json()).toEqual({});
  });
});
