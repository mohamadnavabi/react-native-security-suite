import {
  __resetSecuritySuiteConfigForTests,
  ensureLegacyV09Initialized,
  initializeSecuritySuite,
  isSecuritySuiteInitialized,
  requireSecuritySuiteConfig,
  type SecuritySuiteInitConfig,
} from '../config';
import { SecurityError, SecurityErrorCode } from '../errors';

jest.mock('../native/bridge', () => ({
  getNativeModule: () => ({
    configure: jest.fn().mockResolvedValue(undefined),
  }),
}));

describe('SecuritySuite configuration', () => {
  const validConfig: SecuritySuiteInitConfig = {
    crypto: {
      keyAgreementAlgorithm: 'X25519',
      keyType: 'OKP',
      encryptionKeyAlgorithm: 'AES',
      hmacAlgorithm: 'HmacSHA256',
      cipher: 'AES/GCM/NoPadding',
      tagLength: 128,
      ivLength: 12,
    },
    hkdf: {
      salt: 'app-specific-salt-16b',
      encryptionInfo: 'enc-v1',
      hmacInfo: 'mac-v1',
    },
  };

  beforeEach(() => {
    __resetSecuritySuiteConfigForTests();
  });

  it('requires hkdf when not in legacy mode', async () => {
    await expect(
      initializeSecuritySuite({
        crypto: validConfig.crypto,
      } as SecuritySuiteInitConfig)
    ).rejects.toThrow(SecurityError);

    await expect(
      initializeSecuritySuite({
        crypto: validConfig.crypto,
      } as SecuritySuiteInitConfig)
    ).rejects.toMatchObject({
      code: SecurityErrorCode.CONFIGURATION_ERROR,
    });
  });

  it('allows legacy mode without hkdf', async () => {
    await initializeSecuritySuite({
      ...validConfig,
      legacyV09Crypto: true,
      hkdf: undefined,
    });
    expect(isSecuritySuiteInitialized()).toBe(true);
    expect(requireSecuritySuiteConfig().legacyV09Crypto).toBe(true);
  });

  it('auto-initializes legacy mode for v0.9 callers', async () => {
    await ensureLegacyV09Initialized();
    expect(isSecuritySuiteInitialized()).toBe(true);
    expect(requireSecuritySuiteConfig().legacyV09Crypto).toBe(true);
  });

  it('rejects double initialization', async () => {
    await initializeSecuritySuite(validConfig);
    await expect(initializeSecuritySuite(validConfig)).rejects.toThrow(
      'only be called once'
    );
  });
});
