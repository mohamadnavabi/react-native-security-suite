import { __resetSecuritySuiteConfigForTests } from '../config';
import { Crypto, type CryptoOptions } from '../crypto';

const mockGetPublicKey = jest.fn().mockResolvedValue('public-key');

jest.mock('../native/bridge', () => ({
  getNativeModule: () => ({
    configure: jest.fn().mockResolvedValue(undefined),
    getPublicKey: mockGetPublicKey,
  }),
}));

const cryptoOptions: CryptoOptions = {
  keyAgreementAlgorithm: 'ECDH',
  keyType: 'EC',
  encryptionKeyAlgorithm: 'AES',
  hmacAlgorithm: 'HmacSHA256',
  cipher: 'AES/GCM/NoPadding',
  tagLength: 128,
  ivLength: 12,
};

describe('Crypto.getPublicKey', () => {
  beforeEach(() => {
    __resetSecuritySuiteConfigForTests();
    mockGetPublicKey.mockClear();
  });

  it('passes full native crypto options in legacy bootstrap mode', async () => {
    await Crypto.getPublicKey(cryptoOptions);

    expect(mockGetPublicKey).toHaveBeenCalledWith({
      keyAgreementAlgorithm: 'ECDH',
      keyFactoryAlgorithm: 'EC',
      encryptionKeyAlgorithm: 'AES',
      hmacKeyAlgorithm: 'HmacSHA256',
      cipherTransformation: 'AES/GCM/NoPadding',
      gcmTagLength: 128,
      gcmIvLength: 12,
    });
  });
});
