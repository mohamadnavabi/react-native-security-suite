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
  keyAgreementAlgorithm: 'X25519',
  keyType: 'OKP',
  encryptionKeyAlgorithm: 'AES',
  hmacAlgorithm: 'HmacSHA256',
  cipher: 'AES-GCM',
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
      keyAgreementAlgorithm: 'X25519',
      keyFactoryAlgorithm: 'OKP',
      encryptionKeyAlgorithm: 'AES',
      hmacKeyAlgorithm: 'HmacSHA256',
      cipherTransformation: 'AES-GCM',
      gcmTagLength: 128,
      gcmIvLength: 12,
    });
  });
});
