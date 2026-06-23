import {
  toNativeKeyProfileOptions,
  toNativeCryptoOptions,
  type CryptoOptions,
} from '../legacy/cryptoOptions';

/** Illustrative profile from README — not a package default or production config. */
const sampleCryptoOptions: CryptoOptions = {
  keyAgreementAlgorithm: 'X25519',
  keyType: 'OKP',
  encryptionKeyAlgorithm: 'AES',
  hmacAlgorithm: 'HmacSHA256',
  cipher: 'AES/GCM/NoPadding',
  tagLength: 128,
  ivLength: 12,
};

describe('toNativeKeyProfileOptions', () => {
  it('returns null when options are omitted', () => {
    expect(toNativeKeyProfileOptions()).toBeNull();
    expect(toNativeKeyProfileOptions(null)).toBeNull();
  });

  it('extracts OKP/X25519 profile fields', () => {
    expect(toNativeKeyProfileOptions(sampleCryptoOptions)).toEqual({
      keyAgreementAlgorithm: 'X25519',
      keyFactoryAlgorithm: 'OKP',
    });
  });

  it('extracts EC/ECDH profile fields', () => {
    expect(
      toNativeKeyProfileOptions({
        keyAgreementAlgorithm: 'ECDH',
        keyType: 'EC',
      } as CryptoOptions)
    ).toEqual({
      keyAgreementAlgorithm: 'ECDH',
      keyFactoryAlgorithm: 'EC',
    });
  });

  it('normalizes Curve25519 key type to OKP', () => {
    const options: CryptoOptions = {
      ...sampleCryptoOptions,
      keyType: 'Curve25519',
    };

    expect(toNativeKeyProfileOptions(options)).toEqual({
      keyAgreementAlgorithm: 'X25519',
      keyFactoryAlgorithm: 'OKP',
    });
  });

  it('throws when key profile fields are missing', () => {
    expect(() =>
      toNativeKeyProfileOptions({
        keyAgreementAlgorithm: 'X25519',
        encryptionKeyAlgorithm: 'AES',
      } as CryptoOptions)
    ).toThrow('Missing required crypto option: keyType');
  });
});

describe('toNativeCryptoOptions', () => {
  it('throws when options are omitted', () => {
    expect(() => toNativeCryptoOptions()).toThrow(
      'Crypto options are required'
    );
    expect(() => toNativeCryptoOptions(null)).toThrow(
      'Crypto options are required'
    );
  });

  it('maps preferred field names to native aliases', () => {
    expect(toNativeCryptoOptions(sampleCryptoOptions)).toEqual({
      keyAgreementAlgorithm: 'X25519',
      keyFactoryAlgorithm: 'OKP',
      encryptionKeyAlgorithm: 'AES',
      hmacKeyAlgorithm: 'HmacSHA256',
      cipherTransformation: 'AES/GCM/NoPadding',
      gcmTagLength: 128,
      gcmIvLength: 12,
    });
  });

  it('normalizes Curve25519 key type to OKP in full crypto options', () => {
    const options: CryptoOptions = {
      ...sampleCryptoOptions,
      keyType: 'Curve25519',
    };

    expect(toNativeCryptoOptions(options).keyFactoryAlgorithm).toBe('OKP');
  });
});
