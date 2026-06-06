/** Shared crypto option types used by legacy exports and the Crypto namespace. */
export type KeyAgreementAlgorithm = 'X25519' | 'ECDH' | (string & {});

export type KeyType = 'OKP' | 'EC' | (string & {});

export type EncryptionKeyAlgorithm = 'AES-256' | 'AES' | (string & {});

export type HmacAlgorithm =
  | 'HMAC-SHA-256'
  | 'HMAC-SHA-384'
  | 'HMAC-SHA-512'
  | 'HmacSHA256'
  | 'HmacSHA384'
  | 'HmacSHA512'
  | (string & {});

export type CipherAlgorithm = 'AES-GCM' | 'AES/GCM/NoPadding' | (string & {});

export interface CryptoOptions {
  keyAgreementAlgorithm: KeyAgreementAlgorithm;
  encryptionKeyAlgorithm: EncryptionKeyAlgorithm;
  keyType?: KeyType;
  hmacAlgorithm?: HmacAlgorithm;
  cipher?: CipherAlgorithm;
  tagLength?: number;
  ivLength?: number;
  /** @deprecated Use `keyType` instead. */
  keyFactoryAlgorithm?: KeyType;
  /** @deprecated Use `hmacAlgorithm` instead. */
  hmacKeyAlgorithm?: HmacAlgorithm;
  /** @deprecated Use `cipher` instead. */
  cipherTransformation?: CipherAlgorithm;
  /** @deprecated Use `tagLength` instead. */
  gcmTagLength?: number;
  /** @deprecated Use `ivLength` instead. */
  gcmIvLength?: number;
}

function requireCryptoOption<T>(value: T | undefined | null, key: string): T {
  if (value === undefined || value === null || value === '') {
    throw new Error(`Missing required crypto option: ${key}`);
  }
  return value;
}

export function toNativeCryptoOptions(options?: CryptoOptions | null) {
  if (!options) {
    throw new Error('Crypto options are required');
  }

  return {
    keyAgreementAlgorithm: requireCryptoOption(
      options.keyAgreementAlgorithm,
      'keyAgreementAlgorithm'
    ),
    keyFactoryAlgorithm: requireCryptoOption(
      options.keyType ?? options.keyFactoryAlgorithm,
      'keyFactoryAlgorithm'
    ),
    encryptionKeyAlgorithm: requireCryptoOption(
      options.encryptionKeyAlgorithm,
      'encryptionKeyAlgorithm'
    ),
    hmacKeyAlgorithm: requireCryptoOption(
      options.hmacAlgorithm ?? options.hmacKeyAlgorithm,
      'hmacKeyAlgorithm'
    ),
    cipherTransformation: requireCryptoOption(
      options.cipher ?? options.cipherTransformation,
      'cipherTransformation'
    ),
    gcmTagLength: requireCryptoOption(
      options.tagLength ?? options.gcmTagLength,
      'gcmTagLength'
    ),
    gcmIvLength: requireCryptoOption(
      options.ivLength ?? options.gcmIvLength,
      'gcmIvLength'
    ),
  };
}
