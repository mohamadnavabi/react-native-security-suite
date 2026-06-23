/** Shared crypto option types used by legacy exports and the Crypto namespace. */
export type KeyAgreementAlgorithm = 'X25519' | 'ECDH' | (string & {});

export type KeyType = 'OKP' | 'EC' | 'Curve25519' | (string & {});

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

function requireCryptoOptions(options?: CryptoOptions | null): CryptoOptions {
  if (!options) {
    throw new Error('Crypto options are required');
  }
  return options;
}

export type NativeKeyProfileOptions = {
  keyAgreementAlgorithm: string;
  keyFactoryAlgorithm: string;
};

function normalizeHmacAlgorithm(value: string): string {
  switch (value) {
    case 'HMAC-SHA-256':
      return 'HmacSHA256';
    case 'HMAC-SHA-384':
      return 'HmacSHA384';
    case 'HMAC-SHA-512':
      return 'HmacSHA512';
    default:
      return value;
  }
}

function normalizeKeyFactoryAlgorithm(value: string): string {
  switch (value) {
    case 'Curve25519':
    case 'X25519':
      return 'OKP';
    default:
      return value;
  }
}

/** Extracts the key-agreement profile for getPublicKey / native key storage. */
export function toNativeKeyProfileOptions(
  options?: CryptoOptions | null
): NativeKeyProfileOptions | null {
  if (!options) {
    return null;
  }

  const resolved = requireCryptoOptions(options);

  return {
    keyAgreementAlgorithm: requireCryptoOption(
      resolved.keyAgreementAlgorithm,
      'keyAgreementAlgorithm'
    ),
    keyFactoryAlgorithm: normalizeKeyFactoryAlgorithm(
      requireCryptoOption(
        resolved.keyType ?? resolved.keyFactoryAlgorithm,
        'keyType'
      )
    ),
  };
}

export function toNativeCryptoOptions(options?: CryptoOptions | null) {
  const resolved = requireCryptoOptions(options);

  return {
    keyAgreementAlgorithm: requireCryptoOption(
      resolved.keyAgreementAlgorithm,
      'keyAgreementAlgorithm'
    ),
    keyFactoryAlgorithm: normalizeKeyFactoryAlgorithm(
      requireCryptoOption(
        resolved.keyType ?? resolved.keyFactoryAlgorithm,
        'keyFactoryAlgorithm'
      )
    ),
    encryptionKeyAlgorithm: requireCryptoOption(
      resolved.encryptionKeyAlgorithm,
      'encryptionKeyAlgorithm'
    ),
    hmacKeyAlgorithm: normalizeHmacAlgorithm(
      requireCryptoOption(
        resolved.hmacAlgorithm ?? resolved.hmacKeyAlgorithm,
        'hmacKeyAlgorithm'
      )
    ),
    cipherTransformation: requireCryptoOption(
      resolved.cipher ?? resolved.cipherTransformation,
      'cipherTransformation'
    ),
    gcmTagLength: requireCryptoOption(
      resolved.tagLength ?? resolved.gcmTagLength,
      'gcmTagLength'
    ),
    gcmIvLength: requireCryptoOption(
      resolved.ivLength ?? resolved.gcmIvLength,
      'gcmIvLength'
    ),
  };
}
