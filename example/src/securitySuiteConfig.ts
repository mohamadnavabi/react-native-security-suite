import type { SecuritySuiteInitConfig } from 'react-native-security-suite';

/** Crypto profile — must match your backend. */
export const cryptoOptions = {
  keyAgreementAlgorithm: 'X25519' as const,
  keyType: 'OKP' as const,
  encryptionKeyAlgorithm: 'AES' as const,
  hmacAlgorithm: 'HmacSHA256' as const,
  cipher: 'AES-GCM' as const,
  tagLength: 128,
  ivLength: 12,
};

export const securitySuiteConfig: SecuritySuiteInitConfig = {
  legacyV09Crypto: true,
  crypto: cryptoOptions,
  secureNetwork: {
    requireHttps: true,
    logger: { enabled: __DEV__ },
  },
};
