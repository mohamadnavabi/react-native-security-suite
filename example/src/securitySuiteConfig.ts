import type { SecuritySuiteInitConfig } from 'react-native-security-suite';

/** Crypto profile — must match your backend. */
export const cryptoOptions = {
  keyAgreementAlgorithm: 'ECDH' as const,
  keyType: 'EC' as const,
  encryptionKeyAlgorithm: 'AES' as const,
  hmacAlgorithm: 'HmacSHA256' as const,
  cipher: 'AES/GCM/NoPadding' as const,
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
