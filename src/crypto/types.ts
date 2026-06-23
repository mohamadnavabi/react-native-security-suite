export type HashAlgorithm = 'SHA-256' | 'SHA-512';

export type HkdfHmacAlgorithm =
  | 'HmacSHA256'
  | 'HmacSHA384'
  | 'HmacSHA512'
  | 'HMAC-SHA-256'
  | 'HMAC-SHA-384'
  | 'HMAC-SHA-512';

export interface DerivedKeys {
  /** Base64-encoded 32-byte AES-256 encryption key. */
  encryptionKey: string;
  /** Base64-encoded 32-byte HMAC key. */
  macKey: string;
}

export interface KeyPair {
  /** Base64-encoded public key. */
  publicKey: string;
  /** Base64-encoded private key. Never persist or expose to JS in production. */
  privateKey: string;
}

export interface HkdfDeriveParams {
  /** Base64-encoded input key material (e.g., raw ECDH shared secret). */
  sharedSecret: string;
  /** Base64-encoded application-specific salt (≥16 bytes, never reuse across apps). */
  salt: string;
  /** Base64-encoded info context for the encryption key derivation. */
  encryptionInfo: string;
  /** Base64-encoded info context for the HMAC key derivation. */
  macInfo: string;
  hmacAlgorithm: HkdfHmacAlgorithm;
}

export interface KeyExchangeComputeParams {
  /** Base64-encoded server public key. */
  serverPublicKey: string;
  /** Base64-encoded HKDF salt. */
  salt: string;
  /** Base64-encoded info context for encryption key. */
  encryptionInfo: string;
  /** Base64-encoded info context for HMAC key. */
  macInfo: string;
  hmacAlgorithm: HkdfHmacAlgorithm;
}
