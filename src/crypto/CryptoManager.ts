import { Hashing } from './hashing';
import { KDF } from './kdf';
import { KeyExchange } from './key_exchange';
import { Encryption } from './encryption';
import { Signatures } from './signatures';

export type {
  HashAlgorithm,
  HkdfHmacAlgorithm,
  DerivedKeys,
  KeyPair,
  HkdfDeriveParams,
  KeyExchangeComputeParams,
} from './types';

/**
 * Central cryptography API — groups all primitives under one namespace.
 *
 * All binary I/O uses Base64-encoded strings. Text I/O uses UTF-8 strings.
 *
 * @example
 *   const { encryptionKey } = await CryptoManager.keyExchange.ecdhComputeAndDeriveKeys({ ... });
 *   const ciphertext = await CryptoManager.encryption.encryptAesGcm(plaintext, encryptionKey);
 */
export const CryptoManager = {
  /** SHA-256 and SHA-512 hashing. */
  hashing: Hashing,

  /** HKDF-SHA256 multi-key derivation from a shared secret. */
  kdf: KDF,

  /** ECDH P-256 and X25519 key exchange with integrated HKDF key derivation. */
  keyExchange: KeyExchange,

  /** AES-256-GCM authenticated encryption. Output: IV || ciphertext || authTag. */
  encryption: Encryption,

  /** Ed25519 and ECDSA P-256 digital signatures. */
  signatures: Signatures,
};
