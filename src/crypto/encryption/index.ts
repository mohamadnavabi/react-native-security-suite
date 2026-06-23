import { getNativeModule } from '../../native/bridge';

export const Encryption = {
  /**
   * Encrypts a UTF-8 plaintext string with an AES-256 key (Base64-encoded, 32 bytes).
   * Returns Base64-encoded: IV (12 bytes) || ciphertext || authTag (16 bytes).
   * IV is generated fresh for every call — never reused.
   */
  encryptAesGcm(plaintext: string, key: string): Promise<string> {
    if (!plaintext || typeof plaintext !== 'string') {
      return Promise.reject(new Error('plaintext must be a non-empty string'));
    }
    if (!key || typeof key !== 'string') {
      return Promise.reject(new Error('key must be a non-empty Base64 string'));
    }
    return getNativeModule().cryptoEncryptAesGcm(plaintext, key);
  },

  /**
   * Decrypts Base64-encoded IV || ciphertext || authTag with an AES-256 key (Base64).
   * Authentication tag is verified before any plaintext is returned.
   */
  decryptAesGcm(ciphertext: string, key: string): Promise<string> {
    if (!ciphertext || typeof ciphertext !== 'string') {
      return Promise.reject(new Error('ciphertext must be a non-empty string'));
    }
    if (!key || typeof key !== 'string') {
      return Promise.reject(new Error('key must be a non-empty Base64 string'));
    }
    return getNativeModule().cryptoDecryptAesGcm(ciphertext, key);
  },
};
