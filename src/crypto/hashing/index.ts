import { getNativeModule } from '../../native/bridge';
import type { HashAlgorithm } from '../types';

export const Hashing = {
  /** Hashes a UTF-8 string and returns the Base64-encoded digest. */
  hash(input: string, algorithm: HashAlgorithm): Promise<string> {
    return getNativeModule().cryptoHash(input, algorithm);
  },

  sha256(input: string): Promise<string> {
    return getNativeModule().cryptoHash(input, 'SHA-256');
  },

  sha512(input: string): Promise<string> {
    return getNativeModule().cryptoHash(input, 'SHA-512');
  },
};
