package com.securitysuite.crypto.kdf;

import com.securitysuite.crypto.utils.AlgorithmAllowlist;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 5869 HKDF implementation supporting multi-key derivation from a shared secret.
 */
public final class HkdfDerivation {
  private HkdfDerivation() {}

  public static byte[] extract(byte[] ikm, byte[] salt, String hmacAlgorithm) throws Exception {
    AlgorithmAllowlist.requireHmac(hmacAlgorithm);
    byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
    Mac mac = Mac.getInstance(hmacAlgorithm);
    mac.init(new SecretKeySpec(actualSalt, hmacAlgorithm));
    return mac.doFinal(ikm);
  }

  public static byte[] expand(byte[] prk, byte[] info, int outputLength, String hmacAlgorithm) throws Exception {
    AlgorithmAllowlist.requireHmac(hmacAlgorithm);
    if (outputLength <= 0 || outputLength > 255 * 32) {
      throw new IllegalArgumentException("Invalid HKDF output length: " + outputLength);
    }
    Mac mac = Mac.getInstance(hmacAlgorithm);
    mac.init(new SecretKeySpec(prk, hmacAlgorithm));

    byte[] result = new byte[outputLength];
    byte[] previous = new byte[0];
    int offset = 0;
    byte counter = 1;

    while (offset < outputLength) {
      mac.reset();
      mac.update(previous);
      if (info != null && info.length > 0) {
        mac.update(info);
      }
      mac.update(counter);
      previous = mac.doFinal();
      int copyLength = Math.min(previous.length, outputLength - offset);
      System.arraycopy(previous, 0, result, offset, copyLength);
      offset += copyLength;
      counter++;
    }
    return result;
  }

  public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int outputLength, String hmacAlgorithm)
      throws Exception {
    return expand(extract(ikm, salt, hmacAlgorithm), info, outputLength, hmacAlgorithm);
  }

  /**
   * Derives independent encryption and HMAC keys from a shared secret using HKDF.
   * Each key is derived with a distinct info context to ensure cryptographic independence.
   */
  public static DerivedKeys deriveKeys(
      byte[] sharedSecret,
      byte[] salt,
      byte[] encryptionInfo,
      byte[] macInfo,
      int keyLength,
      String hmacAlgorithm
  ) throws Exception {
    byte[] prk = extract(sharedSecret, salt, hmacAlgorithm);
    byte[] encryptionKey = expand(prk, encryptionInfo, keyLength, hmacAlgorithm);
    byte[] macKey = expand(prk, macInfo, keyLength, hmacAlgorithm);
    return new DerivedKeys(encryptionKey, macKey);
  }

  public static final class DerivedKeys {
    public final byte[] encryptionKey;
    public final byte[] macKey;

    DerivedKeys(byte[] encryptionKey, byte[] macKey) {
      this.encryptionKey = encryptionKey.clone();
      this.macKey = macKey.clone();
    }
  }
}
