package com.securitysuite.crypto.encryption;

import com.securitysuite.crypto.utils.CryptoBytes;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM authenticated encryption.
 *
 * Output format: IV (12 bytes) || ciphertext || authTag (16 bytes)
 * This layout is identical to the iOS CryptoKit AES.GCM.SealedBox.combined format,
 * ensuring cross-platform compatibility.
 */
public final class AesGcmEncryption {
  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  public static final int IV_LENGTH = 12;
  public static final int TAG_LENGTH_BITS = 128;
  public static final int TAG_LENGTH_BYTES = TAG_LENGTH_BITS / 8;
  private static final int KEY_LENGTH = 32;

  private AesGcmEncryption() {}

  /**
   * Encrypts plaintext and returns IV || ciphertext || authTag.
   * @param plaintext raw bytes to encrypt
   * @param keyBytes  AES-256 key — must be exactly 32 bytes
   */
  public static byte[] encrypt(byte[] plaintext, byte[] keyBytes) throws Exception {
    requireKeyLength(keyBytes);
    byte[] iv = CryptoBytes.randomBytes(IV_LENGTH);
    GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), params);
    byte[] ciphertextWithTag = cipher.doFinal(plaintext);
    return concat(iv, ciphertextWithTag);
  }

  /**
   * Decrypts payload structured as IV (12 bytes) || ciphertext || authTag (16 bytes).
   */
  public static byte[] decrypt(byte[] payload, byte[] keyBytes) throws Exception {
    requireKeyLength(keyBytes);
    if (payload.length < IV_LENGTH + TAG_LENGTH_BYTES) {
      throw new IllegalArgumentException("Ciphertext is too short to be valid AES-GCM output");
    }
    GCMParameterSpec params = new GCMParameterSpec(TAG_LENGTH_BITS, payload, 0, IV_LENGTH);
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), params);
    return cipher.doFinal(payload, IV_LENGTH, payload.length - IV_LENGTH);
  }

  private static void requireKeyLength(byte[] keyBytes) {
    if (keyBytes == null || keyBytes.length != KEY_LENGTH) {
      throw new IllegalArgumentException(
          "AES-256-GCM requires exactly 32-byte key; received "
              + (keyBytes == null ? "null" : keyBytes.length + " bytes")
      );
    }
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] result = new byte[a.length + b.length];
    System.arraycopy(a, 0, result, 0, a.length);
    System.arraycopy(b, 0, result, a.length, b.length);
    return result;
  }
}
