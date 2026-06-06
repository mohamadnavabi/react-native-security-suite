package com.securitysuite;

import android.util.Base64;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Local obfuscation only — NOT secure encryption. Requires an explicit user-provided secret.
 * Never use for credentials, tokens, or PII at rest.
 */
public class Obfuscation {
  private static byte[] deriveKey(String secret) throws Exception {
    if (secret == null || secret.trim().isEmpty()) {
      throw new IllegalArgumentException("Obfuscation secret is required");
    }
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    return md.digest(secret.getBytes("utf-8"));
  }

  public static String obfuscate(String input, String secret) throws Exception {
    byte[] iv = CryptoUtils.randomBytes(16);
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(deriveKey(secret), "AES"),
        new IvParameterSpec(iv)
    );
    byte[] cipherText = cipher.doFinal(input.getBytes("utf-8"));
    byte[] ivAndCipherText = new byte[iv.length + cipherText.length];
    System.arraycopy(iv, 0, ivAndCipherText, 0, iv.length);
    System.arraycopy(cipherText, 0, ivAndCipherText, iv.length, cipherText.length);
    return Base64.encodeToString(ivAndCipherText, Base64.NO_WRAP);
  }

  public static String deobfuscate(String encoded, String secret) throws Exception {
    byte[] ivAndCipherText = Base64.decode(encoded, Base64.NO_WRAP);
    if (ivAndCipherText.length < 17) {
      throw new IllegalArgumentException("Invalid obfuscated payload");
    }
    byte[] iv = Arrays.copyOfRange(ivAndCipherText, 0, 16);
    byte[] cipherText = Arrays.copyOfRange(ivAndCipherText, 16, ivAndCipherText.length);

    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(deriveKey(secret), "AES"),
        new IvParameterSpec(iv)
    );
    return new String(cipher.doFinal(cipherText), "utf-8");
  }
}
