package com.securitysuite.crypto.utils;

import java.security.MessageDigest;
import java.security.SecureRandom;

public final class CryptoBytes {
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private CryptoBytes() {}

  public static byte[] randomBytes(int length) {
    if (length <= 0) {
      throw new IllegalArgumentException("length must be positive");
    }
    byte[] bytes = new byte[length];
    SECURE_RANDOM.nextBytes(bytes);
    return bytes;
  }

  public static boolean constantTimeEquals(byte[] a, byte[] b) {
    return MessageDigest.isEqual(a, b);
  }
}
