package com.securitysuite.crypto.hashing;

import com.securitysuite.crypto.utils.AlgorithmAllowlist;

import java.security.MessageDigest;

public final class HashUtils {
  private HashUtils() {}

  public static byte[] sha256(byte[] input) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(input);
  }

  public static byte[] sha512(byte[] input) throws Exception {
    return MessageDigest.getInstance("SHA-512").digest(input);
  }

  public static byte[] hash(byte[] input, String algorithm) throws Exception {
    AlgorithmAllowlist.requireHash(algorithm);
    return MessageDigest.getInstance(algorithm).digest(input);
  }
}
