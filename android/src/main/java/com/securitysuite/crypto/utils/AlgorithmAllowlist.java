package com.securitysuite.crypto.utils;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public final class AlgorithmAllowlist {
  public static final Set<String> HASH_ALGORITHMS = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList("SHA-256", "SHA-512"))
  );

  public static final Set<String> HMAC_ALGORITHMS = Collections.unmodifiableSet(
      new HashSet<>(Arrays.asList("HmacSHA256", "HmacSHA384", "HmacSHA512"))
  );

  private AlgorithmAllowlist() {}

  public static void requireHash(String algorithm) {
    if (algorithm == null || !HASH_ALGORITHMS.contains(algorithm)) {
      throw new IllegalArgumentException("Unsupported hash algorithm: " + algorithm
          + ". Allowed: " + HASH_ALGORITHMS);
    }
  }

  public static void requireHmac(String algorithm) {
    if (algorithm == null || !HMAC_ALGORITHMS.contains(algorithm)) {
      throw new IllegalArgumentException("Unsupported HMAC algorithm: " + algorithm
          + ". Allowed: " + HMAC_ALGORITHMS);
    }
  }
}
