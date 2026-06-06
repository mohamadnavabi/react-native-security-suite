package com.securitysuite;

import android.util.Base64;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.regex.Pattern;

/**
 * Shared cryptographic utilities. HKDF (RFC 5869) is used instead of raw
 * key-agreement output or single-pass SHA-256 to derive independent symmetric keys.
 */
public final class CryptoUtils {
  public static final String HKDF_SALT = "react-native-security-suite";
  public static final String HKDF_INFO_ENCRYPTION = "rss-encryption-v1";
  public static final String HKDF_INFO_HMAC = "rss-hmac-v1";

  private static final Pattern SAFE_JWS_HEADER_KEY = Pattern.compile("^[a-zA-Z][a-zA-Z0-9_-]*$");
  private static final Pattern SAFE_JWS_VALUE = Pattern.compile("^[\\x20-\\x7E]+$");

  private CryptoUtils() {}

  /** RFC 5869 HKDF expand/extract using the configured HMAC algorithm. */
  public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length, String macAlgorithm)
      throws Exception {
    byte[] actualSalt = (salt == null || salt.length == 0)
        ? new byte[32]
        : salt;

    Mac extractMac = Mac.getInstance(macAlgorithm);
    extractMac.init(new SecretKeySpec(actualSalt, macAlgorithm));
    byte[] prk = extractMac.doFinal(ikm);

    Mac expandMac = Mac.getInstance(macAlgorithm);
    expandMac.init(new SecretKeySpec(prk, macAlgorithm));

    byte[] result = new byte[length];
    byte[] previous = new byte[0];
    int offset = 0;
    byte counter = 1;

    while (offset < length) {
      expandMac.reset();
      expandMac.update(previous);
      if (info != null && info.length > 0) {
        expandMac.update(info);
      }
      expandMac.update(counter);
      previous = expandMac.doFinal();
      int copyLength = Math.min(previous.length, length - offset);
      System.arraycopy(previous, 0, result, offset, copyLength);
      offset += copyLength;
      counter++;
    }

    return result;
  }

  public static byte[] deriveEncryptionKey(byte[] sharedSecret, String macAlgorithm) throws Exception {
    return hkdf(
        sharedSecret,
        HKDF_SALT.getBytes(StandardCharsets.UTF_8),
        HKDF_INFO_ENCRYPTION.getBytes(StandardCharsets.UTF_8),
        32,
        macAlgorithm
    );
  }

  public static byte[] deriveHmacKey(byte[] sharedSecret, String macAlgorithm) throws Exception {
    return hkdf(
        sharedSecret,
        HKDF_SALT.getBytes(StandardCharsets.UTF_8),
        HKDF_INFO_HMAC.getBytes(StandardCharsets.UTF_8),
        32,
        macAlgorithm
    );
  }

  public static String base64UrlEncode(byte[] data) {
    return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
  }

  public static boolean isHttpsUrl(String url) {
    if (url == null || url.isEmpty()) {
      return false;
    }
    try {
      java.net.URI uri = new java.net.URI(url.trim());
      return "https".equalsIgnoreCase(uri.getScheme())
          && uri.getHost() != null
          && !uri.getHost().isEmpty();
    } catch (Exception e) {
      return false;
    }
  }

  public static String normalizePinHash(String pin) {
    if (pin == null) {
      return "";
    }
    return pin.trim().replaceAll("(?i)^sha256/", "");
  }

  public static void validateJwsHeaderKey(String key) throws IllegalArgumentException {
    if (key == null || !SAFE_JWS_HEADER_KEY.matcher(key).matches()) {
      throw new IllegalArgumentException("Invalid JWS header key: " + key);
    }
  }

  public static void validateJwsHeaderValue(String value) throws IllegalArgumentException {
    if (value == null || !SAFE_JWS_VALUE.matcher(value).matches()) {
      throw new IllegalArgumentException("Invalid JWS header value");
    }
  }

  public static String validateJwsAlgorithm(String algorithm) throws IllegalArgumentException {
    if (algorithm == null || algorithm.isEmpty()) {
      return "HS256";
    }
    switch (algorithm) {
      case "HS256":
      case "HS384":
      case "HS512":
        return algorithm;
      default:
        throw new IllegalArgumentException("Unsupported JWS algorithm: " + algorithm);
    }
  }

  public static String hmacAlgorithmForJws(String algorithm) {
    switch (algorithm) {
      case "HS384":
        return "HmacSHA384";
      case "HS512":
        return "HmacSHA512";
      case "HS256":
      default:
        return "HmacSHA256";
    }
  }

  public static byte[] sha256(byte[] input) throws Exception {
    return MessageDigest.getInstance("SHA-256").digest(input);
  }

  public static byte[] randomBytes(int length) {
    byte[] bytes = new byte[length];
    new SecureRandom().nextBytes(bytes);
    return bytes;
  }
}
