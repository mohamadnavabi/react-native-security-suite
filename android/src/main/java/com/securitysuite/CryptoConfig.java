package com.securitysuite;

import com.facebook.react.bridge.ReadableMap;

/**
 * Cryptographic parameters supplied by the application.
 */
public final class CryptoConfig {
  public final String keyAgreementAlgorithm;
  public final String keyFactoryAlgorithm;
  public final String encryptionKeyAlgorithm;
  public final String hmacKeyAlgorithm;
  public final String cipherTransformation;
  public final int gcmTagLength;
  public final int gcmIvLength;

  private CryptoConfig(
      String keyAgreementAlgorithm,
      String keyFactoryAlgorithm,
      String encryptionKeyAlgorithm,
      String hmacKeyAlgorithm,
      String cipherTransformation,
      int gcmTagLength,
      int gcmIvLength
  ) {
    this.keyAgreementAlgorithm = keyAgreementAlgorithm;
    this.keyFactoryAlgorithm = keyFactoryAlgorithm;
    this.encryptionKeyAlgorithm = encryptionKeyAlgorithm;
    this.hmacKeyAlgorithm = hmacKeyAlgorithm;
    this.cipherTransformation = cipherTransformation;
    this.gcmTagLength = gcmTagLength;
    this.gcmIvLength = gcmIvLength;
  }

  public static CryptoConfig fromReadableMap(ReadableMap options) {
    if (options == null) {
      throw new IllegalArgumentException("Crypto options are required");
    }

    return new CryptoConfig(
        requireString(options, "keyAgreementAlgorithm"),
        requireString(options, "keyFactoryAlgorithm"),
        requireString(options, "encryptionKeyAlgorithm"),
        requireString(options, "hmacKeyAlgorithm"),
        requireString(options, "cipherTransformation"),
        requireInt(options, "gcmTagLength"),
        requireInt(options, "gcmIvLength")
    );
  }

  public CryptoConfig merge(ReadableMap options) {
    return options == null ? this : fromReadableMap(mergeMaps(this, options));
  }

  private static ReadableMap mergeMaps(CryptoConfig base, ReadableMap overrides) {
    com.facebook.react.bridge.WritableMap map = com.facebook.react.bridge.Arguments.createMap();
    map.putString("keyAgreementAlgorithm", base.keyAgreementAlgorithm);
    map.putString("keyFactoryAlgorithm", base.keyFactoryAlgorithm);
    map.putString("encryptionKeyAlgorithm", base.encryptionKeyAlgorithm);
    map.putString("hmacKeyAlgorithm", base.hmacKeyAlgorithm);
    map.putString("cipherTransformation", base.cipherTransformation);
    map.putInt("gcmTagLength", base.gcmTagLength);
    map.putInt("gcmIvLength", base.gcmIvLength);

    if (overrides.hasKey("keyAgreementAlgorithm")) {
      map.putString("keyAgreementAlgorithm", overrides.getString("keyAgreementAlgorithm"));
    }
    if (overrides.hasKey("keyFactoryAlgorithm")) {
      map.putString("keyFactoryAlgorithm", overrides.getString("keyFactoryAlgorithm"));
    }
    if (overrides.hasKey("encryptionKeyAlgorithm")) {
      map.putString("encryptionKeyAlgorithm", overrides.getString("encryptionKeyAlgorithm"));
    }
    if (overrides.hasKey("hmacKeyAlgorithm")) {
      map.putString("hmacKeyAlgorithm", overrides.getString("hmacKeyAlgorithm"));
    }
    if (overrides.hasKey("cipherTransformation")) {
      map.putString("cipherTransformation", overrides.getString("cipherTransformation"));
    }
    if (overrides.hasKey("gcmTagLength")) {
      map.putInt("gcmTagLength", overrides.getInt("gcmTagLength"));
    }
    if (overrides.hasKey("gcmIvLength")) {
      map.putInt("gcmIvLength", overrides.getInt("gcmIvLength"));
    }
    return map;
  }

  private static String requireString(ReadableMap map, String key) {
    if (!map.hasKey(key) || map.getString(key) == null) {
      throw new IllegalArgumentException("Missing required crypto option: " + key);
    }
    String value = map.getString(key).trim();
    if (value.isEmpty()) {
      throw new IllegalArgumentException("Missing required crypto option: " + key);
    }
    return value;
  }

  private static int requireInt(ReadableMap map, String key) {
    if (!map.hasKey(key)) {
      throw new IllegalArgumentException("Missing required crypto option: " + key);
    }
    return map.getInt(key);
  }
}
