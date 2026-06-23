package com.securitysuite;

import com.facebook.react.bridge.ReadableMap;

/**
 * Resolved key-agreement profile used for key storage and agreement.
 */
public final class KeyAgreementProfile {
  public enum Kind {
    P256_ECDH,
    X25519
  }

  public final Kind kind;
  public final String alias;
  public final String keyAgreementAlgorithm;
  public final String keyFactoryAlgorithm;

  private KeyAgreementProfile(
      Kind kind,
      String alias,
      String keyAgreementAlgorithm,
      String keyFactoryAlgorithm
  ) {
    this.kind = kind;
    this.alias = alias;
    this.keyAgreementAlgorithm = keyAgreementAlgorithm;
    this.keyFactoryAlgorithm = keyFactoryAlgorithm;
  }

  public static KeyAgreementProfile fromReadableMap(ReadableMap options) {
    if (options == null) {
      throw new IllegalArgumentException(
          "Crypto options are required. Call SecuritySuite.initialize() before crypto APIs."
      );
    }

    String keyAgreementAlgorithm = requireString(options, "keyAgreementAlgorithm");
    String keyFactoryAlgorithm = normalizeKeyFactoryAlgorithm(
        requireString(options, "keyFactoryAlgorithm")
    );

    switch (keyFactoryAlgorithm.toUpperCase() + "/" + keyAgreementAlgorithm.toUpperCase()) {
      case "EC/ECDH":
        return new KeyAgreementProfile(
            Kind.P256_ECDH,
            KeyAgreementKeyStore.legacyEcdhAlias(),
            keyAgreementAlgorithm,
            keyFactoryAlgorithm
        );
      case "OKP/X25519":
        return new KeyAgreementProfile(
            Kind.X25519,
            "com.securitysuite.x25519",
            keyAgreementAlgorithm,
            keyFactoryAlgorithm
        );
      default:
        throw new IllegalArgumentException(
            "Unsupported key profile: "
                + keyFactoryAlgorithm
                + "/"
                + keyAgreementAlgorithm
                + ". Supported profiles: EC/ECDH (P-256) and OKP/X25519."
        );
    }
  }

  public static KeyAgreementProfile fromCryptoConfig(CryptoConfig config) {
    com.facebook.react.bridge.WritableMap map = com.facebook.react.bridge.Arguments.createMap();
    map.putString("keyAgreementAlgorithm", config.keyAgreementAlgorithm);
    map.putString("keyFactoryAlgorithm", config.keyFactoryAlgorithm);
    return fromReadableMap(map);
  }

  private static String normalizeKeyFactoryAlgorithm(String value) {
    if ("Curve25519".equals(value) || "X25519".equals(value)) {
      return "OKP";
    }
    return value;
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
}
