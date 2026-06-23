package com.securitysuite;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Persists key-agreement key pairs in Android Keystore.
 * Supports P-256 ECDH (API 23+) and X25519 (API 31+).
 */
public final class KeyAgreementKeyStore {
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String LEGACY_ECDH_ALIAS = "com.securitysuite.ecdh.p256";
  private static final String X25519_ALIAS = "com.securitysuite.x25519";

  private KeyAgreementKeyStore() {}

  public static KeyPair getOrCreateKeyPair(Context context, KeyAgreementProfile profile) throws Exception {
    switch (profile.kind) {
      case P256_ECDH:
        return getOrCreateP256KeyPair(context, profile.alias);
      case X25519:
        return getOrCreateX25519KeyPair(context, profile.alias);
      default:
        throw new IllegalArgumentException("Unsupported key profile");
    }
  }

  public static String getPublicKeyBase64(Context context, KeyAgreementProfile profile) throws Exception {
    PublicKey publicKey = getOrCreateKeyPair(context, profile).getPublic();
    if (profile.kind == KeyAgreementProfile.Kind.X25519) {
      return Base64.encodeToString(extractX25519RawPublicKey(publicKey.getEncoded()), Base64.NO_WRAP);
    }
    return Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
  }

  public static PrivateKey getPrivateKey(Context context, KeyAgreementProfile profile) throws Exception {
    return getOrCreateKeyPair(context, profile).getPrivate();
  }

  public static PublicKey decodeServerPublicKey(byte[] encoded, KeyAgreementProfile profile) throws Exception {
    if (profile.kind == KeyAgreementProfile.Kind.X25519) {
      byte[] rawKey = normalizeX25519PublicKey(encoded);
      if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
        throw new IllegalStateException("X25519 requires Android API 31+");
      }
      KeyFactory keyFactory = KeyFactory.getInstance("XDH");
      return keyFactory.generatePublic(new X509EncodedKeySpec(wrapX25519Spki(rawKey)));
    }

    KeyFactory keyFactory = KeyFactory.getInstance(profile.keyFactoryAlgorithm);
    return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
  }

  private static KeyPair getOrCreateP256KeyPair(Context context, String alias) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);

    if (keyStore.containsAlias(alias)) {
      KeyStore.Entry entry = keyStore.getEntry(alias, null);
      if (entry instanceof KeyStore.PrivateKeyEntry) {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        return new KeyPair(
            privateKeyEntry.getCertificate().getPublicKey(),
            privateKeyEntry.getPrivateKey()
        );
      }
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        ANDROID_KEYSTORE
    );

    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_AGREE_KEY
    )
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build();

    keyPairGenerator.initialize(spec);
    return keyPairGenerator.generateKeyPair();
  }

  private static KeyPair getOrCreateX25519KeyPair(Context context, String alias) throws Exception {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
      throw new IllegalStateException("X25519 requires Android API 31+");
    }

    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);

    if (keyStore.containsAlias(alias)) {
      KeyStore.Entry entry = keyStore.getEntry(alias, null);
      if (entry instanceof KeyStore.PrivateKeyEntry) {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        return new KeyPair(
            privateKeyEntry.getCertificate().getPublicKey(),
            privateKeyEntry.getPrivateKey()
        );
      }
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
        "XDH",
        ANDROID_KEYSTORE
    );

    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_AGREE_KEY
    ).build();

    keyPairGenerator.initialize(spec);
    return keyPairGenerator.generateKeyPair();
  }

  static String legacyEcdhAlias() {
    return LEGACY_ECDH_ALIAS;
  }

  static byte[] normalizeX25519PublicKey(byte[] encoded) {
    if (encoded.length == 32) {
      return encoded;
    }
    if (encoded.length >= 32) {
      byte[] raw = new byte[32];
      System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
      return raw;
    }
    throw new IllegalArgumentException("Invalid X25519 public key length");
  }

  private static byte[] extractX25519RawPublicKey(byte[] spki) {
    return normalizeX25519PublicKey(spki);
  }

  private static byte[] wrapX25519Spki(byte[] rawKey) {
    byte[] prefix = new byte[] {
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E,
        0x03, 0x21, 0x00
    };
    byte[] spki = new byte[prefix.length + rawKey.length];
    System.arraycopy(prefix, 0, spki, 0, prefix.length);
    System.arraycopy(rawKey, 0, spki, prefix.length, rawKey.length);
    return spki;
  }
}
