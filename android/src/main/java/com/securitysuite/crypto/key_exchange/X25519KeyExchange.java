package com.securitysuite.crypto.key_exchange;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.securitysuite.crypto.utils.Base64Utils;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

/**
 * X25519 key exchange backed by Android Keystore.
 * Requires Android API 31 (Android 12) or higher.
 *
 * Public key I/O uses 32-byte raw representation for cross-platform compatibility with iOS CryptoKit.
 */
public final class X25519KeyExchange {
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String KEY_ALIAS = "com.securitysuite.crypto.x25519";

  private static final byte[] SPKI_PREFIX = {
      0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00
  };

  private X25519KeyExchange() {}

  private static void requireApi31() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) {
      throw new UnsupportedOperationException("X25519 requires Android API 31 (Android 12) or higher");
    }
  }

  public static KeyPair getOrCreateKeyPair(Context context) throws Exception {
    requireApi31();
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);

    if (keyStore.containsAlias(KEY_ALIAS)) {
      KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
      if (entry instanceof KeyStore.PrivateKeyEntry) {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        return new KeyPair(
            privateKeyEntry.getCertificate().getPublicKey(),
            privateKeyEntry.getPrivateKey()
        );
      }
      keyStore.deleteEntry(KEY_ALIAS);
    }

    KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH", ANDROID_KEYSTORE);
    generator.initialize(
        new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_AGREE_KEY).build()
    );
    return generator.generateKeyPair();
  }

  /** Returns the raw 32-byte public key, Base64-encoded, matching iOS rawRepresentation. */
  public static String getPublicKeyBase64(Context context) throws Exception {
    byte[] spki = getOrCreateKeyPair(context).getPublic().getEncoded();
    return Base64Utils.encode(extractRaw32(spki));
  }

  /**
   * Performs X25519 agreement and returns the raw shared secret bytes.
   * Input may be raw 32 bytes or SPKI-wrapped — both are normalized automatically.
   */
  public static byte[] computeSharedSecret(Context context, byte[] serverPublicKeyRaw) throws Exception {
    requireApi31();
    PrivateKey privateKey = getOrCreateKeyPair(context).getPrivate();
    byte[] rawKey = normalizeToRaw32(serverPublicKeyRaw);
    KeyFactory keyFactory = KeyFactory.getInstance("XDH");
    PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(wrapSpki(rawKey)));
    KeyAgreement agreement = KeyAgreement.getInstance("XDH");
    agreement.init(privateKey);
    agreement.doPhase(serverPublicKey, true);
    return agreement.generateSecret();
  }

  static byte[] normalizeToRaw32(byte[] encoded) {
    if (encoded.length == 32) {
      return encoded;
    }
    if (encoded.length > 32) {
      byte[] raw = new byte[32];
      System.arraycopy(encoded, encoded.length - 32, raw, 0, 32);
      return raw;
    }
    throw new IllegalArgumentException(
        "Invalid X25519 public key: expected at least 32 bytes, got " + encoded.length
    );
  }

  static byte[] extractRaw32(byte[] spki) {
    return normalizeToRaw32(spki);
  }

  private static byte[] wrapSpki(byte[] rawKey) {
    byte[] spki = new byte[SPKI_PREFIX.length + rawKey.length];
    System.arraycopy(SPKI_PREFIX, 0, spki, 0, SPKI_PREFIX.length);
    System.arraycopy(rawKey, 0, spki, SPKI_PREFIX.length, rawKey.length);
    return spki;
  }
}
