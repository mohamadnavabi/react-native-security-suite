package com.securitysuite;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Persists the ECDH P-256 keypair in Android Keystore (non-exportable private key).
 */
public final class EcdhKeyStore {
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String KEY_ALIAS = "com.securitysuite.ecdh.p256";

  private EcdhKeyStore() {}

  public static KeyPair getOrCreateKeyPair(Context context) throws Exception {
    KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
    keyStore.load(null);

    if (keyStore.containsAlias(KEY_ALIAS)) {
      KeyStore.Entry entry = keyStore.getEntry(KEY_ALIAS, null);
      if (entry instanceof KeyStore.PrivateKeyEntry) {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) entry;
        return new KeyPair(privateKeyEntry.getCertificate().getPublicKey(), privateKeyEntry.getPrivateKey());
      }
    }

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        ANDROID_KEYSTORE
    );

    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
        KEY_ALIAS,
        KeyProperties.PURPOSE_AGREE_KEY
    )
        .setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .build();

    keyPairGenerator.initialize(spec);
    return keyPairGenerator.generateKeyPair();
  }

  public static String getPublicKeyBase64(Context context) throws Exception {
    PublicKey publicKey = getOrCreateKeyPair(context).getPublic();
    return Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
  }

  public static PrivateKey getPrivateKey(Context context) throws Exception {
    return getOrCreateKeyPair(context).getPrivate();
  }
}
