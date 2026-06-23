package com.securitysuite.crypto.key_exchange;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import com.securitysuite.crypto.utils.Base64Utils;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

/**
 * ECDH P-256 key exchange backed by Android Keystore.
 * The private key is non-exportable and hardware-bound when available.
 */
public final class EcdhKeyExchange {
  private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
  private static final String KEY_ALIAS = "com.securitysuite.crypto.ecdh.p256";
  private static final String EC_CURVE = "secp256r1";

  private EcdhKeyExchange() {}

  public static KeyPair getOrCreateKeyPair(Context context) throws Exception {
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

    KeyPairGenerator generator = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE
    );
    generator.initialize(
        new KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
            .setAlgorithmParameterSpec(new ECGenParameterSpec(EC_CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .build()
    );
    return generator.generateKeyPair();
  }

  public static String getPublicKeyBase64(Context context) throws Exception {
    PublicKey pk = getOrCreateKeyPair(context).getPublic();
    return Base64Utils.encode(pk.getEncoded());
  }

  /**
   * Performs ECDH key agreement and returns the raw shared secret bytes.
   * Caller must derive actual keys from this secret via HKDF — never use directly.
   */
  public static byte[] computeSharedSecret(Context context, byte[] serverPublicKeyDer) throws Exception {
    PrivateKey privateKey = getOrCreateKeyPair(context).getPrivate();
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PublicKey serverPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(serverPublicKeyDer));
    KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
    agreement.init(privateKey);
    agreement.doPhase(serverPublicKey, true);
    return agreement.generateSecret();
  }

  public static String keyAlias() {
    return KEY_ALIAS;
  }
}
