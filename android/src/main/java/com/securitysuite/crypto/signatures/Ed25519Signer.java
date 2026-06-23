package com.securitysuite.crypto.signatures;

import android.os.Build;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Ed25519 digital signatures.
 * Requires Android API 33 (Android 13) or higher.
 *
 * Key encoding: DER (PKCS#8 for private, X.509 SubjectPublicKeyInfo for public).
 * Signature: 64 bytes, raw binary.
 *
 * Cross-platform note: iOS CryptoKit Curve25519.Signing uses raw 32-byte key representations.
 * When exchanging keys across platforms, wrap/unwrap the raw bytes accordingly.
 */
public final class Ed25519Signer {
  private static final String ALGORITHM = "Ed25519";

  private Ed25519Signer() {}

  private static void requireApi33() {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
      throw new UnsupportedOperationException(
          "Ed25519 requires Android API 33 (Android 13) or higher"
      );
    }
  }

  public static KeyPair generateKeyPair() throws Exception {
    requireApi33();
    return KeyPairGenerator.getInstance(ALGORITHM).generateKeyPair();
  }

  /** Signs message bytes and returns the 64-byte raw signature. */
  public static byte[] sign(byte[] message, byte[] privateKeyDer) throws Exception {
    requireApi33();
    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDer));
    Signature signer = Signature.getInstance(ALGORITHM);
    signer.initSign(privateKey);
    signer.update(message);
    return signer.sign();
  }

  public static boolean verify(byte[] message, byte[] signatureBytes, byte[] publicKeyDer) throws Exception {
    requireApi33();
    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDer));
    Signature verifier = Signature.getInstance(ALGORITHM);
    verifier.initVerify(publicKey);
    verifier.update(message);
    return verifier.verify(signatureBytes);
  }

  public static byte[] exportPublicKeyDer(KeyPair keyPair) {
    return keyPair.getPublic().getEncoded();
  }

  public static byte[] exportPrivateKeyDer(KeyPair keyPair) {
    return keyPair.getPrivate().getEncoded();
  }
}
