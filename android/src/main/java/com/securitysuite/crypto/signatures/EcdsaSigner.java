package com.securitysuite.crypto.signatures;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * ECDSA P-256 digital signatures (SHA-256 digest).
 *
 * Key encoding: DER (PKCS#8 for private, X.509 SubjectPublicKeyInfo for public).
 * Signature: DER-encoded ASN.1 SEQUENCE, matching iOS P256.Signing.ECDSASignature.derRepresentation.
 */
public final class EcdsaSigner {
  private static final String ALGORITHM = "SHA256withECDSA";
  private static final String EC_CURVE = "secp256r1";

  private EcdsaSigner() {}

  public static KeyPair generateKeyPair() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec(EC_CURVE));
    return generator.generateKeyPair();
  }

  /** Signs message bytes using SHA-256 / ECDSA P-256 and returns a DER-encoded signature. */
  public static byte[] sign(byte[] message, byte[] privateKeyDer) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDer));
    Signature signer = Signature.getInstance(ALGORITHM);
    signer.initSign(privateKey);
    signer.update(message);
    return signer.sign();
  }

  public static boolean verify(byte[] message, byte[] signatureDer, byte[] publicKeyDer) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("EC");
    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDer));
    Signature verifier = Signature.getInstance(ALGORITHM);
    verifier.initVerify(publicKey);
    verifier.update(message);
    return verifier.verify(signatureDer);
  }

  public static byte[] exportPublicKeyDer(KeyPair keyPair) {
    return keyPair.getPublic().getEncoded();
  }

  public static byte[] exportPrivateKeyDer(KeyPair keyPair) {
    return keyPair.getPrivate().getEncoded();
  }
}
