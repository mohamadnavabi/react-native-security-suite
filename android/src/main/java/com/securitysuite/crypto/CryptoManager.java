package com.securitysuite.crypto;

import android.content.Context;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.WritableMap;
import com.securitysuite.crypto.encryption.AesGcmEncryption;
import com.securitysuite.crypto.hashing.HashUtils;
import com.securitysuite.crypto.kdf.HkdfDerivation;
import com.securitysuite.crypto.key_exchange.EcdhKeyExchange;
import com.securitysuite.crypto.key_exchange.X25519KeyExchange;
import com.securitysuite.crypto.signatures.EcdsaSigner;
import com.securitysuite.crypto.signatures.Ed25519Signer;
import com.securitysuite.crypto.utils.Base64Utils;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;

/**
 * Central high-level cryptography API exposed to the React Native bridge.
 *
 * All binary inputs and outputs are Base64-encoded strings.
 * Text inputs (message, plaintext) are UTF-8 strings.
 */
public final class CryptoManager {
  private CryptoManager() {}

  // ─── Hashing ──────────────────────────────────────────────────────────────

  /** Hashes a UTF-8 string and returns the Base64-encoded digest. */
  public static String hash(String input, String algorithm) throws Exception {
    byte[] digest = HashUtils.hash(input.getBytes(StandardCharsets.UTF_8), algorithm);
    return Base64Utils.encode(digest);
  }

  // ─── HKDF ─────────────────────────────────────────────────────────────────

  /** Derives encryptionKey and macKey from a Base64-encoded shared secret. */
  public static WritableMap deriveKeys(
      String sharedSecretBase64,
      String saltBase64,
      String encryptionInfoBase64,
      String macInfoBase64,
      String hmacAlgorithm
  ) throws Exception {
    HkdfDerivation.DerivedKeys keys = HkdfDerivation.deriveKeys(
        Base64Utils.decode(sharedSecretBase64),
        Base64Utils.decode(saltBase64),
        Base64Utils.decode(encryptionInfoBase64),
        Base64Utils.decode(macInfoBase64),
        32,
        hmacAlgorithm
    );
    WritableMap result = Arguments.createMap();
    result.putString("encryptionKey", Base64Utils.encode(keys.encryptionKey));
    result.putString("macKey", Base64Utils.encode(keys.macKey));
    return result;
  }

  // ─── AES-256-GCM ──────────────────────────────────────────────────────────

  /**
   * Encrypts a UTF-8 plaintext string with an AES-256 key (Base64).
   * Returns Base64-encoded IV || ciphertext || authTag.
   */
  public static String encryptAesGcm(String plaintext, String keyBase64) throws Exception {
    byte[] ciphertext = AesGcmEncryption.encrypt(
        plaintext.getBytes(StandardCharsets.UTF_8),
        Base64Utils.decode(keyBase64)
    );
    return Base64Utils.encode(ciphertext);
  }

  /** Decrypts Base64-encoded IV || ciphertext || authTag with an AES-256 key (Base64). */
  public static String decryptAesGcm(String ciphertextBase64, String keyBase64) throws Exception {
    byte[] plaintext = AesGcmEncryption.decrypt(
        Base64Utils.decode(ciphertextBase64),
        Base64Utils.decode(keyBase64)
    );
    return new String(plaintext, StandardCharsets.UTF_8);
  }

  // ─── ECDH P-256 ───────────────────────────────────────────────────────────

  public static String getEcdhPublicKey(Context context) throws Exception {
    return EcdhKeyExchange.getPublicKeyBase64(context);
  }

  public static WritableMap ecdhComputeAndDeriveKeys(
      Context context,
      String serverPublicKeyBase64,
      String saltBase64,
      String encryptionInfoBase64,
      String macInfoBase64,
      String hmacAlgorithm
  ) throws Exception {
    byte[] sharedSecret = EcdhKeyExchange.computeSharedSecret(
        context, Base64Utils.decode(serverPublicKeyBase64)
    );
    HkdfDerivation.DerivedKeys keys = HkdfDerivation.deriveKeys(
        sharedSecret,
        Base64Utils.decode(saltBase64),
        Base64Utils.decode(encryptionInfoBase64),
        Base64Utils.decode(macInfoBase64),
        32,
        hmacAlgorithm
    );
    WritableMap result = Arguments.createMap();
    result.putString("encryptionKey", Base64Utils.encode(keys.encryptionKey));
    result.putString("macKey", Base64Utils.encode(keys.macKey));
    return result;
  }

  // ─── ECDH key rotation / deletion ─────────────────────────────────────────

  public static String rotateEcdhKeyPair(Context context) throws Exception {
    EcdhKeyExchange.deleteKeyPair(context);
    return EcdhKeyExchange.getPublicKeyBase64(context);
  }

  public static void deleteEcdhKeyPair(Context context) throws Exception {
    EcdhKeyExchange.deleteKeyPair(context);
  }

  // ─── ECDH ephemeral ───────────────────────────────────────────────────────

  public static WritableMap ecdhEphemeralComputeAndDeriveKeys(
      Context context,
      String serverPublicKeyBase64,
      String saltBase64,
      String encryptionInfoBase64,
      String macInfoBase64,
      String hmacAlgorithm
  ) throws Exception {
    java.util.Map<String, byte[]> ephemeral = EcdhKeyExchange.generateEphemeralAndComputeSharedSecret(
        Base64Utils.decode(serverPublicKeyBase64)
    );
    HkdfDerivation.DerivedKeys keys = HkdfDerivation.deriveKeys(
        ephemeral.get("sharedSecret"),
        Base64Utils.decode(saltBase64),
        Base64Utils.decode(encryptionInfoBase64),
        Base64Utils.decode(macInfoBase64),
        32,
        hmacAlgorithm
    );
    WritableMap result = Arguments.createMap();
    result.putString("devicePublicKey", Base64Utils.encode(ephemeral.get("publicKey")));
    result.putString("encryptionKey", Base64Utils.encode(keys.encryptionKey));
    result.putString("macKey", Base64Utils.encode(keys.macKey));
    return result;
  }

  // ─── X25519 ───────────────────────────────────────────────────────────────

  public static String getX25519PublicKey(Context context) throws Exception {
    return X25519KeyExchange.getPublicKeyBase64(context);
  }

  public static WritableMap x25519ComputeAndDeriveKeys(
      Context context,
      String serverPublicKeyBase64,
      String saltBase64,
      String encryptionInfoBase64,
      String macInfoBase64,
      String hmacAlgorithm
  ) throws Exception {
    byte[] sharedSecret = X25519KeyExchange.computeSharedSecret(
        context, Base64Utils.decode(serverPublicKeyBase64)
    );
    HkdfDerivation.DerivedKeys keys = HkdfDerivation.deriveKeys(
        sharedSecret,
        Base64Utils.decode(saltBase64),
        Base64Utils.decode(encryptionInfoBase64),
        Base64Utils.decode(macInfoBase64),
        32,
        hmacAlgorithm
    );
    WritableMap result = Arguments.createMap();
    result.putString("encryptionKey", Base64Utils.encode(keys.encryptionKey));
    result.putString("macKey", Base64Utils.encode(keys.macKey));
    return result;
  }

  // ─── X25519 key rotation / deletion ───────────────────────────────────────

  public static String rotateX25519KeyPair(Context context) throws Exception {
    X25519KeyExchange.deleteKeyPair(context);
    return X25519KeyExchange.getPublicKeyBase64(context);
  }

  public static void deleteX25519KeyPair(Context context) throws Exception {
    X25519KeyExchange.deleteKeyPair(context);
  }

  // ─── X25519 ephemeral ─────────────────────────────────────────────────────

  public static WritableMap x25519EphemeralComputeAndDeriveKeys(
      Context context,
      String serverPublicKeyBase64,
      String saltBase64,
      String encryptionInfoBase64,
      String macInfoBase64,
      String hmacAlgorithm
  ) throws Exception {
    java.util.Map<String, byte[]> ephemeral = X25519KeyExchange.generateEphemeralAndComputeSharedSecret(
        Base64Utils.decode(serverPublicKeyBase64)
    );
    HkdfDerivation.DerivedKeys keys = HkdfDerivation.deriveKeys(
        ephemeral.get("sharedSecret"),
        Base64Utils.decode(saltBase64),
        Base64Utils.decode(encryptionInfoBase64),
        Base64Utils.decode(macInfoBase64),
        32,
        hmacAlgorithm
    );
    WritableMap result = Arguments.createMap();
    result.putString("devicePublicKey", Base64Utils.encode(ephemeral.get("publicKey")));
    result.putString("encryptionKey", Base64Utils.encode(keys.encryptionKey));
    result.putString("macKey", Base64Utils.encode(keys.macKey));
    return result;
  }

  // ─── Ed25519 ──────────────────────────────────────────────────────────────

  public static WritableMap generateEd25519KeyPair() throws Exception {
    KeyPair keyPair = Ed25519Signer.generateKeyPair();
    WritableMap result = Arguments.createMap();
    result.putString("publicKey", Base64Utils.encode(Ed25519Signer.exportPublicKeyDer(keyPair)));
    result.putString("privateKey", Base64Utils.encode(Ed25519Signer.exportPrivateKeyDer(keyPair)));
    return result;
  }

  /** Signs a UTF-8 message and returns the Base64-encoded 64-byte signature. */
  public static String signEd25519(String message, String privateKeyBase64) throws Exception {
    byte[] signature = Ed25519Signer.sign(
        message.getBytes(StandardCharsets.UTF_8),
        Base64Utils.decode(privateKeyBase64)
    );
    return Base64Utils.encode(signature);
  }

  public static boolean verifyEd25519(
      String message,
      String signatureBase64,
      String publicKeyBase64
  ) throws Exception {
    return Ed25519Signer.verify(
        message.getBytes(StandardCharsets.UTF_8),
        Base64Utils.decode(signatureBase64),
        Base64Utils.decode(publicKeyBase64)
    );
  }

  // ─── ECDSA P-256 ──────────────────────────────────────────────────────────

  public static WritableMap generateEcdsaKeyPair() throws Exception {
    KeyPair keyPair = EcdsaSigner.generateKeyPair();
    WritableMap result = Arguments.createMap();
    result.putString("publicKey", Base64Utils.encode(EcdsaSigner.exportPublicKeyDer(keyPair)));
    result.putString("privateKey", Base64Utils.encode(EcdsaSigner.exportPrivateKeyDer(keyPair)));
    return result;
  }

  /** Signs a UTF-8 message and returns the Base64-encoded DER-encoded ECDSA signature. */
  public static String signEcdsa(String message, String privateKeyBase64) throws Exception {
    byte[] signature = EcdsaSigner.sign(
        message.getBytes(StandardCharsets.UTF_8),
        Base64Utils.decode(privateKeyBase64)
    );
    return Base64Utils.encode(signature);
  }

  public static boolean verifyEcdsa(
      String message,
      String signatureBase64,
      String publicKeyBase64
  ) throws Exception {
    return EcdsaSigner.verify(
        message.getBytes(StandardCharsets.UTF_8),
        Base64Utils.decode(signatureBase64),
        Base64Utils.decode(publicKeyBase64)
    );
  }
}
