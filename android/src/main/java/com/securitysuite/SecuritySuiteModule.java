package com.securitysuite;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.module.annotations.ReactModule;

import androidx.annotation.NonNull;

import android.util.Base64;
import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import android.app.Activity;
import android.hardware.biometrics.BiometricManager;
import android.os.Build;
import android.view.WindowManager;

import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.scottyab.rootbeer.RootBeer;

import com.securitysuite.crypto.CryptoManager;
import com.securitysuite.security.AppIntegrityChecker;
import com.securitysuite.security.EmulatorDetector;
import com.securitysuite.security.RuntimeDetector;

@ReactModule(name = SecuritySuiteModule.NAME)
public class SecuritySuiteModule extends ReactContextBaseJavaModule {
  public static final String NAME = "SecuritySuite";
  private final ReactApplicationContext context;

  private SecretKey encryptionKey;
  private SecretKey hmacKey;
  private CryptoConfig cryptoConfig;
  private KeyPair legacyKeyPair;
  private boolean configuredLegacyV09Crypto;
  private boolean suiteConfigured;

  public SecuritySuiteModule(ReactApplicationContext reactContext) {
    super(reactContext);
    context = reactContext;
  }

  private boolean usesLegacyV09Crypto() {
    return configuredLegacyV09Crypto;
  }

  @ReactMethod
  public void configure(ReadableMap config, Promise promise) {
    try {
      if (config == null) {
        promise.reject("CONFIGURATION_ERROR", "Security suite configuration is required");
        return;
      }

      if (config.hasKey("legacyV09Crypto") && !config.isNull("legacyV09Crypto")) {
        configuredLegacyV09Crypto = config.getBoolean("legacyV09Crypto");
      }

      if (!configuredLegacyV09Crypto) {
        String salt = config.hasKey("hkdfSalt") ? config.getString("hkdfSalt") : null;
        String infoEncryption = config.hasKey("hkdfInfoEncryption")
            ? config.getString("hkdfInfoEncryption")
            : null;
        String infoHmac = config.hasKey("hkdfInfoHmac") ? config.getString("hkdfInfoHmac") : null;

        if (salt == null || salt.trim().isEmpty()
            || infoEncryption == null || infoEncryption.trim().isEmpty()
            || infoHmac == null || infoHmac.trim().isEmpty()) {
          promise.reject(
              "CONFIGURATION_ERROR",
              "hkdf.salt, hkdf.encryptionInfo, and hkdf.hmacInfo are required"
          );
          return;
        }

        CryptoUtils.setHkdfConfig(
            salt.getBytes(StandardCharsets.UTF_8),
            infoEncryption.getBytes(StandardCharsets.UTF_8),
            infoHmac.getBytes(StandardCharsets.UTF_8)
        );
      }

      suiteConfigured = true;
      promise.resolve(null);
    } catch (Exception e) {
      promise.reject("CONFIGURATION_ERROR", e.getMessage(), e);
    }
  }

  private void ensureConfigured() {
    if (!suiteConfigured) {
      throw new IllegalStateException(
          "Call SecuritySuite.initialize() before using security APIs."
      );
    }
  }

  private KeyPair createLegacyKeyPair(CryptoConfig config) throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(config.keyFactoryAlgorithm);
    keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
    return keyPairGenerator.generateKeyPair();
  }

  private byte[] legacySharedSecret(
      PrivateKey privateKey,
      PublicKey serverPublicKey,
      String keyAgreementAlgorithm
  ) throws Exception {
    KeyAgreement keyAgree = KeyAgreement.getInstance(keyAgreementAlgorithm);
    keyAgree.init(privateKey);
    keyAgree.doPhase(serverPublicKey, true);
    return keyAgree.generateSecret();
  }

  private byte[] legacyComputeAndStoreSharedKeys(String serverPK) throws Exception {
    if (serverPK == null || serverPK.trim().isEmpty()) {
      throw new IllegalArgumentException("Server public key is required");
    }
    if (legacyKeyPair == null) {
      throw new IllegalStateException("Call getPublicKey before getSharedKey");
    }
    PublicKey serverPublicKey = KeyFactory.getInstance(cryptoConfig.keyFactoryAlgorithm).generatePublic(
        new X509EncodedKeySpec(Base64.decode(serverPK.trim(), Base64.NO_WRAP))
    );
    byte[] sharedSecret = legacySharedSecret(legacyKeyPair.getPrivate(), serverPublicKey, cryptoConfig.keyAgreementAlgorithm);
    encryptionKey = new SecretKeySpec(sharedSecret, cryptoConfig.encryptionKeyAlgorithm);
    hmacKey = new SecretKeySpec(sharedSecret, cryptoConfig.hmacKeyAlgorithm);
    return sharedSecret;
  }

  private void legacyEstablishSharedKey(String serverPK, Promise promise) {
    try {
      legacyComputeAndStoreSharedKeys(serverPK);
      promise.resolve(null);
    } catch (Exception e) {
      Log.e("legacyEstablishSharedKey Error: ", String.valueOf(e));
      promise.reject("GET_SHARED_KEY_ERROR", e.getMessage(), e);
    }
  }

  private void legacyGetSharedKey(String serverPK, Promise promise) {
    try {
      byte[] sharedSecret = legacyComputeAndStoreSharedKeys(serverPK);
      promise.resolve(Base64.encodeToString(sharedSecret, Base64.NO_WRAP));
    } catch (Exception e) {
      Log.e("legacyGetSharedKey Error: ", String.valueOf(e));
      promise.reject("GET_SHARED_KEY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void getPublicKey(ReadableMap options, Promise promise) {
    try {
      ensureConfigured();
      if (usesLegacyV09Crypto()) {
        cryptoConfig = CryptoConfig.fromReadableMap(options);
        legacyKeyPair = createLegacyKeyPair(cryptoConfig);
        promise.resolve(
            Base64.encodeToString(legacyKeyPair.getPublic().getEncoded(), Base64.NO_WRAP)
        );
        return;
      }

      KeyAgreementProfile profile = KeyAgreementProfile.fromReadableMap(options);
      promise.resolve(KeyAgreementKeyStore.getPublicKeyBase64(context, profile));
    } catch (Exception e) {
      promise.reject("GET_PUBLIC_KEY_ERROR", e.getMessage(), e);
    }
  }

  /** Performs ECDH + HKDF and stores the derived keys. Returns the derived encryption key bytes. */
  private byte[] computeAndStoreSharedKeys(String serverPK, CryptoConfig config) throws Exception {
    if (serverPK == null || serverPK.trim().isEmpty()) {
      throw new IllegalArgumentException("Server public key is required");
    }
    KeyAgreementProfile profile = KeyAgreementProfile.fromCryptoConfig(config);
    byte[] serverKeyBytes = Base64.decode(serverPK.trim(), Base64.NO_WRAP);
    PublicKey serverPublicKey = KeyAgreementKeyStore.decodeServerPublicKey(serverKeyBytes, profile);
    PrivateKey privateKey = KeyAgreementKeyStore.getPrivateKey(context, profile);
    KeyAgreement keyAgree = KeyAgreement.getInstance(profile.keyAgreementAlgorithm);
    keyAgree.init(privateKey);
    keyAgree.doPhase(serverPublicKey, true);
    byte[] sharedSecret = keyAgree.generateSecret();
    byte[] encKeyBytes = CryptoUtils.deriveEncryptionKey(sharedSecret, config.hmacKeyAlgorithm);
    byte[] macKeyBytes = CryptoUtils.deriveHmacKey(sharedSecret, config.hmacKeyAlgorithm);
    encryptionKey = new SecretKeySpec(encKeyBytes, config.encryptionKeyAlgorithm);
    hmacKey = new SecretKeySpec(macKeyBytes, config.hmacKeyAlgorithm);
    return encKeyBytes;
  }

  @ReactMethod
  public void establishSharedKey(String serverPK, ReadableMap options, Promise promise) {
    try {
      ensureConfigured();
      cryptoConfig = CryptoConfig.fromReadableMap(options);
      if (usesLegacyV09Crypto()) {
        legacyEstablishSharedKey(serverPK, promise);
        return;
      }
      computeAndStoreSharedKeys(serverPK, cryptoConfig);
      promise.resolve(null);
    } catch (Exception e) {
      Log.e("establishSharedKey Error: ", String.valueOf(e));
      promise.reject("GET_SHARED_KEY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void getSharedKey(String serverPK, ReadableMap options, Promise promise) {
    try {
      ensureConfigured();
      cryptoConfig = CryptoConfig.fromReadableMap(options);
      if (usesLegacyV09Crypto()) {
        legacyGetSharedKey(serverPK, promise);
        return;
      }
      byte[] encKeyBytes = computeAndStoreSharedKeys(serverPK, cryptoConfig);
      promise.resolve(Base64.encodeToString(encKeyBytes, Base64.NO_WRAP));
    } catch (Exception e) {
      Log.e("getSharedKey Error: ", String.valueOf(e));
      promise.reject("GET_SHARED_KEY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void encrypt(String input, ReadableMap options, Promise promise) {
    try {
      ensureConfigured();
      if (encryptionKey == null) {
        promise.reject(
            "ENCRYPT_ERROR",
            "Encryption key not established. Call establishSharedKey or getSharedKey first."
        );
        return;
      }
      CryptoConfig config = resolveCryptoConfig(options);
      byte[] inputByte = input.getBytes(StandardCharsets.UTF_8);
      byte[] iv = CryptoUtils.randomBytes(config.gcmIvLength);
      GCMParameterSpec params = new GCMParameterSpec(config.gcmTagLength, iv);
      Cipher cipher = Cipher.getInstance(config.cipherTransformation);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, params);
      byte[] cipherText = cipher.doFinal(inputByte);
      byte[] output = new byte[iv.length + cipherText.length];
      System.arraycopy(iv, 0, output, 0, iv.length);
      System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
      promise.resolve(Base64.encodeToString(output, Base64.NO_WRAP));
    } catch (Exception e) {
      promise.reject("ENCRYPT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void decrypt(String input, ReadableMap options, Promise promise) {
    try {
      ensureConfigured();
      if (encryptionKey == null) {
        promise.reject(
            "DECRYPT_ERROR",
            "Encryption key not established. Call establishSharedKey or getSharedKey first."
        );
        return;
      }
      CryptoConfig config = resolveCryptoConfig(options);
      byte[] inputBytes = Base64.decode(input.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
      int minLength = config.gcmIvLength + (config.gcmTagLength / 8);
      if (inputBytes.length < minLength) {
        promise.reject("DECRYPT_ERROR", "Invalid ciphertext");
        return;
      }
      Cipher cipher = Cipher.getInstance(config.cipherTransformation);
      GCMParameterSpec params = new GCMParameterSpec(
          config.gcmTagLength,
          inputBytes,
          0,
          config.gcmIvLength
      );
      cipher.init(Cipher.DECRYPT_MODE, encryptionKey, params);
      byte[] plaintext = cipher.doFinal(
          inputBytes,
          config.gcmIvLength,
          inputBytes.length - config.gcmIvLength
      );
      promise.resolve(new String(plaintext, StandardCharsets.UTF_8));
    } catch (Exception e) {
      promise.reject("DECRYPT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void generateJWS(ReadableMap options, Promise promise) {
    try {
      if (options == null || !options.hasKey("secret")) {
        promise.reject("JWS_ERROR", "JWS secret is required and must be a non-empty string");
        return;
      }

      String secret = options.getString("secret");
      if (secret == null || secret.trim().isEmpty()) {
        promise.reject("JWS_ERROR", "JWS secret is required and must be a non-empty string");
        return;
      }

      String payload = "";
      if (options.hasKey("payload") && !options.isNull("payload")) {
        payload = options.getString("payload");
        if (payload == null) {
          payload = "";
        }
      }

      String algorithm = options.hasKey("algorithm") ? options.getString("algorithm") : null;
      if (algorithm == null || algorithm.trim().isEmpty()) {
        promise.reject("JWS_ERROR", "JWS algorithm is required");
        return;
      }
      ReadableMap headers = options.hasKey("headers") ? options.getMap("headers") : null;
      boolean detached = options.hasKey("detached") && options.getBoolean("detached");

      JWSGenerator generator = new JWSGenerator();
      String jws = generator.generate(payload, secret, algorithm, headers, detached);
      promise.resolve(jws);
    } catch (Exception e) {
      promise.reject("JWS_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void obfuscate(String input, String secret, Promise promise) {
    try {
      promise.resolve(Obfuscation.obfuscate(input, secret));
    } catch (Exception e) {
      promise.reject("OBFUSCATE_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void deobfuscate(String input, String secret, Promise promise) {
    try {
      promise.resolve(Obfuscation.deobfuscate(input, secret));
    } catch (Exception e) {
      promise.reject("DEOBFUSCATE_ERROR", e.getMessage(), e);
    }
  }

  /** @deprecated Use obfuscate() or SecureStorage instead. */
  @ReactMethod
  public void storageEncrypt(String input, String secretKey, Boolean hardEncryption, Promise promise) {
    try {
      if (secretKey == null || secretKey.trim().isEmpty()) {
        promise.reject(
            "ENCRYPT_ERROR",
            "secretKey is required. Device identifiers are not accepted as encryption keys."
        );
        return;
      }
      if (Boolean.TRUE.equals(hardEncryption)) {
        promise.reject(
            "ENCRYPT_ERROR",
            "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data."
        );
        return;
      }
      promise.resolve(Obfuscation.obfuscate(input, secretKey));
    } catch (Exception e) {
      promise.reject("ENCRYPT_ERROR", e.getMessage(), e);
    }
  }

  /** @deprecated Use deobfuscate() or SecureStorage APIs instead. */
  @ReactMethod
  public void storageDecrypt(String input, String secretKey, Boolean hardEncryption, Promise promise) {
    try {
      if (secretKey == null || secretKey.trim().isEmpty()) {
        promise.reject(
            "DECRYPT_ERROR",
            "secretKey is required. Device identifiers are not accepted as encryption keys."
        );
        return;
      }
      if (Boolean.TRUE.equals(hardEncryption)) {
        promise.reject(
            "DECRYPT_ERROR",
            "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data."
        );
        return;
      }
      promise.resolve(Obfuscation.deobfuscate(input, secretKey));
    } catch (Exception e) {
      promise.reject("DECRYPT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void secureStorageSetItem(String key, String value, Promise promise) {
    try {
      SecureStorageNative.setItem(context, key, value);
      promise.resolve(null);
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageGetItem(String key, Promise promise) {
    try {
      promise.resolve(SecureStorageNative.getItem(context, key));
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageRemoveItem(String key, Promise promise) {
    try {
      SecureStorageNative.removeItem(context, key);
      promise.resolve(null);
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageClear(Promise promise) {
    try {
      SecureStorageNative.clear(context);
      promise.resolve(null);
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageGetAllKeys(Promise promise) {
    try {
      promise.resolve(SecureStorageNative.getAllKeys(context));
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageMultiSet(ReadableArray pairs, Promise promise) {
    try {
      SecureStorageNative.multiSet(context, pairs);
      promise.resolve(null);
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageMultiGet(ReadableArray keys, Promise promise) {
    try {
      promise.resolve(SecureStorageNative.multiGet(context, keys));
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  @ReactMethod
  public void secureStorageMultiRemove(ReadableArray keys, Promise promise) {
    try {
      SecureStorageNative.multiRemove(context, keys);
      promise.resolve(null);
    } catch (Exception e) {
      promise.reject("SECURE_STORAGE_ERROR", secureStorageMessage(e), e);
    }
  }

  private CryptoConfig resolveCryptoConfig(ReadableMap options) {
    if (cryptoConfig != null) {
      return cryptoConfig.merge(options);
    }
    return CryptoConfig.fromReadableMap(options);
  }

  private static String secureStorageMessage(Exception error) {
    String message = error.getMessage();
    if (message != null && !message.isEmpty()) {
      return message;
    }
    return "Secure storage operation failed";
  }

  @ReactMethod
  public void fetch(String url, final ReadableMap options, Callback callback) {
    Sslpinning sslpinning = new Sslpinning(context);
    sslpinning.fetch(url, options, hmacKey, callback);
  }

  @ReactMethod
  public void getDeviceId(Callback callback) {
    try {
      callback.invoke(
          android.provider.Settings.Secure.getString(
              context.getContentResolver(),
              android.provider.Settings.Secure.ANDROID_ID
          ),
          null
      );
    } catch (Exception e) {
      callback.invoke(null, e.getMessage());
    }
  }

  @ReactMethod
  public void runtimeDetect(Promise promise) {
    try {
      promise.resolve(RuntimeDetector.detect());
    } catch (Exception e) {
      promise.reject("RUNTIME_DETECT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void appIntegrityVerify(Promise promise) {
    try {
      promise.resolve(AppIntegrityChecker.verify(context));
    } catch (Exception e) {
      promise.reject("APP_INTEGRITY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void deviceGetEnvironment(Promise promise) {
    try {
      promise.resolve(EmulatorDetector.detect(context));
    } catch (Exception e) {
      promise.reject("DEVICE_ENVIRONMENT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void deviceHasSecurityRisk(Promise promise) {
    RootBeer rootBeer = new RootBeer(context);
    promise.resolve(rootBeer.isRooted());
  }

  // ─── CryptoManager bridge ───────────────────────────────────────────────

  @ReactMethod
  public void cryptoHash(String input, String algorithm, Promise promise) {
    try {
      promise.resolve(CryptoManager.hash(input, algorithm));
    } catch (Exception e) {
      promise.reject("CRYPTO_HASH_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoDeriveKeys(ReadableMap params, Promise promise) {
    try {
      String sharedSecret = requireParam(params, "sharedSecret");
      String salt = requireParam(params, "salt");
      String encryptionInfo = requireParam(params, "encryptionInfo");
      String macInfo = requireParam(params, "macInfo");
      String hmacAlgorithm = requireParam(params, "hmacAlgorithm");
      promise.resolve(CryptoManager.deriveKeys(sharedSecret, salt, encryptionInfo, macInfo, hmacAlgorithm));
    } catch (Exception e) {
      promise.reject("CRYPTO_KDF_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoEncryptAesGcm(String plaintext, String key, Promise promise) {
    try {
      promise.resolve(CryptoManager.encryptAesGcm(plaintext, key));
    } catch (Exception e) {
      promise.reject("CRYPTO_ENCRYPT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoDecryptAesGcm(String ciphertext, String key, Promise promise) {
    try {
      promise.resolve(CryptoManager.decryptAesGcm(ciphertext, key));
    } catch (Exception e) {
      promise.reject("CRYPTO_DECRYPT_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoGetEcdhPublicKey(Promise promise) {
    try {
      promise.resolve(CryptoManager.getEcdhPublicKey(context));
    } catch (Exception e) {
      promise.reject("CRYPTO_KEY_EXCHANGE_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoEcdhComputeAndDeriveKeys(ReadableMap params, Promise promise) {
    try {
      String serverPublicKey = requireParam(params, "serverPublicKey");
      String salt = requireParam(params, "salt");
      String encryptionInfo = requireParam(params, "encryptionInfo");
      String macInfo = requireParam(params, "macInfo");
      String hmacAlgorithm = requireParam(params, "hmacAlgorithm");
      promise.resolve(CryptoManager.ecdhComputeAndDeriveKeys(
          context, serverPublicKey, salt, encryptionInfo, macInfo, hmacAlgorithm
      ));
    } catch (Exception e) {
      promise.reject("CRYPTO_KEY_EXCHANGE_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoGetX25519PublicKey(Promise promise) {
    try {
      promise.resolve(CryptoManager.getX25519PublicKey(context));
    } catch (Exception e) {
      promise.reject("CRYPTO_KEY_EXCHANGE_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoX25519ComputeAndDeriveKeys(ReadableMap params, Promise promise) {
    try {
      String serverPublicKey = requireParam(params, "serverPublicKey");
      String salt = requireParam(params, "salt");
      String encryptionInfo = requireParam(params, "encryptionInfo");
      String macInfo = requireParam(params, "macInfo");
      String hmacAlgorithm = requireParam(params, "hmacAlgorithm");
      promise.resolve(CryptoManager.x25519ComputeAndDeriveKeys(
          context, serverPublicKey, salt, encryptionInfo, macInfo, hmacAlgorithm
      ));
    } catch (Exception e) {
      promise.reject("CRYPTO_KEY_EXCHANGE_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoGenerateEd25519KeyPair(Promise promise) {
    try {
      promise.resolve(CryptoManager.generateEd25519KeyPair());
    } catch (Exception e) {
      promise.reject("CRYPTO_SIGN_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoSignEd25519(String message, String privateKey, Promise promise) {
    try {
      promise.resolve(CryptoManager.signEd25519(message, privateKey));
    } catch (Exception e) {
      promise.reject("CRYPTO_SIGN_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoVerifyEd25519(String message, String signature, String publicKey, Promise promise) {
    try {
      promise.resolve(CryptoManager.verifyEd25519(message, signature, publicKey));
    } catch (Exception e) {
      promise.reject("CRYPTO_VERIFY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoGenerateEcdsaKeyPair(Promise promise) {
    try {
      promise.resolve(CryptoManager.generateEcdsaKeyPair());
    } catch (Exception e) {
      promise.reject("CRYPTO_SIGN_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoSignEcdsa(String message, String privateKey, Promise promise) {
    try {
      promise.resolve(CryptoManager.signEcdsa(message, privateKey));
    } catch (Exception e) {
      promise.reject("CRYPTO_SIGN_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void cryptoVerifyEcdsa(String message, String signature, String publicKey, Promise promise) {
    try {
      promise.resolve(CryptoManager.verifyEcdsa(message, signature, publicKey));
    } catch (Exception e) {
      promise.reject("CRYPTO_VERIFY_ERROR", e.getMessage(), e);
    }
  }

  private static String requireParam(ReadableMap params, String key) {
    if (!params.hasKey(key) || params.isNull(key)) {
      throw new IllegalArgumentException("Missing required parameter: " + key);
    }
    String value = params.getString(key);
    if (value == null || value.trim().isEmpty()) {
      throw new IllegalArgumentException("Missing required parameter: " + key);
    }
    return value;
  }

  // ─── CSPRNG ─────────────────────────────────────────────────────────────────

  @ReactMethod
  public void cryptoRandomBytes(int count, Promise promise) {
    try {
      byte[] bytes = new byte[count];
      new java.security.SecureRandom().nextBytes(bytes);
      promise.resolve(android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP));
    } catch (Exception e) {
      promise.reject("CRYPTO_RANDOM_ERROR", e.getMessage(), e);
    }
  }

  // ─── Asymmetric JWS ─────────────────────────────────────────────────────────

  @ReactMethod
  public void generateAsymmetricJWS(ReadableMap options, Promise promise) {
    try {
      String privateKey = options.hasKey("privateKey") ? options.getString("privateKey") : null;
      if (privateKey == null || privateKey.trim().isEmpty()) {
        promise.reject("JWS_ERROR", "privateKey is required");
        return;
      }
      String algorithm = options.hasKey("algorithm") ? options.getString("algorithm") : null;
      if (algorithm == null || algorithm.isEmpty()) {
        promise.reject("JWS_ERROR", "algorithm is required");
        return;
      }
      String payload = "";
      if (options.hasKey("payload") && !options.isNull("payload")) {
        payload = options.getString("payload");
      }
      ReadableMap headers = options.hasKey("headers") ? options.getMap("headers") : null;
      boolean detached = options.hasKey("detached") && options.getBoolean("detached");

      JWSGenerator generator = new JWSGenerator();
      String jws = generator.generateAsymmetric(payload, privateKey, algorithm, headers, detached);
      promise.resolve(jws);
    } catch (Exception e) {
      promise.reject("JWS_ERROR", e.getMessage(), e);
    }
  }

  // ─── Biometric SecureStorage ─────────────────────────────────────────────────

  @ReactMethod
  public void secureStorageBiometricIsAvailable(Promise promise) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
      android.hardware.biometrics.BiometricManager bm =
          context.getSystemService(android.hardware.biometrics.BiometricManager.class);
      if (bm != null) {
        promise.resolve(
            bm.canAuthenticate(android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG)
                == android.hardware.biometrics.BiometricManager.BIOMETRIC_SUCCESS
        );
        return;
      }
    }
    promise.resolve(false);
  }

  @ReactMethod
  public void secureStorageSetItemBiometric(String key, String value, ReadableMap options, Promise promise) {
    String prompt = options != null && options.hasKey("prompt") ? options.getString("prompt") : "Authenticate to save";
    String subtitle = options != null && options.hasKey("subtitle") ? options.getString("subtitle") : "";
    Activity activity = getCurrentActivity();
    if (!(activity instanceof FragmentActivity)) {
      promise.reject("BIOMETRIC_UNAVAILABLE", "Biometric authentication requires a FragmentActivity");
      return;
    }
    activity.runOnUiThread(() -> {
      BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
          .setTitle(prompt)
          .setSubtitle(subtitle)
          .setNegativeButtonText("Cancel")
          .build();

      BiometricPrompt biometricPrompt = new BiometricPrompt(
          (FragmentActivity) activity,
          ContextCompat.getMainExecutor(context),
          new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
              try {
                SecureStorageNative.setItem(context, key, value);
                promise.resolve(null);
              } catch (Exception e) {
                promise.reject("SECURE_STORAGE_ERROR", e.getMessage(), e);
              }
            }
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
              promise.reject("BIOMETRIC_AUTH_FAILED", errString.toString());
            }
            @Override
            public void onAuthenticationFailed() {
              promise.reject("BIOMETRIC_AUTH_FAILED", "Biometric authentication failed");
            }
          }
      );
      biometricPrompt.authenticate(promptInfo);
    });
  }

  @ReactMethod
  public void secureStorageGetItemBiometric(String key, ReadableMap options, Promise promise) {
    String prompt = options != null && options.hasKey("prompt") ? options.getString("prompt") : "Authenticate to read";
    String subtitle = options != null && options.hasKey("subtitle") ? options.getString("subtitle") : "";
    Activity activity = getCurrentActivity();
    if (!(activity instanceof FragmentActivity)) {
      promise.reject("BIOMETRIC_UNAVAILABLE", "Biometric authentication requires a FragmentActivity");
      return;
    }
    activity.runOnUiThread(() -> {
      BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
          .setTitle(prompt)
          .setSubtitle(subtitle)
          .setNegativeButtonText("Cancel")
          .build();

      BiometricPrompt biometricPrompt = new BiometricPrompt(
          (FragmentActivity) activity,
          ContextCompat.getMainExecutor(context),
          new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
              try {
                promise.resolve(SecureStorageNative.getItem(context, key));
              } catch (Exception e) {
                promise.reject("SECURE_STORAGE_ERROR", e.getMessage(), e);
              }
            }
            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
              promise.reject("BIOMETRIC_AUTH_FAILED", errString.toString());
            }
            @Override
            public void onAuthenticationFailed() {
              promise.reject("BIOMETRIC_AUTH_FAILED", "Biometric authentication failed");
            }
          }
      );
      biometricPrompt.authenticate(promptInfo);
    });
  }

  // ─── Background / window security ─────────────────────────────────────────────

  @ReactMethod
  public void screenSetWindowSecure(boolean enabled, Promise promise) {
    Activity activity = getCurrentActivity();
    if (activity == null) {
      promise.resolve(null);
      return;
    }
    activity.runOnUiThread(() -> {
      if (enabled) {
        activity.getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
      } else {
        activity.getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
      }
      promise.resolve(null);
    });
  }

  // ─── Device Attestation (Play Integrity stub) ─────────────────────────────────

  @ReactMethod
  public void deviceAttestationIsSupported(Promise promise) {
    // Play Integrity availability check would require Google Play Services.
    // Return true only if Google Play Services is available.
    try {
      com.google.android.gms.common.GoogleApiAvailability api =
          com.google.android.gms.common.GoogleApiAvailability.getInstance();
      int result = api.isGooglePlayServicesAvailable(context);
      promise.resolve(result == com.google.android.gms.common.ConnectionResult.SUCCESS);
    } catch (Throwable t) {
      promise.resolve(false);
    }
  }

  @ReactMethod
  public void deviceAttestationGenerateKey(Promise promise) {
    // On Android, Play Integrity uses a nonce-only flow — no persistent key generation needed.
    promise.resolve("");
  }

  @ReactMethod
  public void deviceAttestationAttestKey(String keyId, String clientDataHash, Promise promise) {
    promise.reject("ATTESTATION_UNSUPPORTED", "Use getPlayIntegrityToken on Android");
  }

  @ReactMethod
  public void deviceAttestationGenerateAssertion(String keyId, String clientDataHash, Promise promise) {
    promise.reject("ATTESTATION_UNSUPPORTED", "Use getPlayIntegrityToken on Android");
  }

  @ReactMethod
  public void deviceAttestationGetPlayIntegrityToken(String nonce, Promise promise) {
    try {
      com.google.android.play.core.integrity.IntegrityManagerFactory
          .create(context)
          .requestIntegrityToken(
              com.google.android.play.core.integrity.IntegrityTokenRequest.builder()
                  .setNonce(nonce)
                  .build()
          )
          .addOnSuccessListener(response -> promise.resolve(response.token()))
          .addOnFailureListener(e -> promise.reject("ATTESTATION_ERROR", e.getMessage(), e));
    } catch (Throwable t) {
      promise.reject("ATTESTATION_ERROR", "Play Integrity API unavailable: " + t.getMessage(), t);
    }
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }
}
