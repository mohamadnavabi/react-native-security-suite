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

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.scottyab.rootbeer.RootBeer;

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

  public SecuritySuiteModule(ReactApplicationContext reactContext) {
    super(reactContext);
    context = reactContext;
  }

  @ReactMethod
  public void getPublicKey(Promise promise) {
    try {
      promise.resolve(EcdhKeyStore.getPublicKeyBase64(context));
    } catch (Exception e) {
      promise.reject("GET_PUBLIC_KEY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void establishSharedKey(String serverPK, ReadableMap options, Promise promise) {
    try {
      if (serverPK == null || serverPK.trim().isEmpty()) {
        promise.reject("GET_SHARED_KEY_ERROR", "Server public key is required");
        return;
      }

      cryptoConfig = CryptoConfig.fromReadableMap(options);

      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
          Base64.decode(serverPK.trim(), Base64.NO_WRAP)
      );
      KeyFactory keyFactory = KeyFactory.getInstance(cryptoConfig.keyFactoryAlgorithm);
      PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);
      PrivateKey privateKey = EcdhKeyStore.getPrivateKey(context);

      KeyAgreement keyAgree = KeyAgreement.getInstance(cryptoConfig.keyAgreementAlgorithm);
      keyAgree.init(privateKey);
      keyAgree.doPhase(serverPublicKey, true);
      byte[] sharedSecret = keyAgree.generateSecret();

      byte[] encKeyBytes = CryptoUtils.deriveEncryptionKey(sharedSecret, cryptoConfig.hmacKeyAlgorithm);
      byte[] macKeyBytes = CryptoUtils.deriveHmacKey(sharedSecret, cryptoConfig.hmacKeyAlgorithm);
      encryptionKey = new SecretKeySpec(encKeyBytes, cryptoConfig.encryptionKeyAlgorithm);
      hmacKey = new SecretKeySpec(macKeyBytes, cryptoConfig.hmacKeyAlgorithm);

      promise.resolve(null);
    } catch (Exception e) {
      Log.e("establishSharedKey Error: ", String.valueOf(e));
      promise.reject("GET_SHARED_KEY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void getSharedKey(String serverPK, ReadableMap options, Promise promise) {
    try {
      if (serverPK == null || serverPK.trim().isEmpty()) {
        promise.reject("GET_SHARED_KEY_ERROR", "Server public key is required");
        return;
      }

      cryptoConfig = CryptoConfig.fromReadableMap(options);

      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
          Base64.decode(serverPK.trim(), Base64.NO_WRAP)
      );
      KeyFactory keyFactory = KeyFactory.getInstance(cryptoConfig.keyFactoryAlgorithm);
      PublicKey serverPublicKey = keyFactory.generatePublic(keySpec);
      PrivateKey privateKey = EcdhKeyStore.getPrivateKey(context);

      KeyAgreement keyAgree = KeyAgreement.getInstance(cryptoConfig.keyAgreementAlgorithm);
      keyAgree.init(privateKey);
      keyAgree.doPhase(serverPublicKey, true);
      byte[] sharedSecret = keyAgree.generateSecret();

      byte[] encKeyBytes = CryptoUtils.deriveEncryptionKey(sharedSecret, cryptoConfig.hmacKeyAlgorithm);
      byte[] macKeyBytes = CryptoUtils.deriveHmacKey(sharedSecret, cryptoConfig.hmacKeyAlgorithm);
      encryptionKey = new SecretKeySpec(encKeyBytes, cryptoConfig.encryptionKeyAlgorithm);
      hmacKey = new SecretKeySpec(macKeyBytes, cryptoConfig.hmacKeyAlgorithm);

      promise.resolve(Base64.encodeToString(encKeyBytes, Base64.NO_WRAP));
    } catch (Exception e) {
      Log.e("getSharedKey Error: ", String.valueOf(e));
      promise.reject("GET_SHARED_KEY_ERROR", e.getMessage(), e);
    }
  }

  @ReactMethod
  public void encrypt(String input, ReadableMap options, Promise promise) {
    try {
      if (encryptionKey == null) {
        promise.reject("ENCRYPT_ERROR", "Encryption key not established. Call getSharedKey first.");
        return;
      }
      CryptoConfig config = resolveCryptoConfig(options);
      byte[] inputByte = input.getBytes(StandardCharsets.UTF_8);
      Cipher cipher = Cipher.getInstance(config.cipherTransformation);
      cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
      byte[] iv = cipher.getIV();
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
      if (encryptionKey == null) {
        promise.reject("DECRYPT_ERROR", "Encryption key not established. Call getSharedKey first.");
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
      promise.resolve(new String(plaintext, Charset.forName("UTF-8")));
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
  public void storageEncrypt(String input, String secretKey, Boolean hardEncryption, Callback callback) {
    try {
      if (secretKey == null || secretKey.trim().isEmpty()) {
        callback.invoke(null, "secretKey is required. Device identifiers are not accepted as encryption keys.");
        return;
      }
      if (Boolean.TRUE.equals(hardEncryption)) {
        callback.invoke(
            null,
            "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data."
        );
        return;
      }
      callback.invoke(Obfuscation.obfuscate(input, secretKey), null);
    } catch (Exception e) {
      callback.invoke(null, e.getMessage());
    }
  }

  /** @deprecated Use deobfuscate() or SecureStorage APIs instead. */
  @ReactMethod
  public void storageDecrypt(String input, String secretKey, Boolean hardEncryption, Callback callback) {
    try {
      if (secretKey == null || secretKey.trim().isEmpty()) {
        callback.invoke(null, "secretKey is required. Device identifiers are not accepted as encryption keys.");
        return;
      }
      if (Boolean.TRUE.equals(hardEncryption)) {
        callback.invoke(
            null,
            "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data."
        );
        return;
      }
      callback.invoke(Obfuscation.deobfuscate(input, secretKey), null);
    } catch (Exception e) {
      callback.invoke(null, e.getMessage());
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
    sslpinning.fetch(url, options, callback);
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

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }
}
