package com.securitysuite;

import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.module.annotations.ReactModule;

import androidx.annotation.NonNull;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.provider.Settings;
import android.util.Base64;
import android.util.Log;
import android.view.Window;
import android.view.WindowManager;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.scottyab.rootbeer.RootBeer;

@ReactModule(name = SecuritySuiteModule.NAME)
public class SecuritySuiteModule extends ReactContextBaseJavaModule {
  public static final String NAME = "SecuritySuite";
  private ReactApplicationContext context;

  KeyPairGenerator keyPairGenerator;
  KeyPair keyPair;
  PublicKey publicKey;
  PublicKey serverPublicKey;
  PrivateKey privateKey;
  String sharedKey;
  SecretKey secretKey;

  public SecuritySuiteModule(ReactApplicationContext reactContext) {
    super(reactContext);
    context = reactContext;
    generateKeyPair();
  }

  private void generateKeyPair() {
    try {
      keyPairGenerator = KeyPairGenerator.getInstance("EC");
      ECGenParameterSpec prime256v1ParamSpec = new ECGenParameterSpec("secp256r1");
      keyPairGenerator.initialize(prime256v1ParamSpec);
      keyPair = keyPairGenerator.genKeyPair();
      publicKey = keyPair.getPublic();
      privateKey = keyPair.getPrivate();
    } catch (Exception e) {
      Log.e("generateKeyPair Error: ", String.valueOf(e));
    }
  }

  @ReactMethod
  public void getPublicKey(Promise promise) {
    String base64DEREncoded = Base64.encodeToString(publicKey.getEncoded(), Base64.NO_WRAP);
    promise.resolve(base64DEREncoded);
  }

  private static SecretKey agreeSecretKey(PrivateKey prk_self, PublicKey pbk_peer, boolean lastPhase) throws Exception {
    SecretKey desSpec;
    try {
      KeyAgreement keyAgree = KeyAgreement.getInstance("ECDH");
      keyAgree.init(prk_self);
      keyAgree.doPhase(pbk_peer, true);
      byte[] sec = keyAgree.generateSecret();
      desSpec = new SecretKeySpec(sec, "AES");
    } catch (NoSuchAlgorithmException e) {
      throw new Exception();
    } catch (InvalidKeyException e) {
      throw new Exception();
    }
    return desSpec;
  }

  @ReactMethod
  public void getSharedKey(String serverPK, Promise promise) {
    try {
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.decode(serverPK.getBytes(), Base64.NO_WRAP)); // Change ASN1 to publicKey
      KeyFactory keyFactory = KeyFactory.getInstance("EC");
      serverPublicKey = keyFactory.generatePublic(keySpec);
      secretKey = agreeSecretKey(keyPair.getPrivate(), serverPublicKey, true);
      sharedKey = Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP);
      promise.resolve(sharedKey);
    } catch (Exception e) {
      Log.e("getSharedKey Error: ", String.valueOf(e));
      promise.reject(String.valueOf(e));
    }
  }

  @ReactMethod
  public void encrypt(String input, Promise promise) {
    try {
      byte[] inputByte = input.getBytes();
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      byte[] decodedKey = Base64.decode(sharedKey, Base64.NO_WRAP);
      SecretKey secretKeySpec = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
      byte[] iv = cipher.getIV();
      assert iv.length == 12;
      byte[] cipherText = cipher.doFinal(inputByte);
      if (cipherText.length != inputByte.length + 16)
        throw new IllegalStateException();
      byte[] output = new byte[12 + inputByte.length + 16];
      System.arraycopy(iv, 0, output, 0, 12);
      System.arraycopy(cipherText, 0, output, 12, cipherText.length);
      promise.resolve(Base64.encodeToString(output, Base64.NO_WRAP));
    } catch (Exception e) {
      Log.e("encrypt Error: ", String.valueOf(e));
      promise.reject(String.valueOf(e));
    }
  }

  @ReactMethod
  public void decrypt(String input, Promise promise) {
    try {
      byte[] inputBytes = Base64.decode(input.getBytes(), Base64.NO_WRAP);
      if (inputBytes.length < 12 + 16)
        throw new IllegalArgumentException();
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      GCMParameterSpec params = new GCMParameterSpec(128, inputBytes, 0, 12);
      byte[] decodedKey = Base64.decode(sharedKey, Base64.NO_WRAP);
      SecretKey secretKeySpec = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
      cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, params);
      byte[] plaintext = cipher.doFinal(inputBytes, 12, inputBytes.length - 12);
      String decrypted = new String(plaintext, Charset.forName("UTF-8"));
      promise.resolve(decrypted);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
        | BadPaddingException | InvalidAlgorithmParameterException e) {
      promise.reject(e);
    }
  }

  @ReactMethod
  public void getDeviceId(Callback callback) {
    try {
      String deviceId = getAndroidId();
      callback.invoke(deviceId, null);
    } catch (Exception e) {
      callback.invoke(null, e);
    }
  }

  @ReactMethod
  public void storageEncrypt(String input, String secretKey, Boolean hardEncryption, Callback callback) {
    try {
      String key = getAndroidId();
      if (secretKey != null) {
        key = secretKey;
      }
      String encryptedMessage = StorageEncryption.encrypt(input, key, hardEncryption);
      callback.invoke(encryptedMessage, null);
    } catch (Exception e) {
      callback.invoke(null, e);
    }
  }

  @ReactMethod
  public void storageDecrypt(String input, String secretKey, Boolean hardEncryption, Callback callback) {
    try {
      String key = getAndroidId();
      if (secretKey != null) {
        key = secretKey;
      }
      String decryptedMessage = StorageEncryption.decrypt(input, key);
      callback.invoke(decryptedMessage, null);
    } catch (Exception e) {
      callback.invoke(null, e.getMessage());
    }
  }

  @SuppressLint("HardwareIds")
  private String getAndroidId() {
    return Settings.Secure.getString(context.getContentResolver(),
        Settings.Secure.ANDROID_ID);
  }

  @ReactMethod
  public void fetch(String url, final ReadableMap options, Callback callback) {
    Sslpinning sslpinning = new Sslpinning(context);
    sslpinning.fetch(url, options, secretKey, callback);
  }

  @ReactMethod
  public void deviceHasSecurityRisk(Promise promise) {
    RootBeer rootBeer = new RootBeer(context);
    promise.resolve(rootBeer.isRooted());
  }

  @ReactMethod
  public void setScreenshotGuard(boolean enable) {
    final Activity activity = getCurrentActivity();
    if (activity != null) {
      activity.runOnUiThread(new Runnable() {
        @Override
        public void run() {
          Window window = activity.getWindow();
          if (enable) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE);
          } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
          }
        }
      });
    }
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }
}
