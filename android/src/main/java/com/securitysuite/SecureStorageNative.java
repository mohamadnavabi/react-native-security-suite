package com.securitysuite;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyPermanentlyInvalidatedException;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.WritableArray;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.ProviderException;
import java.security.UnrecoverableKeyException;
import java.util.Map;

/**
 * Hardware-backed encrypted storage via Android Keystore + EncryptedSharedPreferences.
 * Keys are managed by the system — no hardcoded secrets or salts.
 */
public final class SecureStorageNative {
  private static final String PREFS_FILE = "com.securitysuite.secure_storage";
  private static final String KEY_PREFIX = "rss:";
  private static final String SECURE_STORAGE_FAILED = "Secure storage operation failed";

  private static volatile SharedPreferences cachedPreferences;

  private SecureStorageNative() {}

  private static boolean isKeyStoreOrDecryptionFailure(Throwable error) {
    Throwable current = error;
    while (current != null) {
      if (current instanceof GeneralSecurityException
          || current instanceof KeyStoreException
          || current instanceof UnrecoverableKeyException
          || current instanceof KeyPermanentlyInvalidatedException
          || current instanceof ProviderException
          || current instanceof IOException) {
        return true;
      }
      current = current.getCause();
    }
    return false;
  }

  private static SharedPreferences createEncryptedPreferences(Context context)
      throws GeneralSecurityException, IOException {
    MasterKey masterKey =
        new MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build();

    return EncryptedSharedPreferences.create(
        context,
        PREFS_FILE,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM);
  }

  private static SharedPreferences getPreferences(Context context) throws Exception {
    SharedPreferences preferences = cachedPreferences;
    if (preferences != null) {
      return preferences;
    }

    synchronized (SecureStorageNative.class) {
      if (cachedPreferences != null) {
        return cachedPreferences;
      }

      try {
        cachedPreferences = createEncryptedPreferences(context.getApplicationContext());
        return cachedPreferences;
      } catch (Exception initialError) {
        if (!isKeyStoreOrDecryptionFailure(initialError)) {
          throw new Exception(
              SECURE_STORAGE_FAILED + ": KeyStore initialization failed", initialError);
        }

        // One-time recovery: drop legacy/plaintext prefs so encrypted storage starts fresh.
        context.getApplicationContext().deleteSharedPreferences(PREFS_FILE);
        cachedPreferences = null;

        try {
          cachedPreferences = createEncryptedPreferences(context.getApplicationContext());
          return cachedPreferences;
        } catch (Exception retryError) {
          throw new Exception(
              SECURE_STORAGE_FAILED + ": KeyStore initialization failed", retryError);
        }
      }
    }
  }

  private static String namespacedKey(String key) throws IllegalArgumentException {
    if (key == null || key.trim().isEmpty()) {
      throw new IllegalArgumentException("Storage key is required");
    }
    return KEY_PREFIX + key.trim();
  }

  private static Exception secureStorageException(String operation, Exception error) {
    String detail = error.getMessage();
    if (detail == null || detail.isEmpty()) {
      detail = error.getClass().getSimpleName();
    }
    return new Exception(SECURE_STORAGE_FAILED + " (" + operation + "): " + detail, error);
  }

  public static void setItem(Context context, String key, String value) throws Exception {
    try {
      getPreferences(context).edit().putString(namespacedKey(key), value).apply();
    } catch (Exception error) {
      throw secureStorageException("setItem", error);
    }
  }

  public static String getItem(Context context, String key) throws Exception {
    try {
      return getPreferences(context).getString(namespacedKey(key), null);
    } catch (Exception error) {
      throw secureStorageException("getItem", error);
    }
  }

  public static void removeItem(Context context, String key) throws Exception {
    try {
      getPreferences(context).edit().remove(namespacedKey(key)).apply();
    } catch (Exception error) {
      throw secureStorageException("removeItem", error);
    }
  }

  public static void clear(Context context) throws Exception {
    try {
      SharedPreferences prefs = getPreferences(context);
      SharedPreferences.Editor editor = prefs.edit();
      for (Map.Entry<String, ?> entry : prefs.getAll().entrySet()) {
        if (entry.getKey().startsWith(KEY_PREFIX)) {
          editor.remove(entry.getKey());
        }
      }
      editor.apply();
    } catch (Exception error) {
      throw secureStorageException("clear", error);
    }
  }

  public static WritableArray getAllKeys(Context context) throws Exception {
    try {
      WritableArray keys = Arguments.createArray();
      for (Map.Entry<String, ?> entry : getPreferences(context).getAll().entrySet()) {
        if (entry.getKey().startsWith(KEY_PREFIX)) {
          keys.pushString(entry.getKey().substring(KEY_PREFIX.length()));
        }
      }
      return keys;
    } catch (Exception error) {
      throw secureStorageException("getAllKeys", error);
    }
  }

  public static void multiSet(Context context, ReadableArray pairs) throws Exception {
    try {
      SharedPreferences.Editor editor = getPreferences(context).edit();
      for (int i = 0; i < pairs.size(); i++) {
        ReadableArray pair = pairs.getArray(i);
        if (pair != null && pair.size() == 2) {
          editor.putString(namespacedKey(pair.getString(0)), pair.getString(1));
        }
      }
      editor.apply();
    } catch (Exception error) {
      throw secureStorageException("multiSet", error);
    }
  }

  public static WritableArray multiGet(Context context, ReadableArray keys) throws Exception {
    try {
      SharedPreferences prefs = getPreferences(context);
      WritableArray result = Arguments.createArray();
      for (int i = 0; i < keys.size(); i++) {
        String key = keys.getString(i);
        WritableArray pair = Arguments.createArray();
        pair.pushString(key);
        pair.pushString(prefs.getString(namespacedKey(key), null));
        result.pushArray(pair);
      }
      return result;
    } catch (Exception error) {
      throw secureStorageException("multiGet", error);
    }
  }

  public static void multiRemove(Context context, ReadableArray keys) throws Exception {
    try {
      SharedPreferences.Editor editor = getPreferences(context).edit();
      for (int i = 0; i < keys.size(); i++) {
        editor.remove(namespacedKey(keys.getString(i)));
      }
      editor.apply();
    } catch (Exception error) {
      throw secureStorageException("multiRemove", error);
    }
  }
}
