package com.securitysuite.crypto.utils;

import android.util.Base64;

public final class Base64Utils {
  private Base64Utils() {}

  public static String encode(byte[] data) {
    return Base64.encodeToString(data, Base64.NO_WRAP);
  }

  public static byte[] decode(String encoded) {
    return Base64.decode(encoded.trim(), Base64.NO_WRAP);
  }

  public static String encodeUrlSafe(byte[] data) {
    return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
  }

  public static byte[] decodeUrlSafe(String encoded) {
    return Base64.decode(encoded.trim(), Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
  }
}
