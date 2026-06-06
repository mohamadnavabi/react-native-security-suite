package com.securitysuite;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.ReadableType;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import okhttp3.Headers;

/**
 * Prevents sensitive credentials from appearing in debug network logs.
 */
public final class HeaderSanitizer {
  public static final Set<String> SENSITIVE_HEADERS = Set.of(
      "authorization",
      "proxy-authorization",
      "cookie",
      "set-cookie",
      "x-api-key",
      "x-auth-token",
      "x-access-token",
      "x-jws-signature",
      "x-request-signature",
      "x-csrf-token"
  );

  private HeaderSanitizer() {}

  public static boolean isSensitiveHeader(String name) {
    return name != null && SENSITIVE_HEADERS.contains(name.toLowerCase(Locale.US));
  }

  public static String maskValue(String value) {
    if (value == null || value.isEmpty()) {
      return "***";
    }
    if (value.length() <= 8) {
      return "***";
    }
    return value.substring(0, 4) + "***" + value.substring(value.length() - 2);
  }

  public static Headers sanitizeHeaders(Headers headers) {
    if (headers == null) {
      return new Headers.Builder().build();
    }
    Headers.Builder builder = new Headers.Builder();
    for (int i = 0; i < headers.size(); i++) {
      String name = headers.name(i);
      String value = headers.value(i);
      builder.add(name, isSensitiveHeader(name) ? maskValue(value) : value);
    }
    return builder.build();
  }

  public static Map<String, String> sanitizeReadableMap(ReadableMap readableMap) {
    HashMap<String, String> map = new HashMap<>();
    if (readableMap == null) {
      return map;
    }
    ReadableMapKeySetIterator iterator = readableMap.keySetIterator();
    while (iterator.hasNextKey()) {
      String key = iterator.nextKey();
      if (readableMap.getType(key) == ReadableType.String) {
        String value = readableMap.getString(key);
        map.put(key, isSensitiveHeader(key) ? maskValue(value) : value);
      }
    }
    return map;
  }
}
