package com.securitysuite;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.ReadableType;

import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.util.TreeMap;

/**
 * RFC 7515 compact JWS serialization.
 * Protected headers are built with JSONObject — never string concatenation.
 */
public class JWSGenerator {
  public String generate(
      String payloadString,
      String secret,
      String algorithm,
      ReadableMap headers,
      boolean detached
  ) throws Exception {
    if (secret == null || secret.trim().isEmpty()) {
      throw new IllegalArgumentException("JWS secret is required and must be a non-empty string");
    }

    String selectedAlgorithm = resolveAlgorithm(algorithm, headers);
    JSONObject header = buildProtectedHeader(selectedAlgorithm, headers);

    byte[] headerBytes = serializeHeader(header);
    String encodedProtectedHeader = CryptoUtils.base64UrlEncode(headerBytes);
    String encodedPayload = encodePayload(payloadString);
    byte[] signingInput = buildSigningInputBytes(encodedProtectedHeader, encodedPayload);

    Mac mac = Mac.getInstance(CryptoUtils.hmacAlgorithmForJws(selectedAlgorithm));
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), CryptoUtils.hmacAlgorithmForJws(selectedAlgorithm)));
    String encodedSignature = CryptoUtils.base64UrlEncode(mac.doFinal(signingInput));

    return formatCompactJws(encodedProtectedHeader, encodedPayload, encodedSignature, detached);
  }

  /** @deprecated Use {@link #generate} with explicit secret and headers. */
  @Deprecated
  public String jwsHeader(byte[] payload, String keyId, String requestId, String secret) {
    try {
      JSONObject legacyHeaders = new JSONObject();
      legacyHeaders.put("kid", keyId);
      legacyHeaders.put("request_id", requestId);

      String payloadString = payload != null
          ? new String(payload, StandardCharsets.UTF_8)
          : "";

      return generate(payloadString, secret, "HS256", toReadableMap(legacyHeaders), true);
    } catch (Exception e) {
      throw new IllegalStateException("JWS generation failed: " + e.getMessage(), e);
    }
  }

  public boolean verify(
      String compactJws,
      String payloadString,
      String secret,
      String expectedAlgorithm,
      boolean detached
  ) throws Exception {
    if (compactJws == null || compactJws.isEmpty()) {
      throw new IllegalArgumentException("Invalid compact JWS format");
    }

    String encodedProtectedHeader;
    String encodedSignature;

    if (detached) {
      String[] parts = compactJws.split("\\.\\.", 2);
      if (parts.length != 2) {
        throw new IllegalArgumentException("Invalid compact detached JWS format");
      }
      encodedProtectedHeader = parts[0];
      encodedSignature = parts[1];
    } else {
      String[] parts = compactJws.split("\\.");
      if (parts.length != 3) {
        throw new IllegalArgumentException("Invalid compact JWS format");
      }
      encodedProtectedHeader = parts[0];
      encodedSignature = parts[2];
    }

    String encodedPayload = encodePayload(payloadString);
    byte[] signingInput = buildSigningInputBytes(encodedProtectedHeader, encodedPayload);

    String algorithm = expectedAlgorithm != null ? expectedAlgorithm : "HS256";
    Mac mac = Mac.getInstance(CryptoUtils.hmacAlgorithmForJws(CryptoUtils.validateJwsAlgorithm(algorithm)));
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), CryptoUtils.hmacAlgorithmForJws(algorithm)));
    byte[] expectedSignature = mac.doFinal(signingInput);

    byte[] providedSignature = android.util.Base64.decode(
        encodedSignature,
        android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP
    );

    return java.security.MessageDigest.isEqual(expectedSignature, providedSignature);
  }

  static String resolveAlgorithm(String algorithm, ReadableMap headers) throws Exception {
    String headerAlg = null;
    if (headers != null && headers.hasKey("alg") && !headers.isNull("alg")) {
      headerAlg = readHeaderValueAsString(headers, "alg");
    }

    if (algorithm != null && !algorithm.isEmpty() && headerAlg != null && !algorithm.equals(headerAlg)) {
      throw new IllegalArgumentException(
          "JWS algorithm mismatch: options.algorithm and headers.alg must match"
      );
    }

    if (algorithm != null && !algorithm.isEmpty()) {
      return CryptoUtils.validateJwsAlgorithm(algorithm);
    }

    if (headerAlg != null && !headerAlg.isEmpty()) {
      return CryptoUtils.validateJwsAlgorithm(headerAlg);
    }

    return "HS256";
  }

  private JSONObject buildProtectedHeader(String selectedAlgorithm, ReadableMap headers) throws Exception {
    JSONObject header = new JSONObject();
    header.put("alg", selectedAlgorithm);

    if (headers != null) {
      TreeMap<String, Object> sorted = new TreeMap<>();
      ReadableMapKeySetIterator iterator = headers.keySetIterator();
      while (iterator.hasNextKey()) {
        String key = iterator.nextKey();
        if ("alg".equals(key)) {
          continue;
        }
        CryptoUtils.validateJwsHeaderKey(key);
        sorted.put(key, readHeaderValue(headers, key));
      }

      for (java.util.Map.Entry<String, Object> entry : sorted.entrySet()) {
        header.put(entry.getKey(), entry.getValue());
      }
    }

    return header;
  }

  private static Object readHeaderValue(ReadableMap headers, String key) {
    ReadableType type = headers.getType(key);
    switch (type) {
      case Null:
        return JSONObject.NULL;
      case Boolean:
        return headers.getBoolean(key);
      case Number:
        return headers.getDouble(key);
      case String:
        String value = headers.getString(key);
        CryptoUtils.validateJwsHeaderValue(value);
        return value;
      default:
        throw new IllegalArgumentException(
            "JWS header values must be JSON-serializable primitives: " + key
        );
    }
  }

  private static String readHeaderValueAsString(ReadableMap headers, String key) {
    ReadableType type = headers.getType(key);
    if (type == ReadableType.String) {
      return headers.getString(key);
    }
    if (type == ReadableType.Number) {
      double number = headers.getDouble(key);
      if (number == Math.rint(number)) {
        return String.valueOf((long) number);
      }
      return String.valueOf(number);
    }
    if (type == ReadableType.Boolean) {
      return String.valueOf(headers.getBoolean(key));
    }
    throw new IllegalArgumentException(
        "JWS header values must be JSON-serializable primitives: " + key
    );
  }

  private static byte[] serializeHeader(JSONObject header) throws Exception {
    TreeMap<String, Object> sorted = new TreeMap<>();
    java.util.Iterator<String> keys = header.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      sorted.put(key, header.get(key));
    }

    JSONObject sortedHeader = new JSONObject();
    for (java.util.Map.Entry<String, Object> entry : sorted.entrySet()) {
      sortedHeader.put(entry.getKey(), entry.getValue());
    }
    return sortedHeader.toString().getBytes(StandardCharsets.UTF_8);
  }

  static String encodePayload(String payloadString) {
    if (payloadString == null || payloadString.isEmpty()) {
      return "";
    }
    return CryptoUtils.base64UrlEncode(payloadString.getBytes(StandardCharsets.UTF_8));
  }

  static byte[] buildSigningInputBytes(String encodedProtectedHeader, String encodedPayload) {
    String signingInput = encodedProtectedHeader + "." + (encodedPayload != null ? encodedPayload : "");
    return signingInput.getBytes(StandardCharsets.UTF_8);
  }

  static String formatCompactJws(
      String encodedProtectedHeader,
      String encodedPayload,
      String encodedSignature,
      boolean detached
  ) {
    if (detached) {
      return encodedProtectedHeader + ".." + encodedSignature;
    }
    String payloadSegment = encodedPayload != null ? encodedPayload : "";
    return encodedProtectedHeader + "." + payloadSegment + "." + encodedSignature;
  }

  private static ReadableMap toReadableMap(JSONObject jsonObject) {
    com.facebook.react.bridge.WritableMap map = com.facebook.react.bridge.Arguments.createMap();
    java.util.Iterator<String> keys = jsonObject.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      try {
        map.putString(key, jsonObject.getString(key));
      } catch (Exception e) {
        throw new IllegalStateException("Failed to convert legacy JWS headers", e);
      }
    }
    return map;
  }
}
