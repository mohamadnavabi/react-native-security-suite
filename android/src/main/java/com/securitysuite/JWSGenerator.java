package com.securitysuite;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.ReadableType;

import com.securitysuite.crypto.signatures.EcdsaSigner;
import com.securitysuite.crypto.signatures.Ed25519Signer;

import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
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

  /**
   * Legacy detached JWS used by fetch when keyId/requestId are set.
   * Signs {@code base64url(header) + "." + rawPayloadBytes} with the derived HMAC key bytes.
   */
  public String jwsHeader(byte[] payload, String keyId, String requestId, SecretKey secretKey) {
    try {
      CryptoUtils.validateJwsHeaderValue(keyId);
      CryptoUtils.validateJwsHeaderValue(requestId);

      JSONObject header = new JSONObject();
      header.put("alg", "HS256");
      header.put("kid", keyId);
      header.put("b64", false);
      header.put("crit", new org.json.JSONArray().put("b64"));
      header.put("request_id", requestId);

      byte[] joseHeaderBytes = header.toString().getBytes(StandardCharsets.UTF_8);
      String base64JoseHeader = CryptoUtils.base64UrlEncode(joseHeaderBytes);
      byte[] value = prepareAggregatedContentBytes(
          base64JoseHeader.getBytes(StandardCharsets.US_ASCII),
          payload != null ? payload : new byte[0]
      );

      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(secretKey);
      return base64JoseHeader + ".." + CryptoUtils.base64UrlEncode(mac.doFinal(value));
    } catch (Exception e) {
      throw new IllegalStateException("JWS generation failed: " + e.getMessage(), e);
    }
  }

  /** Legacy JWS generation using the derived HMAC key and raw request payload bytes. */
  public String generate(
      byte[] payload,
      SecretKey secretKey,
      String algorithm,
      ReadableMap headers
  ) throws Exception {
    if (secretKey == null) {
      throw new IllegalArgumentException("Secret key is required for JWS signing");
    }

    String validatedAlgorithm = CryptoUtils.validateJwsAlgorithm(algorithm);
    JSONObject header = buildLegacyDetachedHeader(validatedAlgorithm, headers);

    byte[] joseHeaderBytes = header.toString().getBytes(StandardCharsets.UTF_8);
    String base64JoseHeader = CryptoUtils.base64UrlEncode(joseHeaderBytes);
    byte[] value = prepareAggregatedContentBytes(
        base64JoseHeader.getBytes(StandardCharsets.US_ASCII),
        payload != null ? payload : new byte[0]
    );

    Mac mac = Mac.getInstance(CryptoUtils.hmacAlgorithmForJws(validatedAlgorithm));
    mac.init(secretKey);
    return base64JoseHeader + ".." + CryptoUtils.base64UrlEncode(mac.doFinal(value));
  }

  private JSONObject buildLegacyDetachedHeader(String algorithm, ReadableMap headers) throws Exception {
    JSONObject header = new JSONObject();
    header.put("alg", algorithm);
    header.put("b64", false);
    header.put("crit", new org.json.JSONArray().put("b64"));

    if (headers != null) {
      TreeMap<String, String> sorted = new TreeMap<>();
      ReadableMapKeySetIterator iterator = headers.keySetIterator();
      while (iterator.hasNextKey()) {
        String key = iterator.nextKey();
        if (headers.getType(key) != ReadableType.String) {
          throw new IllegalArgumentException("JWS header values must be strings: " + key);
        }
        CryptoUtils.validateJwsHeaderKey(key);
        String value = headers.getString(key);
        CryptoUtils.validateJwsHeaderValue(value);
        sorted.put(key, value);
      }

      for (java.util.Map.Entry<String, String> entry : sorted.entrySet()) {
        String key = entry.getKey();
        if ("alg".equals(key) || "b64".equals(key) || "crit".equals(key)) {
          continue;
        }
        header.put(key, entry.getValue());
      }
    }

    if (!header.has("kid")) {
      throw new IllegalArgumentException("JWS header 'kid' is required");
    }
    if (!header.has("request_id")) {
      throw new IllegalArgumentException("JWS header 'request_id' is required");
    }

    return header;
  }

  private static byte[] prepareAggregatedContentBytes(byte[] headerBytes, byte[] payloadBytes) {
    byte[] contentBytes = new byte[headerBytes.length + 1 + payloadBytes.length];
    System.arraycopy(headerBytes, 0, contentBytes, 0, headerBytes.length);
    contentBytes[headerBytes.length] = '.';
    System.arraycopy(payloadBytes, 0, contentBytes, headerBytes.length + 1, payloadBytes.length);
    return contentBytes;
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

  // ─── Asymmetric JWS (ES256 / EdDSA) ─────────────────────────────────────────

  public String generateAsymmetric(
      String payloadString,
      String privateKeyBase64,
      String algorithm,
      ReadableMap headers,
      boolean detached
  ) throws Exception {
    if (privateKeyBase64 == null || privateKeyBase64.trim().isEmpty()) {
      throw new IllegalArgumentException("privateKey is required");
    }
    if (!"ES256".equals(algorithm) && !"EdDSA".equals(algorithm)) {
      throw new IllegalArgumentException(
          "Expected asymmetric algorithm (ES256 or EdDSA), got: " + algorithm
      );
    }

    byte[] privateKeyBytes = android.util.Base64.decode(
        privateKeyBase64, android.util.Base64.NO_WRAP | android.util.Base64.URL_SAFE
    );

    JSONObject header = buildProtectedHeader(algorithm, headers);
    byte[] headerBytes = serializeHeader(header);
    String encodedProtectedHeader = CryptoUtils.base64UrlEncode(headerBytes);
    String encodedPayload = encodePayload(payloadString);
    byte[] signingInput = buildSigningInputBytes(encodedProtectedHeader, encodedPayload);

    byte[] signature;
    switch (algorithm) {
      case "ES256":
        signature = EcdsaSigner.sign(signingInput, privateKeyBytes);
        break;
      case "EdDSA":
        signature = Ed25519Signer.sign(signingInput, privateKeyBytes);
        break;
      default:
        throw new IllegalArgumentException("Unsupported asymmetric algorithm: " + algorithm);
    }

    String encodedSignature = CryptoUtils.base64UrlEncode(signature);
    return formatCompactJws(encodedProtectedHeader, encodedPayload, encodedSignature, detached);
  }
}
