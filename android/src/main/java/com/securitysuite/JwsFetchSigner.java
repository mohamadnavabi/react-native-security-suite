package com.securitysuite;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;

import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;

/**
 * Resolves JWS signing for {@link Sslpinning#fetch}.
 *
 * <p>Priority:
 * <ol>
 *   <li>{@code options.jws.secret} — RFC 7515 compact JWS with explicit secret string</li>
 *   <li>{@code options.jws} + native HMAC key — legacy detached JWS with {@code jws.headers}</li>
 *   <li>{@code options.keyId} + {@code options.requestId} + native HMAC key — legacy shortcut
 *       (signs raw request body; header {@code X-JWS-Signature})</li>
 *   <li>{@code options.keyId} + {@code options.requestId} + {@code options.secret} — explicit
 *       secret fallback for the legacy detached format</li>
 * </ol>
 *
 * <p>After {@code establishSharedKey} / {@code getSharedKey}, callers can pass only
 * {@code keyId} and {@code requestId} — no secret in JavaScript.
 */
public final class JwsFetchSigner {
  public static final String LEGACY_JWS_HEADER = "X-JWS-Signature";
  public static final String MODERN_JWS_HEADER = "X-Request-Signature";

  public static final class Result {
    public final String headerName;
    public final String signature;

    public Result(String headerName, String signature) {
      this.headerName = headerName;
      this.signature = signature;
    }
  }

  private JwsFetchSigner() {}

  public static Result sign(
      String url,
      String method,
      byte[] requestBody,
      ReadableMap options,
      SecretKey nativeHmacKey
  ) throws Exception {
    if (options.hasKey("jws") && options.getMap("jws") != null) {
      return signWithJwsOptions(url, method, requestBody, options.getMap("jws"), nativeHmacKey);
    }

    if (options.hasKey("keyId") && options.hasKey("requestId")) {
      return signWithLegacyKeyId(
          requestBody,
          options.getString("keyId"),
          options.getString("requestId"),
          options.hasKey("secret") ? options.getString("secret") : null,
          nativeHmacKey
      );
    }

    return null;
  }

  private static Result signWithJwsOptions(
      String url,
      String method,
      byte[] requestBody,
      ReadableMap jwsOptions,
      SecretKey nativeHmacKey
  ) throws Exception {
    String headerName = MODERN_JWS_HEADER;
    if (jwsOptions.hasKey("headerName") && jwsOptions.getString("headerName") != null) {
      headerName = jwsOptions.getString("headerName");
    }

    if (jwsOptions.hasKey("secret")) {
      String secret = jwsOptions.getString("secret");
      if (secret == null || secret.trim().isEmpty()) {
        throw new IllegalArgumentException("JWS secret is required and must be a non-empty string");
      }

      String payloadString = JwsFetchPayload.build(url, method, requestBody, jwsOptions);
      boolean detached = jwsOptions.hasKey("detached") && jwsOptions.getBoolean("detached");
      String algorithm = jwsOptions.hasKey("algorithm") ? jwsOptions.getString("algorithm") : null;
      ReadableMap headers = jwsOptions.hasKey("headers") ? jwsOptions.getMap("headers") : null;

      JWSGenerator generator = new JWSGenerator();
      String signature = generator.generate(
          payloadString,
          secret,
          algorithm,
          headers,
          detached
      );
      return new Result(headerName, signature);
    }

    if (nativeHmacKey == null) {
      throw new IllegalStateException(
          "HMAC key required for JWS signing. Call establishSharedKey or getSharedKey first."
      );
    }

    if (!jwsOptions.hasKey("headers") || jwsOptions.getMap("headers") == null) {
      throw new IllegalArgumentException("JWS headers (kid, request_id) are required");
    }

    JWSGenerator generator = new JWSGenerator();
    String signature = generator.generate(
        requestBody,
        nativeHmacKey,
        jwsOptions.hasKey("algorithm") ? jwsOptions.getString("algorithm") : "HS256",
        jwsOptions.getMap("headers")
    );
    return new Result(LEGACY_JWS_HEADER, signature);
  }

  private static Result signWithLegacyKeyId(
      byte[] requestBody,
      String keyId,
      String requestId,
      String explicitSecret,
      SecretKey nativeHmacKey
  ) throws Exception {
    byte[] payload = requestBody != null ? requestBody : new byte[0];
    JWSGenerator generator = new JWSGenerator();

    if (nativeHmacKey != null) {
      return new Result(
          LEGACY_JWS_HEADER,
          generator.jwsHeader(payload, keyId, requestId, nativeHmacKey)
      );
    }

    if (explicitSecret != null && !explicitSecret.trim().isEmpty()) {
      WritableMap legacyHeaders = Arguments.createMap();
      legacyHeaders.putString("kid", keyId);
      legacyHeaders.putString("request_id", requestId);
      String signature = generator.generate(
          new String(payload, StandardCharsets.UTF_8),
          explicitSecret,
          "HS256",
          legacyHeaders,
          true
      );
      return new Result(LEGACY_JWS_HEADER, signature);
    }

    throw new IllegalStateException(
        "HMAC key required for JWS signing. Call establishSharedKey or getSharedKey first."
    );
  }
}
