package com.securitysuite;

import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;

import org.json.JSONObject;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.TreeMap;

/**
 * Builds the default fetch request-signing payload when jws.payload is omitted.
 */
public final class JwsFetchPayload {
  private JwsFetchPayload() {}

  public static String build(
      String url,
      String method,
      byte[] requestBody,
      ReadableMap jwsOptions
  ) throws Exception {
    if (jwsOptions != null && jwsOptions.hasKey("payload")) {
      ReadableType payloadType = jwsOptions.getType("payload");
      if (payloadType == ReadableType.Null) {
        return "";
      }
      if (payloadType == ReadableType.String) {
        String payload = jwsOptions.getString("payload");
        return payload != null ? payload : "";
      }
      throw new IllegalArgumentException("JWS fetch payload must be a string when provided");
    }

    URI uri = new URI(url);
    TreeMap<String, Object> fields = new TreeMap<>();
    fields.put("method", method != null ? method.toUpperCase() : "GET");
    fields.put("path", uri.getPath() != null && !uri.getPath().isEmpty() ? uri.getPath() : "/");

    if (uri.getQuery() != null && !uri.getQuery().isEmpty()) {
      fields.put("query", uri.getQuery());
    }

    if (requestBody != null && requestBody.length > 0) {
      fields.put("bodyHash", CryptoUtils.base64UrlEncode(CryptoUtils.sha256(requestBody)));
    }

    if (jwsOptions != null && jwsOptions.hasKey("headers") && jwsOptions.getMap("headers") != null) {
      ReadableMap headers = jwsOptions.getMap("headers");
      copyIfPresent(headers, fields, "timestamp");
      copyIfPresent(headers, fields, "nonce");
      copyIfPresent(headers, fields, "request_id");
      copyIfPresent(headers, fields, "requestId");
    }

    JSONObject json = new JSONObject();
    for (java.util.Map.Entry<String, Object> entry : fields.entrySet()) {
      json.put(entry.getKey(), entry.getValue());
    }
    return json.toString();
  }

  private static void copyIfPresent(
      ReadableMap headers,
      TreeMap<String, Object> fields,
      String key
  ) {
    if (!headers.hasKey(key) || headers.isNull(key)) {
      return;
    }
    ReadableType type = headers.getType(key);
    if (type == ReadableType.String) {
      fields.put(key, headers.getString(key));
    } else if (type == ReadableType.Number) {
      fields.put(key, headers.getDouble(key));
    } else if (type == ReadableType.Boolean) {
      fields.put(key, headers.getBoolean(key));
    }
  }
}
