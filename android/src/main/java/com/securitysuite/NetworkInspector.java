package com.securitysuite;

import com.facebook.react.internal.featureflags.ReactNativeFeatureFlags;
import com.facebook.react.modules.network.InspectorNetworkReporter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import okio.Buffer;

/**
 * Mirrors requests made by the native pinned fetch into the React Native DevTools Network panel.
 * Every call is a no-op when the React Native inspector network reporter is unavailable
 * (unsupported React Native version or a build without debugger support).
 */
final class NetworkInspector {
  private static final long MAX_BODY_PREVIEW_SIZE = 512 * 1024;
  private static volatile boolean available = true;

  private NetworkInspector() {}

  /**
   * Reports the start of a request and returns its DevTools request id, or null when reporting is
   * unavailable.
   */
  static String reportRequestStart(Request request) {
    if (!isEnabled()) {
      return null;
    }

    String requestId = "security-suite-" + UUID.randomUUID();
    try {
      Map<String, String> headers = toMap(HeaderSanitizer.sanitizeHeaders(request.headers()));
      RequestBody body = request.body();
      InspectorNetworkReporter.reportRequestStart(
          requestId,
          request.url().toString(),
          request.method(),
          headers,
          InspectorNetworkReporter.isDebuggingEnabled() ? bodyPreview(body) : "",
          body != null ? Math.max(body.contentLength(), 0) : 0
      );
      InspectorNetworkReporter.reportConnectionTiming(requestId, headers);
      return requestId;
    } catch (LinkageError e) {
      available = false;
      return null;
    } catch (Exception e) {
      return null;
    }
  }

  static void reportResponse(String requestId, Response response, String body, long encodedDataLength) {
    if (requestId == null) {
      return;
    }

    try {
      InspectorNetworkReporter.reportResponseStart(
          requestId,
          response.request().url().toString(),
          response.code(),
          toMap(HeaderSanitizer.sanitizeHeaders(response.headers())),
          encodedDataLength
      );
      InspectorNetworkReporter.reportDataReceived(requestId, body);
      InspectorNetworkReporter.maybeStoreResponseBody(requestId, body, false);
      InspectorNetworkReporter.reportResponseEnd(requestId, encodedDataLength);
    } catch (LinkageError e) {
      available = false;
    }
  }

  static void reportRequestFailed(String requestId) {
    if (requestId == null) {
      return;
    }

    try {
      InspectorNetworkReporter.reportRequestFailed(requestId, false);
    } catch (LinkageError e) {
      available = false;
    }
  }

  private static boolean isEnabled() {
    if (!available) {
      return false;
    }

    try {
      return ReactNativeFeatureFlags.enableNetworkEventReporting();
    } catch (LinkageError e) {
      available = false;
      return false;
    }
  }

  private static String bodyPreview(RequestBody body) throws IOException {
    if (body == null) {
      return "";
    }
    MediaType contentType = body.contentType();
    if (contentType != null && "multipart".equals(contentType.type())) {
      return "";
    }

    Buffer buffer = new Buffer();
    body.writeTo(buffer);
    long size = buffer.size();
    if (size <= MAX_BODY_PREVIEW_SIZE) {
      return buffer.readUtf8();
    }
    return buffer.readUtf8(MAX_BODY_PREVIEW_SIZE)
        + "\n... [truncated, showing " + MAX_BODY_PREVIEW_SIZE + " of " + size + " bytes]";
  }

  private static Map<String, String> toMap(Headers headers) {
    Map<String, String> map = new HashMap<>();
    for (int i = 0; i < headers.size(); i++) {
      String name = headers.name(i);
      String existing = map.get(name);
      map.put(name, existing == null ? headers.value(i) : existing + ", " + headers.value(i));
    }
    return map;
  }
}
