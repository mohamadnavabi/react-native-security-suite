package com.securitysuite;

import android.content.Context;
import android.net.Uri;

import com.chuckerteam.chucker.api.ChuckerCollector;
import com.chuckerteam.chucker.api.ChuckerInterceptor;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableMapKeySetIterator;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.bridge.WritableMap;

import org.json.JSONException;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLPeerUnverifiedException;

import okhttp3.CertificatePinner;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.Request;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.Response;

import okio.Buffer;

public class Sslpinning {
  private final ReactApplicationContext context;
  private static final String CONTENT_TYPE = "application/json; charset=utf-8";
  public static final MediaType mediaType = MediaType.parse(CONTENT_TYPE);
  String responseBodyString = "{}";
  Callback callback;
  private final java.util.List<java.io.File> tempFiles = new java.util.ArrayList<>();

  public Sslpinning(ReactApplicationContext context) {
    this.context = context;
  }

  public void fetch(String url, final ReadableMap options, SecretKey hmacKey, Callback callback) {
    this.callback = callback;

    PinningPolicy pinning;
    try {
      pinning = PinningPolicy.fromOptions(options);
    } catch (IllegalArgumentException e) {
      callback.invoke(null, e.getMessage());
      return;
    }

    if (!CryptoUtils.isHttpsUrl(url)) {
      // Cleartext is opt-in and never combined with pinning. When allowed, the app's
      // network security config still decides whether the host may be reached.
      if (!isCleartextAllowed(options) || !CryptoUtils.isHttpUrl(url)) {
        callback.invoke(null, "Only HTTPS URLs are allowed");
        return;
      }
      if (pinning.isEnabled()) {
        callback.invoke(null, "Cleartext HTTP is not allowed when SSL pinning is configured");
        return;
      }
    }

    try {
      getHostname(url);
    } catch (URISyntaxException e) {
      callback.invoke(null, "Invalid URL hostname");
      return;
    }

    CertificatePinner pinner = null;
    if (pinning.isEnabled()) {
      HttpUrl httpUrl = HttpUrl.parse(url);
      if (httpUrl == null) {
        callback.invoke(null, "Invalid URL hostname");
        return;
      }
      pinner = pinning.toCertificatePinner();
      if (!PinningPolicy.isPinned(pinner, httpUrl.host())) {
        WritableMap error = Arguments.createMap();
        error.putString("error", "Hostname '" + httpUrl.host() + "' is not in the SSL pinning domains");
        error.putString("networkError", "SSL_PEER_UNVERIFIED");
        callback.invoke(null, error);
        return;
      }
    }

    try {
      OkHttpClient client = getClient(options, pinner);

      Headers header = setHeader(options);
      String method = getMethod(options);
      RequestBody requestBody = setBody(options);

      if ((method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) && requestBody == null) {
        this.callback.invoke(null, "For " + method + " method body option is Required!");
        return;
      }

      JwsFetchSigner.Result jwsResult;
      try {
        jwsResult = JwsFetchSigner.sign(
            url,
            method,
            extractPayload(requestBody),
            options,
            hmacKey
        );
      } catch (Exception e) {
        callback.invoke(null, e.getMessage() != null ? e.getMessage() : "JWS signing failed");
        return;
      }

      Request.Builder requestBuilder = new Request.Builder()
          .url(url)
          .method(method, requestBody);

      if (header != null) {
        requestBuilder.headers(header);
      }
      if (jwsResult != null && jwsResult.signature != null && !jwsResult.signature.isEmpty()) {
        requestBuilder.addHeader(jwsResult.headerName, jwsResult.signature);
      }

      Request request = requestBuilder.build();
      WritableMap output = Arguments.createMap();
      String devToolsRequestId = isLoggerEnabled(options) ? NetworkInspector.reportRequestStart(request) : null;

      try {
        Response response = client.newCall(request).execute();
        int responseCode = response.code();

        if (isLoggerEnabled(options)) {
          NetworkLoggerNotification.show(context, responseCode + " " + request.url().encodedPath());
        } else {
          NetworkLoggerNotification.cancel(context);
        }

        okhttp3.ResponseBody body = response.body();
        byte[] bytes = body != null ? body.bytes() : new byte[0];
        responseBodyString = new String(bytes, StandardCharsets.UTF_8);
        NetworkInspector.reportResponse(devToolsRequestId, response, responseBodyString, bytes.length);

        output.putInt("status", responseCode);
        output.putString("url", request.url().toString());

        long tx = response.sentRequestAtMillis();
        long rx = response.receivedResponseAtMillis();
        output.putString("duration", (rx - tx) + "ms");

        if (!response.isSuccessful() || responseCode >= 400) {
          output.putString("error", responseBodyString);
          callback.invoke(null, output);
          return;
        }
        output.putString("response", responseBodyString);
        callback.invoke(output, null);
      } catch (IOException e) {
        NetworkInspector.reportRequestFailed(devToolsRequestId);
        output.putString("error", e.getMessage() != null ? e.getMessage() : responseBodyString);
        output.putString("networkError", networkError(e));
        callback.invoke(null, output);
        if (!(e instanceof SocketTimeoutException)) {
          e.printStackTrace();
        }
      } finally {
        for (java.io.File f : tempFiles) { f.delete(); }
        tempFiles.clear();
      }
    } catch (Exception e) {
      callback.invoke(null, e.getMessage() != null ? e.getMessage() : "Request failed");
    }
  }

  static String networkError(IOException e) {
    if (e instanceof UnknownHostException) {
      return "UNKNOWN_HOST";
    }
    if (e instanceof SSLPeerUnverifiedException) {
      return "SSL_PEER_UNVERIFIED";
    }
    if (e instanceof SSLHandshakeException) {
      return "SSL_HANDSHAKE";
    }
    if (e instanceof SocketTimeoutException) {
      return "TIMEOUT";
    }
    return "NETWORK";
  }

  private byte[] extractPayload(RequestBody requestBody) throws IOException {
    if (requestBody == null) {
      return new byte[0];
    }
    Buffer buffer = new Buffer();
    requestBody.writeTo(buffer);
    return buffer.readByteArray();
  }

  private OkHttpClient getClient(ReadableMap options, CertificatePinner pinner) {
    OkHttpClient.Builder builder = new OkHttpClient.Builder();

    if (pinner != null) {
      builder.certificatePinner(pinner);
      builder.addNetworkInterceptor(PinningPolicy.hostInterceptor(pinner));
    }

    if (options.hasKey("timeout")) {
      int timeout = options.getInt("timeout");
      // Seconds, matching iOS (URLRequest.timeoutInterval) and the JS default of 60.
      builder.connectTimeout(timeout, TimeUnit.SECONDS)
          .readTimeout(timeout, TimeUnit.SECONDS)
          .writeTimeout(timeout, TimeUnit.SECONDS);
    }

    if (isLoggerEnabled(options)) {
      // Chucker's own notification is disabled; NetworkLoggerNotification shows a single one instead.
      ChuckerInterceptor chuckerInterceptor = new ChuckerInterceptor.Builder(context)
          .collector(new ChuckerCollector(context, false))
          .redactHeaders(HeaderSanitizer.SENSITIVE_HEADERS.toArray(new String[0]))
          .build();
      builder.addInterceptor(chuckerInterceptor);
    }

    return builder.build();
  }

  private static boolean isLoggerEnabled(ReadableMap options) {
    return options.hasKey("loggerIsEnabled") && options.getBoolean("loggerIsEnabled");
  }

  private static boolean isCleartextAllowed(ReadableMap options) {
    return options.hasKey("allowCleartext")
        && options.getType("allowCleartext") == ReadableType.Boolean
        && options.getBoolean("allowCleartext");
  }

  private static String getHostname(String url) throws URISyntaxException {
    URI uri = new URI(url.trim());
    String domain = uri.getHost();
    if (domain == null) {
      throw new URISyntaxException(url, "Missing host");
    }
    return domain;
  }

  private String getMethod(ReadableMap options) {
    String method = "GET";
    if (options.hasKey("method") && options.getString("method") != null) {
      method = options.getString("method").toUpperCase();
    }
    return method;
  }

  private Headers setHeader(ReadableMap options) {
    if (!options.hasKey("headers")) {
      return null;
    }

    ReadableMap headers = options.getMap("headers");
    Headers.Builder builder = new Headers.Builder();
    Map<String, String> headersMap = readableMapToHashMap(headers);
    for (Map.Entry<String, String> set : headersMap.entrySet()) {
      builder.add(set.getKey(), set.getValue());
    }
    return builder.build();
  }

  private HashMap<String, String> readableMapToHashMap(ReadableMap readableMap) {
    HashMap<String, String> map = new HashMap<>();
    if (readableMap == null) {
      return map;
    }

    ReadableMapKeySetIterator keySetIterator = readableMap.keySetIterator();
    while (keySetIterator.hasNextKey()) {
      String key = keySetIterator.nextKey();
      if (readableMap.getType(key) == ReadableType.String) {
        map.put(key, readableMap.getString(key));
      }
    }
    return map;
  }

  private static boolean isFilePart(ReadableArray part) {
    if (part.getType(1) != ReadableType.Map) {
      return false;
    }
    ReadableMap value = part.getMap(1);
    return value.hasKey("type") && (value.hasKey("uri") || value.hasKey("path"));
  }

  private RequestBody setBody(ReadableMap options) {
    if (!options.hasKey("body")) {
      return null;
    }

    // OkHttp writes the body's media type over any Content-Type header, so the
    // caller's header has to become the body's type to survive.
    MediaType bodyType = requestMediaType(options);
    switch (options.getType("body")) {
      case String:
        return RequestBody.create(bodyType, options.getString("body"));
      case Map:
        ReadableMap bodyMap = options.getMap("body");
        if (bodyMap.hasKey("formData")) {
          return getBody(bodyMap.getMap("formData"));
        } else if (bodyMap.hasKey("_parts")) {
          return getBody(bodyMap);
        } else {
          return RequestBody.create(bodyType, bodyMap.toString());
        }
      default:
        return null;
    }
  }

  private static MediaType requestMediaType(ReadableMap options) {
    if (options.hasKey("headers") && options.getType("headers") == ReadableType.Map) {
      ReadableMap headers = options.getMap("headers");
      ReadableMapKeySetIterator iterator = headers.keySetIterator();
      while (iterator.hasNextKey()) {
        String key = iterator.nextKey();
        if ("content-type".equalsIgnoreCase(key) && headers.getType(key) == ReadableType.String) {
          MediaType parsed = MediaType.parse(headers.getString(key));
          if (parsed != null) {
            return parsed;
          }
        }
      }
    }
    return mediaType;
  }

  private RequestBody getBody(ReadableMap body) {
    MultipartBody.Builder multipartBodyBuilder = new MultipartBody.Builder()
        .setType(MultipartBody.FORM);
    if (body.hasKey("_parts")) {
      ReadableArray parts = body.getArray("_parts");
      for (int i = 0; i < parts.size(); i++) {
        ReadableArray part = parts.getArray(i);
        String key = "";
        if (part.getType(0) == ReadableType.String) {
          key = part.getString(0);
        } else if (part.getType(0) == ReadableType.Number) {
          key = String.valueOf(part.getInt(0));
        }

        if (isFilePart(part)) {
          ReadableMap fileData = part.getMap(1);
          addFormDataPart(multipartBodyBuilder, fileData, key);
        } else {
          multipartBodyBuilder.addFormDataPart(key, part.getString(1));
        }
      }
    }
    return multipartBodyBuilder.build();
  }

  private void addFormDataPart(
      MultipartBody.Builder multipartBodyBuilder,
      ReadableMap fileData,
      String key
  ) {
    Uri uri = Uri.parse("");
    if (fileData.hasKey("uri")) {
      uri = Uri.parse(fileData.getString("uri"));
    } else if (fileData.hasKey("path")) {
      uri = Uri.parse(fileData.getString("path"));
    }
    String type = fileData.getString("type");
    String fileName = fileData.hasKey("fileName")
        ? fileData.getString("fileName")
        : fileData.getString("name");

    try {
      File file = getTempFile(context, uri);
      tempFiles.add(file);
      multipartBodyBuilder.addFormDataPart(key, fileName, RequestBody.create(MediaType.parse(type), file));
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read multipart file", e);
    }
  }

  public static File getTempFile(Context context, Uri uri) throws IOException {
    File file = File.createTempFile("media", null);
    try (InputStream inputStream = context.getContentResolver().openInputStream(uri);
         OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(file))) {
      if (inputStream == null) {
        throw new IOException("Unable to open URI: " + uri);
      }
      byte[] buffer = new byte[1024];
      int len;
      while ((len = inputStream.read(buffer)) != -1) {
        outputStream.write(buffer, 0, len);
      }
    }
    return file;
  }

}
