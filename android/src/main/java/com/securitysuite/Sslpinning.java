package com.securitysuite;

import android.content.Context;
import android.net.Uri;

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

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import okhttp3.CertificatePinner;
import okhttp3.Headers;
import okhttp3.MediaType;
import okhttp3.MultipartBody;
import okhttp3.Request;
import okhttp3.OkHttpClient;
import okhttp3.RequestBody;
import okhttp3.Response;

import okio.Buffer;

public class Sslpinning {
  private final ReactApplicationContext context;
  private static String hostname = "";
  private static final String CONTENT_TYPE = "application/json; charset=utf-8";
  public static final MediaType mediaType = MediaType.parse(CONTENT_TYPE);
  String responseBodyString = "{}";
  Callback callback;

  public Sslpinning(ReactApplicationContext context) {
    this.context = context;
  }

  public void fetch(String url, final ReadableMap options, Callback callback) {
    this.callback = callback;

    if (!CryptoUtils.isHttpsUrl(url)) {
      callback.invoke(null, "Only HTTPS URLs are allowed");
      return;
    }

    PinningConfig pinningConfig = PinningConfig.fromOptions(options);
    if (pinningConfig.hasError()) {
      callback.invoke(null, pinningConfig.getError());
      return;
    }

    try {
      this.hostname = getHostname(url);
    } catch (URISyntaxException e) {
      callback.invoke(null, "Invalid URL hostname");
      return;
    }

    if (pinningConfig.isEnabled() && !isValidDomain(this.hostname, options)) {
      callback.invoke(null, "Hostname '" + this.hostname + "' is not in validDomains");
      return;
    }

    try {
      OkHttpClient client = getClient(options, pinningConfig);

      Headers header = setHeader(options);
      String method = getMethod(options);
      RequestBody requestBody = setBody(options);

      if ((method.equals("POST") || method.equals("PUT") || method.equals("PATCH")) && requestBody == null) {
        this.callback.invoke(null, "For " + method + " method body option is Required!");
        return;
      }

      String jwsHeader = "";
      String jwsHeaderName = "X-Request-Signature";
      if (options.hasKey("jws") && options.getMap("jws") != null) {
        ReadableMap jwsOptions = options.getMap("jws");
        if (jwsOptions == null || !jwsOptions.hasKey("secret")) {
          callback.invoke(null, "JWS secret is required and must be a non-empty string");
          return;
        }
        String secret = jwsOptions.getString("secret");
        if (secret == null || secret.trim().isEmpty()) {
          callback.invoke(null, "JWS secret is required and must be a non-empty string");
          return;
        }

        if (jwsOptions.hasKey("headerName") && jwsOptions.getString("headerName") != null) {
          jwsHeaderName = jwsOptions.getString("headerName");
        }

        byte[] requestBodyBytes = extractPayload(requestBody);
        String payloadString = JwsFetchPayload.build(url, method, requestBodyBytes, jwsOptions);
        boolean detached = jwsOptions.hasKey("detached") && jwsOptions.getBoolean("detached");
        String algorithm = jwsOptions.hasKey("algorithm") ? jwsOptions.getString("algorithm") : null;
        ReadableMap headers = jwsOptions.hasKey("headers") ? jwsOptions.getMap("headers") : null;

        JWSGenerator jwsGenerator = new JWSGenerator();
        jwsHeader = jwsGenerator.generate(
            payloadString,
            secret,
            algorithm,
            headers,
            detached
        );
      } else if (options.hasKey("keyId") && options.hasKey("requestId")) {
        if (!options.hasKey("secret")) {
          callback.invoke(null, "JWS secret is required. Pass options.jws.secret or options.secret for legacy signing.");
          return;
        }
        String secret = options.getString("secret");
        if (secret == null || secret.trim().isEmpty()) {
          callback.invoke(null, "JWS secret is required and must be a non-empty string");
          return;
        }
        String keyId = options.getString("keyId");
        String requestId = options.getString("requestId");
        byte[] payload = extractPayload(requestBody);
        JWSGenerator jwsGenerator = new JWSGenerator();
        jwsHeader = jwsGenerator.jwsHeader(payload, keyId, requestId, secret);
        jwsHeaderName = "X-JWS-Signature";
      }

      Request.Builder requestBuilder = new Request.Builder()
          .url(url)
          .method(method, requestBody);

      if (header != null) {
        requestBuilder.headers(header);
      }
      if (!jwsHeader.isEmpty()) {
        requestBuilder.addHeader(jwsHeaderName, jwsHeader);
      }

      Request request = requestBuilder.build();
      WritableMap output = Arguments.createMap();

      try {
        Response response = client.newCall(request).execute();
        int responseCode = response.code();

        byte[] bytes = response.body().bytes();
        responseBodyString = new String(bytes, StandardCharsets.UTF_8);

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
        output.putString("error", e.getMessage() != null ? e.getMessage() : responseBodyString);
        callback.invoke(null, output);
        if (!(e instanceof SocketTimeoutException)) {
          e.printStackTrace();
        }
      }
    } catch (Exception e) {
      callback.invoke(null, e.getMessage() != null ? e.getMessage() : "Request failed");
    }
  }

  private byte[] extractPayload(RequestBody requestBody) throws IOException {
    if (requestBody == null) {
      return new byte[0];
    }
    Buffer buffer = new Buffer();
    requestBody.writeTo(buffer);
    return buffer.readByteArray();
  }

  private CertificatePinner getCertificatePinner(ReadableMap options) {
    CertificatePinner.Builder certificatePinner = new CertificatePinner.Builder();
    ReadableArray hashes = options.getArray("certificates");

    for (int i = 0; i < hashes.size(); i++) {
      String pin = CryptoUtils.normalizePinHash(hashes.getString(i));
      if (pin.isEmpty()) {
        throw new IllegalArgumentException("Invalid certificate/public key pin at index " + i);
      }
      // OkHttp CertificatePinner pins SPKI SHA-256 hashes (public key pinning).
      certificatePinner.add(this.hostname, "sha256/" + pin);
    }

    return certificatePinner.build();
  }

  private OkHttpClient getClient(ReadableMap options, PinningConfig pinningConfig) {
    OkHttpClient.Builder builder = new OkHttpClient.Builder();

    // Fail-closed: once pinning is configured, OkHttp enforces pins with no system-trust fallback.
    if (pinningConfig.isEnabled()) {
      builder.certificatePinner(getCertificatePinner(options));
    }

    if (options.hasKey("timeout")) {
      int timeout = options.getInt("timeout");
      builder.connectTimeout(timeout, TimeUnit.MILLISECONDS)
          .readTimeout(timeout, TimeUnit.MILLISECONDS)
          .writeTimeout(timeout, TimeUnit.MILLISECONDS);
    }

    // Hard-gate network logging to debug builds only.
    if (options.hasKey("loggerIsEnabled")
        && options.getBoolean("loggerIsEnabled")
        && BuildConfig.DEBUG) {
      ChuckerInterceptor.Builder chuckerBuilder = new ChuckerInterceptor.Builder(context);
      for (String header : HeaderSanitizer.SENSITIVE_HEADERS) {
        chuckerBuilder.redactHeader(header);
      }
      builder.addInterceptor(chuckerBuilder.build());
    }

    return builder.build();
  }

  private static String getHostname(String url) throws URISyntaxException {
    URI uri = new URI(url.trim());
    String domain = uri.getHost();
    if (domain == null) {
      throw new URISyntaxException(url, "Missing host");
    }
    return domain.startsWith("www.") ? domain.substring(4) : domain;
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

    ReadableType bodyType = options.getType("body");
    switch (bodyType) {
      case String:
        return RequestBody.create(mediaType, options.getString("body"));
      case Map:
        ReadableMap bodyMap = options.getMap("body");
        if (bodyMap.hasKey("formData")) {
          return getBody(bodyMap.getMap("formData"));
        } else if (bodyMap.hasKey("_parts")) {
          return getBody(bodyMap);
        } else {
          return RequestBody.create(mediaType, bodyMap.toString());
        }
      default:
        return null;
    }
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
          addFormDataPart(this.context, multipartBodyBuilder, fileData, key);
        } else {
          multipartBodyBuilder.addFormDataPart(key, part.getString(1));
        }
      }
    }
    return multipartBodyBuilder.build();
  }

  private static void addFormDataPart(
      Context context,
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

  private boolean isValidDomain(String hostname, ReadableMap options) {
    ReadableArray domains = options.getArray("validDomains");
    if (domains == null || domains.size() == 0) {
      return false;
    }

    for (int i = 0; i < domains.size(); i++) {
      String domain = domains.getString(i);
      if (domain == null || domain.trim().isEmpty()) {
        continue;
      }
      String normalized = domain.trim().toLowerCase();
      String host = hostname.toLowerCase();
      if (host.equals(normalized) || host.endsWith("." + normalized)) {
        return true;
      }
    }
    return false;
  }

  static final class PinningConfig {
    private final boolean enabled;
    private final String error;

    private PinningConfig(boolean enabled, String error) {
      this.enabled = enabled;
      this.error = error;
    }

    static PinningConfig fromOptions(ReadableMap options) {
      boolean hasCertificates = options.hasKey("certificates");
      boolean hasValidDomains = options.hasKey("validDomains");

      if (hasCertificates != hasValidDomains) {
        return new PinningConfig(
            false,
            "SSL pinning requires both 'certificates' (SPKI SHA-256 hashes) and 'validDomains'"
        );
      }

      if (!hasCertificates) {
        return new PinningConfig(false, null);
      }

      ReadableArray certs = options.getArray("certificates");
      ReadableArray domains = options.getArray("validDomains");
      if (certs == null || certs.size() == 0) {
        return new PinningConfig(false, "At least one certificate/public key pin is required");
      }
      if (domains == null || domains.size() == 0) {
        return new PinningConfig(false, "At least one valid domain is required");
      }

      return new PinningConfig(true, null);
    }

    boolean isEnabled() {
      return enabled;
    }

    boolean hasError() {
      return error != null;
    }

    String getError() {
      return error;
    }
  }
}
