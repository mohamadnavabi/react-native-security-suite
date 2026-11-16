package com.securitysuite;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

import javax.net.ssl.SSLPeerUnverifiedException;

import okhttp3.CertificatePinner;
import okhttp3.Interceptor;
import okhttp3.Request;
import okhttp3.Response;
import okio.ByteString;

/**
 * SSL pinning rules for one request: a list of domains, each with its own SPKI SHA-256 pins.
 *
 * <p>Built from either form of the fetch options (both may be combined):
 * <ul>
 *   <li>{@code pinnedDomains: [{ domain, pins, includeSubdomains? }]} — per-domain pins.</li>
 *   <li>{@code certificates} + {@code validDomains} — legacy form: every pin applies to every
 *       listed domain and its subdomains.</li>
 * </ul>
 *
 * <p>A host is accepted with the union of the pins of every entry that matches it. Keep the
 * semantics in sync with {@code ios/SslPinningPolicy.swift}.
 */
final class PinningPolicy {
  static final String LEGACY_PAIR_ERROR =
      "SSL pinning requires both 'certificates' (SPKI SHA-256 hashes) and 'validDomains'";

  private static final Pattern HOSTNAME = Pattern.compile("^[a-z0-9_-]+(\\.[a-z0-9_-]+)*$");
  private static final Pattern PIN_PREFIX = Pattern.compile("^sha256/", Pattern.CASE_INSENSITIVE);
  private static final int SHA256_LENGTH = 32;

  static final class Domain {
    final String domain;
    final boolean includeSubdomains;
    /** OkHttp-formatted pins: {@code sha256/<base64>}. */
    final List<String> pins;

    private Domain(String domain, boolean includeSubdomains, List<String> pins) {
      this.domain = domain;
      this.includeSubdomains = includeSubdomains;
      this.pins = Collections.unmodifiableList(pins);
    }
  }

  private final List<Domain> domains;

  private PinningPolicy(List<Domain> domains) {
    this.domains = Collections.unmodifiableList(domains);
  }

  static PinningPolicy of(List<Domain> domains) {
    return new PinningPolicy(new ArrayList<>(domains));
  }

  boolean isEnabled() {
    return !domains.isEmpty();
  }

  List<Domain> getDomains() {
    return domains;
  }

  /**
   * Pins every configured domain ({@code **.domain} also matches the domain itself). Hosts with
   * no entry get no pins from OkHttp, so pair this with {@link #hostInterceptor}.
   */
  CertificatePinner toCertificatePinner() {
    CertificatePinner.Builder builder = new CertificatePinner.Builder();
    for (Domain entry : domains) {
      String pattern = entry.includeSubdomains ? "**." + entry.domain : entry.domain;
      builder.add(pattern, entry.pins.toArray(new String[0]));
    }
    return builder.build();
  }

  static boolean isPinned(CertificatePinner pinner, String host) {
    return !pinner.findMatchingPins(host).isEmpty();
  }

  /**
   * Network interceptor that runs for every hop, redirects included, before any request bytes are
   * written. CertificatePinner only enforces hosts it has pins for, so without this a redirect to
   * an unlisted host (or to plain HTTP) would go out unpinned.
   */
  static Interceptor hostInterceptor(final CertificatePinner pinner) {
    return new Interceptor() {
      @Override
      public Response intercept(Chain chain) throws IOException {
        Request request = chain.request();
        String host = request.url().host();
        if (!request.isHttps()) {
          throw new SSLPeerUnverifiedException(
              "SSL pinning: refusing cleartext request to '" + host + "'");
        }
        if (!isPinned(pinner, host)) {
          throw new SSLPeerUnverifiedException(
              "SSL pinning: host '" + host + "' is not in the SSL pinning domains");
        }
        return chain.proceed(request);
      }
    };
  }

  /** @throws IllegalArgumentException with a caller-facing message when the options are invalid. */
  static PinningPolicy fromOptions(ReadableMap options) {
    List<Domain> result = new ArrayList<>();

    if (isPresent(options, "pinnedDomains")) {
      if (options.getType("pinnedDomains") != ReadableType.Array) {
        throw new IllegalArgumentException("'pinnedDomains' must be an array");
      }
      ReadableArray entries = options.getArray("pinnedDomains");
      if (entries == null || entries.size() == 0) {
        throw new IllegalArgumentException("'pinnedDomains' must contain at least one domain");
      }
      for (int i = 0; i < entries.size(); i++) {
        String label = "pinnedDomains[" + i + "]";
        if (entries.getType(i) != ReadableType.Map) {
          throw new IllegalArgumentException(label + " must be an object");
        }
        ReadableMap entry = entries.getMap(i);
        String domain = isPresent(entry, "domain") && entry.getType("domain") == ReadableType.String
            ? entry.getString("domain")
            : null;
        boolean includeSubdomains = false;
        if (isPresent(entry, "includeSubdomains")) {
          if (entry.getType("includeSubdomains") != ReadableType.Boolean) {
            throw new IllegalArgumentException(label + ".includeSubdomains must be a boolean");
          }
          includeSubdomains = entry.getBoolean("includeSubdomains");
        }
        result.add(domain(domain, readStrings(entry, "pins", label + ".pins"), includeSubdomains, label));
      }
    }

    boolean hasCertificates = isPresent(options, "certificates");
    boolean hasValidDomains = isPresent(options, "validDomains");
    if (hasCertificates != hasValidDomains) {
      throw new IllegalArgumentException(LEGACY_PAIR_ERROR);
    }
    if (hasCertificates) {
      result.addAll(fromLegacy(
          readStrings(options, "certificates", "certificates"),
          readStrings(options, "validDomains", "validDomains")));
    }

    return new PinningPolicy(result);
  }

  /** Legacy form: each valid domain (and its subdomains) accepts every certificate pin. */
  static List<Domain> fromLegacy(List<String> certificates, List<String> validDomains) {
    if (certificates.isEmpty()) {
      throw new IllegalArgumentException("At least one certificate/public key pin is required");
    }
    List<Domain> result = new ArrayList<>();
    for (int i = 0; i < validDomains.size(); i++) {
      String domain = validDomains.get(i);
      if (domain == null || domain.trim().isEmpty()) {
        continue;
      }
      result.add(domain(domain, certificates, true, "validDomains[" + i + "]"));
    }
    if (result.isEmpty()) {
      throw new IllegalArgumentException("At least one valid domain is required");
    }
    return result;
  }

  static Domain domain(String rawDomain, List<String> rawPins, boolean includeSubdomains, String label) {
    String domain = rawDomain == null ? "" : rawDomain.trim().toLowerCase(Locale.ROOT);
    if (domain.endsWith(".")) {
      domain = domain.substring(0, domain.length() - 1);
    }
    if (domain.isEmpty()) {
      throw new IllegalArgumentException(label + ": 'domain' is required");
    }
    if (!HOSTNAME.matcher(domain).matches()) {
      throw new IllegalArgumentException(label + ": invalid domain '" + rawDomain
          + "'. Use a bare hostname such as 'api.example.com' (no scheme, port, path or wildcard;"
          + " set includeSubdomains to cover subdomains)");
    }
    if (rawPins == null || rawPins.isEmpty()) {
      throw new IllegalArgumentException(label + ": at least one pin is required for '" + domain + "'");
    }
    List<String> pins = new ArrayList<>();
    for (int i = 0; i < rawPins.size(); i++) {
      String raw = rawPins.get(i);
      String hash = raw == null ? "" : PIN_PREFIX.matcher(raw.trim()).replaceFirst("");
      ByteString decoded = hash.isEmpty() ? null : ByteString.decodeBase64(hash);
      if (decoded == null || decoded.size() != SHA256_LENGTH) {
        throw new IllegalArgumentException(label + ": pin at index " + i + " for '" + domain
            + "' is not a base64 SPKI SHA-256 hash");
      }
      pins.add("sha256/" + decoded.base64());
    }
    return new Domain(domain, includeSubdomains, pins);
  }

  private static boolean isPresent(ReadableMap map, String key) {
    return map.hasKey(key) && !map.isNull(key);
  }

  private static List<String> readStrings(ReadableMap map, String key, String label) {
    if (!isPresent(map, key) || map.getType(key) != ReadableType.Array) {
      throw new IllegalArgumentException(label + " must be an array of strings");
    }
    ReadableArray array = map.getArray(key);
    List<String> values = new ArrayList<>();
    for (int i = 0; array != null && i < array.size(); i++) {
      if (array.getType(i) != ReadableType.String) {
        throw new IllegalArgumentException(label + " must be an array of strings");
      }
      values.add(array.getString(i));
    }
    return values;
  }
}
