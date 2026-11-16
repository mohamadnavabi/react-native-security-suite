package com.securitysuite;

import com.facebook.react.bridge.JavaOnlyArray;
import com.facebook.react.bridge.JavaOnlyMap;

import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;

import okhttp3.CertificatePinner;
import okhttp3.Interceptor;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okio.ByteString;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class PinningPolicyTest {
  private static final String PIN_A = pin("a");
  private static final String PIN_A_BACKUP = pin("a-backup");
  private static final String PIN_B = pin("b");

  @Test
  public void noPinningOptions_isDisabled() {
    PinningPolicy policy = PinningPolicy.fromOptions(JavaOnlyMap.of("method", "GET"));
    assertFalse(policy.isEnabled());
  }

  @Test
  public void nullPinningOptions_isDisabled() {
    PinningPolicy policy = PinningPolicy.fromOptions(
        JavaOnlyMap.of("pinnedDomains", null, "certificates", null, "validDomains", null));
    assertFalse(policy.isEnabled());
  }

  @Test
  public void pinnedDomains_keepPinsSeparatePerDomain() {
    CertificatePinner pinner = PinningPolicy.fromOptions(JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of(
        entry("api.example.com", false, PIN_A, PIN_A_BACKUP),
        entry("cdn.example.net", false, "sha256/" + PIN_B)))).toCertificatePinner();

    assertEquals(hashes(PIN_A, PIN_A_BACKUP), hashes(pinner, "api.example.com"));
    assertEquals(hashes(PIN_B), hashes(pinner, "cdn.example.net"));
    assertTrue(pinner.findMatchingPins("example.com").isEmpty());
    assertTrue(pinner.findMatchingPins("other.example.net").isEmpty());
  }

  @Test
  public void pinnedDomains_exactByDefault_subdomainsWhenRequested() {
    CertificatePinner pinner = PinningPolicy.fromOptions(JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of(
        entry("api.example.com", null, PIN_A),
        entry("example.net", true, PIN_B)))).toCertificatePinner();

    assertTrue(pinner.findMatchingPins("v2.api.example.com").isEmpty());
    assertEquals(hashes(PIN_B), hashes(pinner, "example.net"));
    assertEquals(hashes(PIN_B), hashes(pinner, "cdn.example.net"));
    assertEquals(hashes(PIN_B), hashes(pinner, "a.b.example.net"));
    assertTrue(pinner.findMatchingPins("badexample.net").isEmpty());
  }

  @Test
  public void overlappingEntries_acceptTheUnionOfTheirPins() {
    CertificatePinner pinner = PinningPolicy.fromOptions(JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of(
        entry("example.com", true, PIN_A),
        entry("api.example.com", false, PIN_B)))).toCertificatePinner();

    assertEquals(hashes(PIN_A, PIN_B), hashes(pinner, "api.example.com"));
    assertEquals(hashes(PIN_A), hashes(pinner, "www.example.com"));
  }

  @Test
  public void legacyForm_appliesEveryPinToEveryDomainAndItsSubdomains() {
    PinningPolicy policy = PinningPolicy.fromOptions(JavaOnlyMap.of(
        "certificates", JavaOnlyArray.of("sha256/" + PIN_A, PIN_B),
        "validDomains", JavaOnlyArray.of(" API.Example.com ", "", "example.net")));
    CertificatePinner pinner = policy.toCertificatePinner();

    assertEquals(2, policy.getDomains().size());
    assertEquals(hashes(PIN_A, PIN_B), hashes(pinner, "api.example.com"));
    assertEquals(hashes(PIN_A, PIN_B), hashes(pinner, "v2.api.example.com"));
    assertEquals(hashes(PIN_A, PIN_B), hashes(pinner, "example.net"));
  }

  @Test
  public void bothForms_areCombined() {
    CertificatePinner pinner = PinningPolicy.fromOptions(JavaOnlyMap.of(
        "pinnedDomains", JavaOnlyArray.of(entry("api.example.com", false, PIN_A)),
        "certificates", JavaOnlyArray.of(PIN_B),
        "validDomains", JavaOnlyArray.of("example.net"))).toCertificatePinner();

    assertEquals(hashes(PIN_A), hashes(pinner, "api.example.com"));
    assertEquals(hashes(PIN_B), hashes(pinner, "cdn.example.net"));
  }

  @Test
  public void invalidConfigurations_areRejected() {
    assertRejected(JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of()), "at least one domain");
    assertRejected(JavaOnlyMap.of("pinnedDomains", "api.example.com"), "must be an array");
    assertRejected(JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of("api.example.com")), "must be an object");
    assertRejected(pinned(entry(null, false, PIN_A)), "'domain' is required");
    assertRejected(pinned(entry("https://api.example.com", false, PIN_A)), "invalid domain");
    assertRejected(pinned(entry("api.example.com:443", false, PIN_A)), "invalid domain");
    assertRejected(pinned(entry("*.example.com", false, PIN_A)), "invalid domain");
    assertRejected(pinned(entry("api.example.com", false)), "at least one pin");
    assertRejected(pinned(entry("api.example.com", false, "sha256/not-a-hash")), "pin at index 0");
    assertRejected(pinned(entry("api.example.com", false, PIN_A, "")), "pin at index 1");
    assertRejected(
        JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of(
            JavaOnlyMap.of("domain", "api.example.com", "pins", JavaOnlyArray.of(PIN_A), "includeSubdomains", "yes"))),
        "includeSubdomains must be a boolean");
    assertRejected(
        JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of(
            JavaOnlyMap.of("domain", "api.example.com", "pins", JavaOnlyArray.of(1))))
        , "pins must be an array of strings");

    assertRejected(JavaOnlyMap.of("certificates", JavaOnlyArray.of(PIN_A)), "requires both");
    assertRejected(JavaOnlyMap.of("validDomains", JavaOnlyArray.of("api.example.com")), "requires both");
    assertRejected(
        JavaOnlyMap.of("certificates", JavaOnlyArray.of(), "validDomains", JavaOnlyArray.of("api.example.com")),
        "At least one certificate");
    assertRejected(
        JavaOnlyMap.of("certificates", JavaOnlyArray.of(PIN_A), "validDomains", JavaOnlyArray.of(" ")),
        "At least one valid domain");
  }

  @Test
  public void hostInterceptor_allowsPinnedHttpsHosts() throws Exception {
    Interceptor interceptor = PinningPolicy.hostInterceptor(pinnerFor("api.example.com"));
    Request request = new Request.Builder().url("https://api.example.com/v1").build();
    Response expected = response(request);

    assertSame(expected, interceptor.intercept(chain(request, expected)));
  }

  @Test
  public void hostInterceptor_blocksRedirectsToUnpinnedHosts() throws Exception {
    Interceptor interceptor = PinningPolicy.hostInterceptor(pinnerFor("api.example.com"));
    Request request = new Request.Builder().url("https://evil.example.org/").build();

    try {
      interceptor.intercept(chain(request, response(request)));
      fail("Expected the unpinned host to be blocked");
    } catch (SSLPeerUnverifiedException e) {
      assertTrue(e.getMessage().contains("evil.example.org"));
    }
  }

  @Test
  public void hostInterceptor_blocksCleartextHops() throws Exception {
    Interceptor interceptor = PinningPolicy.hostInterceptor(pinnerFor("api.example.com"));
    Request request = new Request.Builder().url("http://api.example.com/").build();

    try {
      interceptor.intercept(chain(request, response(request)));
      fail("Expected the cleartext hop to be blocked");
    } catch (SSLPeerUnverifiedException e) {
      assertTrue(e.getMessage().contains("cleartext"));
    }
  }

  private static String pin(String seed) {
    return ByteString.encodeUtf8(seed).sha256().base64();
  }

  private static JavaOnlyMap entry(String domain, Boolean includeSubdomains, String... pins) {
    JavaOnlyMap map = JavaOnlyMap.of("pins", JavaOnlyArray.of((Object[]) pins));
    if (domain != null) {
      map.putString("domain", domain);
    }
    if (includeSubdomains != null) {
      map.putBoolean("includeSubdomains", includeSubdomains);
    }
    return map;
  }

  private static JavaOnlyMap pinned(JavaOnlyMap entry) {
    return JavaOnlyMap.of("pinnedDomains", JavaOnlyArray.of(entry));
  }

  private static CertificatePinner pinnerFor(String domain) {
    return PinningPolicy.fromOptions(pinned(entry(domain, false, PIN_A))).toCertificatePinner();
  }

  private static List<String> hashes(String... pins) {
    List<String> result = new ArrayList<>();
    for (String p : pins) {
      result.add(p);
    }
    return result;
  }

  private static List<String> hashes(CertificatePinner pinner, String host) {
    List<String> result = new ArrayList<>();
    for (CertificatePinner.Pin p : pinner.findMatchingPins(host)) {
      result.add(p.getHash().base64());
    }
    return result;
  }

  private static void assertRejected(JavaOnlyMap options, String messagePart) {
    try {
      PinningPolicy.fromOptions(options);
      fail("Expected rejection containing: " + messagePart);
    } catch (IllegalArgumentException e) {
      assertTrue(
          "'" + e.getMessage() + "' should contain '" + messagePart + "'",
          e.getMessage().contains(messagePart));
    }
  }

  private static Response response(Request request) {
    return new Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(200)
        .message("OK")
        .build();
  }

  private static Interceptor.Chain chain(final Request request, final Response response) {
    return (Interceptor.Chain) Proxy.newProxyInstance(
        Interceptor.Chain.class.getClassLoader(),
        new Class<?>[] {Interceptor.Chain.class},
        (proxy, method, args) -> {
          switch (method.getName()) {
            case "request":
              return request;
            case "proceed":
              return response;
            default:
              throw new UnsupportedOperationException(method.getName());
          }
        });
  }
}
