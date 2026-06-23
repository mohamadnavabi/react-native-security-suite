package com.securitysuite;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.WritableMap;

import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class JWSGeneratorTest {
  private static final String SECRET = "secret";

  @Test
  public void omittedPayloadProducesThreeSegmentsWithEmptyMiddle() throws Exception {
    assertEmptyPayloadCase(null);
  }

  @Test
  public void nullPayloadProducesThreeSegmentsWithEmptyMiddle() throws Exception {
    assertEmptyPayloadCase("");
  }

  @Test
  public void emptyStringPayloadProducesThreeSegmentsWithEmptyMiddle() throws Exception {
    assertEmptyPayloadCase("");
  }

  @Test
  public void stringNullPayloadIsNotEmpty() throws Exception {
    JWSGenerator generator = new JWSGenerator();
    String jws = generator.generate("null", SECRET, "HS256", headersWithKid(), false);
    String[] segments = jws.split("\\.", -1);

    assertEquals(3, segments.length);
    assertEquals(base64Url("null"), segments[1]);
    assertFalse(segments[1].isEmpty());
  }

  @Test
  public void stringUndefinedPayloadIsNotEmpty() throws Exception {
    JWSGenerator generator = new JWSGenerator();
    String jws = generator.generate("undefined", SECRET, "HS256", headersWithKid(), false);
    String[] segments = jws.split("\\.", -1);

    assertEquals(3, segments.length);
    assertEquals(base64Url("undefined"), segments[1]);
  }

  @Test
  public void objectPayloadIsBase64UrlEncodedJson() throws Exception {
    JWSGenerator generator = new JWSGenerator();
    String payload = "{\"amount\":1000}";
    String jws = generator.generate(payload, SECRET, "HS256", headersWithKid(), false);
    String[] segments = jws.split("\\.", -1);

    assertEquals(3, segments.length);
    assertEquals(base64Url(payload), segments[1]);
  }

  @Test(expected = IllegalArgumentException.class)
  public void algorithmMismatchThrows() throws Exception {
    WritableMap headers = Arguments.createMap();
    headers.putString("alg", "HS256");
    headers.putString("kid", "test-key");

    JWSGenerator generator = new JWSGenerator();
    generator.generate("", SECRET, "HS512", headers, false);
  }

  @Test
  public void algorithmFromHeaderIsUsed() throws Exception {
    WritableMap headers = Arguments.createMap();
    headers.putString("alg", "HS384");
    headers.putString("kid", "test-key");

    JWSGenerator generator = new JWSGenerator();
    String jws = generator.generate("", SECRET, null, headers, false);
    String protectedHeaderJson = new String(
        Base64.getUrlDecoder().decode(jws.split("\\.", -1)[0]),
        StandardCharsets.UTF_8
    );

    assertTrue(protectedHeaderJson.contains("\"alg\":\"HS384\""));
  }

  @Test
  public void defaultAlgorithmIsHs256() throws Exception {
    JWSGenerator generator = new JWSGenerator();
    String jws = generator.generate("", SECRET, null, headersWithKid(), false);
    String protectedHeaderJson = new String(
        Base64.getUrlDecoder().decode(jws.split("\\.", -1)[0]),
        StandardCharsets.UTF_8
    );

    assertTrue(protectedHeaderJson.contains("\"alg\":\"HS256\""));
  }

  @Test
  public void detachedOutputUsesDoubleDot() throws Exception {
    JWSGenerator generator = new JWSGenerator();
    String jws = generator.generate("payload", SECRET, "HS256", headersWithKid(), true);

    assertTrue(jws.contains(".."));
    assertEquals(2, jws.split("\\.\\.", -1).length);
    assertTrue(generator.verify(jws, "payload", SECRET, "HS256", true));
  }

  @Test
  public void legacyDetachedJwsHeaderUsesRawPayloadBytes() throws Exception {
    byte[] payload = "{\"password\":\"secret\"}".getBytes(StandardCharsets.UTF_8);
    SecretKeySpec hmacKey = new SecretKeySpec(
        "derived-hmac-key-material-32-bytes!!".getBytes(StandardCharsets.UTF_8),
        "HmacSHA256"
    );

    JWSGenerator generator = new JWSGenerator();
    String jws = generator.jwsHeader(payload, "kid-1", "req-1", hmacKey);

    assertTrue(jws.contains(".."));
    String[] parts = jws.split("\\.\\.", 2);
    assertEquals(2, parts.length);

    String protectedHeaderJson = new String(
        Base64.getUrlDecoder().decode(parts[0]),
        StandardCharsets.UTF_8
    );
    assertTrue(protectedHeaderJson.contains("\"b64\":false"));
    assertTrue(protectedHeaderJson.contains("\"kid\":\"kid-1\""));
    assertTrue(protectedHeaderJson.contains("\"request_id\":\"req-1\""));
  }

  private void assertEmptyPayloadCase(String payload) throws Exception {
    JWSGenerator generator = new JWSGenerator();
    String jws = generator.generate(payload, SECRET, "HS256", headersWithKid(), false);
    String[] segments = jws.split("\\.", -1);

    assertEquals(3, segments.length);
    assertEquals("", segments[1]);
    assertTrue(jws.contains(".."));
    assertTrue(generator.verify(jws, payload == null ? "" : payload, SECRET, "HS256", false));
  }

  private ReadableMap headersWithKid() {
    WritableMap headers = Arguments.createMap();
    headers.putString("kid", "test-key");
    return headers;
  }

  private String base64Url(String value) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString(value.getBytes(StandardCharsets.UTF_8));
  }

  private String signReference(String protectedHeader, String payloadString, String algorithm)
      throws Exception {
    String encodedPayload = payloadString == null || payloadString.isEmpty()
        ? ""
        : base64Url(payloadString);
    String signingInput = protectedHeader + "." + encodedPayload;
    String macAlgorithm = CryptoUtils.hmacAlgorithmForJws(algorithm);
    Mac mac = Mac.getInstance(macAlgorithm);
    mac.init(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), macAlgorithm));
    String signature = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(
        signingInput.getBytes(StandardCharsets.UTF_8)
    ));
    return protectedHeader + "." + encodedPayload + "." + signature;
  }
}
