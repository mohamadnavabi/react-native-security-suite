package com.securitysuite;

import android.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class JWSGenerator {
    public String jwsHeader(byte[] payload, String keyId, String requestId, SecretKey secretKey) {
        try {
            // Construct JOSE Header
            String joseHeader = "{\"alg\":\"HS256\",\"kid\":\"" + keyId + "\",\"b64\":false,\"crit\":[\"b64\"],\"requestId\":\"" + requestId + "\"}";
            byte[] joseHeaderBytes = joseHeader.getBytes(StandardCharsets.UTF_8);
            String base64JoseHeader = Base64.encodeToString(joseHeaderBytes, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

            byte[] value = prepareAggregatedContentBytes(base64JoseHeader.getBytes(), payload);

            // Sign the value
            Mac hmacSha256 = Mac.getInstance("HmacSHA256");
            hmacSha256.init(secretKey);
            byte[] signature = hmacSha256.doFinal(value);

            // Convert signature to URL-safe Base64
            String base64URLSignature = Base64.encodeToString(signature, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);

            // Combine base64JoseHeader, "..", and base64URLSignature to form final JWS
            return base64JoseHeader + ".." + base64URLSignature;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return "";
        }
    }

    private static byte[] prepareAggregatedContentBytes(byte[] headerBytes, byte[] payloadBytes) {
        byte[] contentBytes = new byte[headerBytes.length + 1 + payloadBytes.length];
        System.arraycopy(headerBytes, 0, contentBytes, 0, headerBytes.length);
        contentBytes[headerBytes.length] = '.';
        System.arraycopy(payloadBytes, 0, contentBytes, headerBytes.length + 1, payloadBytes.length);
        return contentBytes;
    }
}
