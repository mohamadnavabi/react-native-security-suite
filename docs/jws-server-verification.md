# JWS Server-Side Verification

## Overview

RSS generates [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) compact JWS tokens. The server must verify signatures, validate replay-protection headers, and enforce time windows.

## HS256/384/512 (legacy — shared secret)

**Client:**

```typescript
const headers = JWS.createReplayProtectedHeaders();
await SecureNetwork.fetch(url, {
  method: 'POST',
  body: payload,
  jws: {
    algorithm: 'HS256',
    secret: sessionSecret, // short-lived, from backend
    headers,
  },
});
```

**Server (Node.js example):**

```javascript
const crypto = require('crypto');

function verifyHS256(compact, secret, maxAgeMs = 60_000) {
  const [headerB64, payloadB64, sigB64] = compact.split('.');
  const signingInput = `${headerB64}.${payloadB64}`;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(signingInput)
    .digest('base64url');

  if (expected !== sigB64) throw new Error('INVALID_SIGNATURE');

  const header = JSON.parse(Buffer.from(headerB64, 'base64url'));
  const payload = JSON.parse(
    payloadB64 ? Buffer.from(payloadB64, 'base64url') : '{}'
  );

  const ts = header.timestamp ?? payload.timestamp;
  if (Date.now() - ts > maxAgeMs) throw new Error('EXPIRED');

  // Store nonce/request_id in Redis with TTL to prevent replay
  return { header, payload };
}
```

**Limitation:** Shared secrets in mobile apps are extractable. Use only for session-scoped secrets delivered post-authentication.

## ES256 (recommended — Keystore keypair)

**Client:**

```typescript
await JWS.generateKeyPair({ alias: 'device-signing', algorithm: 'ES256' });
const publicKey = await JWS.exportPublicKey('device-signing');
// Register publicKey with backend during device enrollment

const token = await JWS.generate({
  algorithm: 'ES256',
  keyAlias: 'device-signing',
  payload: canonicalPayload,
  headers: JWS.createReplayProtectedHeaders(),
});
```

**Server:** Verify with registered P-256 public key (JWK or PEM). Use `jose` (Node) or equivalent:

```javascript
import { jwtVerify, importJWK } from 'jose';

const publicKey = await importJWK(deviceRegisteredJwk, 'ES256');
const { payload, protectedHeader } = await jwtVerify(compactJws, publicKey, {
  algorithms: ['ES256'],
});
```

Private key **never leaves** the device Keystore.

## Default fetch signing payload

When `jws.payload` is omitted, native code builds:

```json
{
  "bodyHash": "<base64url SHA-256 of body>",
  "method": "POST",
  "path": "/v1/payments",
  "query": "currency=USD",
  "nonce": "<from headers>",
  "request_id": "<from headers>",
  "timestamp": 1717654321000
}
```

Server must reconstruct the same payload from the incoming HTTP request.

## Replay protection headers

`JWS.createReplayProtectedHeaders()` returns:

```typescript
{
  timestamp: Date.now(),
  nonce: '<crypto.randomUUID()>',  // native CSPRNG
  request_id: '<crypto.randomUUID()>',
}
```

**Server checklist:**

1. Reject if `timestamp` older than 60s (tune per use case)
2. Store `nonce` + `request_id` in idempotency store (Redis, 5 min TTL)
3. Reject duplicate `request_id` for mutating operations
4. Validate `bodyHash` matches actual request body SHA-256

## Detached JWS

When `detached: true`, token format is `header..signature`. Payload is the raw HTTP body. Server verifies signature over `header.payload` where payload is the body bytes.

## Canonical JSON

For object payloads in `JWS.generate()`, keys are sorted lexicographically with no insignificant whitespace (RFC 8785-style). Ensures client and server compute identical signing strings.

## Algorithm support matrix

| Algorithm | Key location | Recommended |
|-----------|--------------|-------------|
| HS256/384/512 | JS memory | Legacy only |
| ES256 | Keystore / Secure Enclave | ✅ Primary |
| EdDSA (Ed25519) | Keystore (API 33+) / Keychain | ✅ Preferred on supported devices |
