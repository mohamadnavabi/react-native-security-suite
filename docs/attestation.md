# Device Attestation Flows

## Overview

Client-side integrity checks (`AppIntegrity.verify()`) are necessary but insufficient for high-value operations. Pair with platform attestation verified **on your server**.

## Android — Play Integrity API

### Client

```typescript
const attestation = await AppIntegrity.requestPlayIntegrity({
  nonce: serverProvidedNonce, // bind token to session
});

// Send attestation.token to backend
await api.post('/device/attest', { token: attestation.token });
```

### Server

1. Generate cryptographically random `nonce` (32 bytes, base64)
2. Client requests integrity token with that nonce
3. Server calls [Google Play Integrity API](https://developer.android.com/google/play/integrity) with `token`
4. Verify:
   - `requestDetails.nonce` matches
   - `appIntegrity.appRecognitionVerdict === 'PLAY_RECOGNIZED'`
   - `deviceIntegrity.deviceRecognitionVerdict` includes `MEETS_DEVICE_INTEGRITY`
   - `accountDetails.appLicensingVerdict === 'LICENSED'` (optional)

### Prerequisites

- App published on Google Play (or internal testing track)
- Google Cloud project with Play Integrity API enabled
- Service account with `playintegrity` scope

## iOS — App Attest

### Client

```typescript
const attestation = await AppIntegrity.requestAppAttest({
  challenge: serverChallenge,
});

await api.post('/device/attest', {
  keyId: attestation.keyId,
  attestation: attestation.attestationObject,
});
```

### Server

1. Issue challenge from server
2. Verify attestation object with Apple's App Attest verification procedure
3. Store `keyId` → public key mapping for subsequent assertions
4. For ongoing requests, verify `assertion` objects

See [Apple DeviceCheck documentation](https://developer.apple.com/documentation/devicecheck).

## Combined with SecurityReport

Recommended login flow:

```typescript
const [report, integrity] = await Promise.all([
  SecuritySuite.getSecurityReport(),
  AppIntegrity.verify(),
]);

await api.post('/auth/device-check', {
  report,
  integrity,
  playIntegrityToken, // or appAttest, platform-specific
});
```

**Server policy example:**

| Condition | Action |
|-----------|--------|
| `riskLevel === 'high'` | Block or step-up auth |
| `!integrity.validSignature` | Block |
| Play Integrity fails | Allow limited read-only mode |
| Emulator + debug build | Allow (dev environment) |
| Emulator + release build | Block |

## Nonce binding

Always bind attestation tokens to a server-issued nonce/challenge to prevent replay of captured tokens.

## Limitations

- Play Integrity unavailable on sideloaded APKs, some Chinese ROMs, emulators
- App Attest requires iOS 14+; Simulator returns unsupported
- Attestation adds latency (200ms–2s) — use on login, not every API call
