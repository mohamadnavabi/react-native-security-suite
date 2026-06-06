# Security Policy & Guarantees

## Supported versions

| Version | Status |
|---------|--------|
| 0.9.x | Maintenance — current release line |
| 1.0.x | Target production-grade architecture (see migration guide) |

Report vulnerabilities to **7navabi@gmail.com** or via [GitHub Security Advisories](https://github.com/mohamadnavabi/react-native-security-suite/security/advisories). Please do not disclose publicly before a fix is available.

## Security guarantees (v1.0 target)

### What this library provides

| Feature | Guarantee |
|---------|-----------|
| **SecureStorage** | Data encrypted at rest via iOS Keychain or Android EncryptedSharedPreferences + Keystore. Master keys are OS-generated, not embedded in the app. |
| **SSL pinning** | Connections using `SecureNetwork.fetch` fail closed when pin validation fails on configured domains. |
| **Native crypto keys** | ECDH/X25519 private keys stored in Android Keystore / iOS Keychain; non-exportable. |
| **JWS (asymmetric)** | ES256/EdDSA signing performed in Keystore/Secure Enclave; private key never returned to JS. |
| **Network logger** | Disabled in release builds by default; sensitive headers redacted when enabled. |
| **Screen security** | FLAG_SECURE (Android) and capture detection (iOS) when explicitly enabled. |

### What this library does NOT guarantee

- **Unbreakable client-side protection** — A determined attacker with root/jailbreak and Frida can bypass any client check.
- **JS memory safety** — Values read from storage or crypto APIs exist in the JavaScript heap until garbage-collected.
- **HS256 JWS secrecy** — HMAC secrets passed from JS are extractable from the app binary or runtime memory.
- **100% emulator/root detection** — Heuristic-based; false negatives and false positives are possible.
- **Clipboard isolation on all OS versions** — Auto-clear is best-effort; users can still screenshot clipboard UI on some devices.

## Secure defaults (v1.0)

```typescript
// Applied automatically unless overridden
SecuritySuite.configure({
  secureNetwork: {
    requireHttps: true,
    logger: { enabled: __DEV__ },
  },
  secureStorage: {
    accessibility: 'afterFirstUnlockThisDeviceOnly', // iOS
    requireAuthentication: false,
  },
  crypto: {
    returnSharedKey: false, // keep derived keys native-only
  },
});
```

## Error codes

All security failures use structured `SecurityError` with stable `code`:

| Code | Meaning |
|------|---------|
| `ROOT_DETECTED` | Android root indicators present |
| `JAILBREAK_DETECTED` | iOS jailbreak indicators present |
| `FRIDA_DETECTED` | Frida/instrumentation detected |
| `EMULATOR_DETECTED` | Running in emulator/simulator |
| `APP_TAMPERED` | Signature/installer mismatch |
| `SSL_PINNING_FAILED` | Certificate pin mismatch |
| `SECURE_STORAGE_UNAVAILABLE` | Keystore/Keychain failure |
| `CRYPTO_KEY_NOT_FOUND` | Missing key alias |
| `BIOMETRIC_AUTH_FAILED` | User cancelled or failed biometric |
| `JWS_SIGNING_FAILED` | JWS generation error |

## Data handling

- **No telemetry** is sent by the library
- **No analytics** or crash reporting is embedded
- Network logs stay on-device (Chucker/Pulse) when enabled in debug
- SecureStorage values are never written to AsyncStorage or plain files

## Dependency security

Production dependencies (via host app):

- Android: RootBeer, OkHttp, AndroidX Security Crypto, Chucker (debug)
- iOS: IOSSecuritySuite, CryptoKit, Pulse (debug)

Keep host apps updated; RSS inherits their CVE surface.

## Compliance notes

This library assists with **technical controls** commonly referenced in:

- OWASP MASVS (storage, network, platform interaction)
- PCI DSS mobile guidance (pinning, secure storage — not sufficient alone)
- PSD2 / open banking (device binding support via key exchange + JWS)

It does **not** certify compliance. Legal/compliance review remains the integrator's responsibility.

## Further reading

- [THREAT_MODEL.md](./THREAT_MODEL.md)
- [docs/architecture.md](./docs/architecture.md)
- [docs/migration-v1.md](./docs/migration-v1.md)
- [docs/ssl-pinning.md](./docs/ssl-pinning.md)
- [docs/jws-server-verification.md](./docs/jws-server-verification.md)
- [docs/secure-storage.md](./docs/secure-storage.md)
- [docs/attestation.md](./docs/attestation.md)
