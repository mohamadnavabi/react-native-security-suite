# React Native Security Suite

[![npm version](https://badge.fury.io/js/react-native-security-suite.svg)](https://www.npmjs.com/package/react-native-security-suite)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/npm/dm/react-native-security-suite.svg)](https://www.npmjs.com/package/react-native-security-suite)

Comprehensive mobile security for React Native — detection, cryptography, secure storage, network protection, and device attestation in a single package.

<div style="display: flex; flex-direction: row; justify-content: center; align-items: center; gap: 20px;">
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/pulse.gif" alt="iOS Pulse Network Monitor" width="200" />
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/chucker.gif" alt="Android Chucker Network Monitor" width="200" />
</div>

---

## Contents

- [Features](#features)
- [Platform Support](#platform-support)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Security Detection](#security-detection)
- [Threat Monitoring](#threat-monitoring)
- [Cryptography](#cryptography)
- [JWS Request Signing](#jws-request-signing)
- [Secure Storage](#secure-storage)
- [Network Security](#network-security)
- [Screen Protection](#screen-protection)
- [Clipboard Protection](#clipboard-protection)
- [Device Attestation](#device-attestation)
- [API Reference](#api-reference)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)

---

## Features

**Detection & Runtime Protection**
- Root and jailbreak detection (Android RootBeer + IOSSecuritySuite)
- Emulator/simulator detection with environment indicators
- Debugger detection (`P_TRACED`, TracerPid)
- Hooking detection — Frida, Xposed/LSPosed, Substrate, Magisk
- Continuous threat monitoring with configurable callbacks
- Composite risk scoring (`low` / `medium` / `high`)
- `SecuritySuite.protect()` — throws `SecurityError` on policy violations

**Cryptography**
- ECDH (P-256) and X25519 key exchange
- AES-256-GCM encryption/decryption
- HKDF key derivation
- Ed25519 and ECDSA P-256 digital signatures
- SHA-256 / SHA-512 hashing
- CSPRNG — `Random.randomBytes()` and `Random.randomUUID()`

**JWS Request Signing (RFC 7515)**
- Symmetric: HS256, HS384, HS512
- Asymmetric: ES256 (ECDSA P-256), EdDSA (Ed25519)
- Detached compact JWS for body signing
- Auto-signing on `fetch` with configurable header name

**Secure Storage**
- Hardware-backed: Keychain (iOS) / EncryptedSharedPreferences + Android Keystore (Android)
- Biometric-gated read/write (Face ID, Touch ID, Fingerprint)
- Key expiry — `setItemWithExpiry` / `getItemIfValid`
- Key rotation with version tracking — `rotateItem`

**Network Security**
- SSL/TLS certificate pinning (SPKI SHA-256 hashes)
- Global `fetch` interceptor for zero-config pinning
- `createPinnedFetch()` — per-instance pinned transport
- Network request logging (Chucker on Android, Pulse on iOS)

**Screen Protection**
- `SecureView` — blocks screenshots and screen recordings per-view
- `BackgroundProtection` component + `useBackgroundProtection` hook — privacy overlay in app switcher
- `ScreenSecurity.setWindowSecure()` — native window-level `FLAG_SECURE` (Android) / blur overlay (iOS)

**Clipboard Protection**
- `ClipboardGuard.copy(text, { clearAfterMs })` — auto-clear after timeout
- Manual clear and cancel-auto-clear controls

**Device Attestation**
- iOS App Attest (DCAppAttestService, iOS 14+)
- Android Play Integrity API
- Unified `DeviceAttestation.attestDevice(challengeHash)` for both platforms

---

## Platform Support

| Platform | Minimum Version |
|----------|----------------|
| Android  | API 21 (Android 5.0) |
| iOS      | iOS 13.0 |
| React Native | 0.60+ |

Biometric storage requires Android API 28+ (Android 9). Device Attestation requires iOS 14+ (App Attest) or Google Play Services (Play Integrity).

---

## Installation

```bash
# yarn
yarn add react-native-security-suite

# npm
npm install react-native-security-suite
```

```bash
cd ios && pod install
```

**Optional peer dependency** — for clipboard support install:

```bash
yarn add @react-native-clipboard/clipboard
```

**Android — Play Integrity** (opt-in): add to your app's `build.gradle`:

```gradle
implementation "com.google.android.play:integrity:1.3.0"
```

**iOS — App Attest** (opt-in): add the "App Attest" capability in your Apple Developer account and target entitlements.

---

## Quick Start

```typescript
import { SecuritySuite } from 'react-native-security-suite';

await SecuritySuite.initialize({
  crypto: {
    keyAgreementAlgorithm: 'X25519',
    keyType: 'OKP',
    encryptionKeyAlgorithm: 'AES',
    hmacAlgorithm: 'HmacSHA256',
    cipher: 'AES/GCM/NoPadding',
    tagLength: 128,
    ivLength: 12,
  },
  hkdf: {
    salt: 'your-app-specific-salt-min-16-chars',
    encryptionInfo: 'your-app/encryption',
    hmacInfo: 'your-app/hmac',
  },
});

// Block compromised environments at startup
await SecuritySuite.protect({
  blockEmulator: true,
  blockDebugger: true,
  blockHooking: true,
  blockRoot: false,
});
```

---

## Security Detection

### One-shot report

```typescript
import { SecuritySuite } from 'react-native-security-suite';

const report = await SecuritySuite.getSecurityReport();
// report.riskLevel: 'low' | 'medium' | 'high'
// report.riskScore: 0–100
// report.device.isRooted, .isJailbroken, .isEmulator, .isSimulator
// report.runtime.debuggerAttached, .fridaDetected, .xposedDetected, …
// report.app.validSignature, .tampered, .buildType
```

### Targeted checks

```typescript
import { DeviceSecurity, RuntimeSecurity, AppIntegrity } from 'react-native-security-suite';

const isCompromised = await DeviceSecurity.isCompromised();     // root / jailbreak
const isEmulator   = await DeviceSecurity.isEmulator();
const environment  = await DeviceSecurity.getEnvironment();     // { isEmulator, isSimulator, indicators }

const isDebugged   = await RuntimeSecurity.isDebuggerAttached();
const isHooked     = await RuntimeSecurity.isHooked();          // Frida / Xposed / Substrate / Magisk

const integrity    = await AppIntegrity.verify();               // { validSignature, tampered, buildType, … }
```

### Policy enforcement

`protect()` throws `SecurityError` when a violation is detected.

```typescript
import { SecuritySuite, SecurityError, isSecurityError } from 'react-native-security-suite';

try {
  await SecuritySuite.protect({
    blockEmulator: true,
    blockDebugger: true,
    blockHooking: true,
    blockRoot: true,
    minRiskLevel: 'high', // also throw when riskLevel >= 'high'
  });
} catch (err) {
  if (isSecurityError(err)) {
    // err.code: 'EMULATOR_DETECTED' | 'DEBUGGER_DETECTED' | 'FRIDA_DETECTED' | …
    console.warn('Security violation:', err.code, err.details);
  }
}
```

**Detection signals:**

| Signal | Android | iOS |
|--------|---------|-----|
| Root / Jailbreak | RootBeer (20+ checks) | IOSSecuritySuite |
| Emulator | Build props, QEMU, sensors, telephony | `TARGET_OS_SIMULATOR`, hw.model, IOSSecuritySuite |
| Debugger | `Debug.isDebuggerConnected`, TracerPid | `P_TRACED` sysctl, IOSSecuritySuite |
| Hooking | `/proc/self/maps`, Frida ports/threads, Xposed, Magisk | Dyld inserts, loaded dylibs, Frida paths, Substrate |

---

## Threat Monitoring

Continuously poll for threats and react in real time.

```typescript
import { ThreatMonitor } from 'react-native-security-suite';
import type { ThreatEvent } from 'react-native-security-suite';

const monitor = ThreatMonitor.start({
  intervalMs: 30_000,       // poll every 30 s (default)
  minRiskLevel: 'medium',   // only fire for medium or high risk (default)
  runImmediately: true,     // run one check immediately on start (default)
  onThreat: (event: ThreatEvent) => {
    // event.type: 'root' | 'jailbreak' | 'emulator' | 'debugger' | 'hooking' | 'tamper' | 'risk-threshold'
    // event.report: SecurityReport
    // event.timestamp: number
    console.warn('Threat detected:', event.type);
    // e.g. navigate to an error screen or sign the user out
  },
  onError: (err) => console.error('ThreatMonitor error:', err),
});

// Later — e.g. on logout or unmount
monitor.stop();
```

---

## Cryptography

### Key exchange + encryption

```typescript
import { KeyExchange, Encryption } from 'react-native-security-suite';

// 1. Get client public key and send to server
const clientPublicKey = await KeyExchange.getX25519PublicKey();
// send clientPublicKey to your API …

// 2. Server responds with its public key → derive shared keys
const { encryptionKey, macKey } = await KeyExchange.x25519ComputeAndDeriveKeys({
  serverPublicKey: serverPublicKeyBase64,
  salt:            saltBase64,
  encryptionInfo:  btoa('my-app/encryption'),
  macInfo:         btoa('my-app/hmac'),
  hmacAlgorithm:   'HmacSHA256',
});

// 3. Encrypt / decrypt
const ciphertext = await Encryption.encryptAesGcm(plaintext, encryptionKey);
const plaintext2 = await Encryption.decryptAesGcm(ciphertext, encryptionKey);
```

ECDH (P-256) works the same way via `KeyExchange.getEcdhPublicKey()` and `KeyExchange.ecdhComputeAndDeriveKeys()`.

### Hashing

```typescript
import { Hashing } from 'react-native-security-suite';

const sha256 = await Hashing.hash('message', 'SHA-256');
const sha512 = await Hashing.hash('message', 'SHA-512');
```

### Digital signatures

```typescript
import { Signatures } from 'react-native-security-suite';

// Ed25519
const { privateKey, publicKey } = await Signatures.generateEd25519KeyPair();
const signature = await Signatures.signEd25519('message', privateKey);
const valid     = await Signatures.verifyEd25519('message', signature, publicKey);

// ECDSA P-256
const ecKeyPair = await Signatures.generateEcdsaKeyPair();
const ecSig     = await Signatures.signEcdsa('message', ecKeyPair.privateKey);
const ecValid   = await Signatures.verifyEcdsa('message', ecSig, ecKeyPair.publicKey);
```

### CSPRNG

```typescript
import { Random } from 'react-native-security-suite';

const bytes = await Random.randomBytes(32);   // base64-encoded, 32 random bytes
const uuid  = await Random.randomUUID();      // 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
```

---

## JWS Request Signing

### Symmetric (HS256 / HS384 / HS512)

```typescript
import { generateJWS } from 'react-native-security-suite';

const jws = await generateJWS({
  algorithm: 'HS256',
  secret: 'session-secret-from-backend',
  payload: { amount: 100, currency: 'USD' },
  headers: { kid: 'key-1', request_id: 'req-abc' },
});
// compact: <header>.<payload>.<signature>
```

### Asymmetric (ES256 / EdDSA)

```typescript
import { generateAsymmetricJWS, Signatures } from 'react-native-security-suite';

const { privateKey } = await Signatures.generateEd25519KeyPair();

const jws = await generateAsymmetricJWS({
  algorithm: 'EdDSA',
  privateKey,
  payload: { userId: 42 },
  headers: { kid: 'ed-key-1' },
});
```

```typescript
// ES256 (ECDSA P-256)
const { privateKey: ecPrivKey } = await Signatures.generateEcdsaKeyPair();

const jws = await generateAsymmetricJWS({
  algorithm: 'ES256',
  privateKey: ecPrivKey,
  payload: { action: 'transfer' },
});
```

### Auto-signing on `fetch`

```typescript
import { fetch } from 'react-native-security-suite';

await fetch('https://api.example.com/payments', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: { amount: 100 },
  jws: {
    algorithm: 'HS256',
    secret: 'session-secret-from-backend',
    headers: {
      kid: 'key-1',
      request_id: crypto.randomUUID(),
      timestamp: Date.now(),
    },
    headerName: 'X-Request-Signature', // default
    detached: false,
  },
  certificates: ['sha256/AAAA…='],
  validDomains: ['api.example.com'],
});
```

When `jws.payload` is omitted, native code builds a canonical payload from `method`, `path`, `query`, `bodyHash`, and any `timestamp`/`nonce`/`request_id` from `jws.headers`.

---

## Secure Storage

### Basic usage

```typescript
import { SecureStorage } from 'react-native-security-suite';

await SecureStorage.setItem('token', 'eyJhbGc…');
const token = await SecureStorage.getItem('token');
await SecureStorage.removeItem('token');
await SecureStorage.clear();
```

Values are encrypted at rest — AES-GCM via EncryptedSharedPreferences on Android; Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` on iOS. No hardcoded keys or salts.

### Biometric-gated items

Require biometric authentication before reading or writing a value.

```typescript
import { Storage } from 'react-native-security-suite';

// Store — prompts biometric before writing
await Storage.setItem('secret', 'my-value', {
  requireBiometric: true,
  prompt: 'Authenticate to save your secret',
});

// Read — prompts biometric before returning the value
const value = await Storage.getItem('secret', {
  requireBiometric: true,
  prompt: 'Authenticate to read your secret',
});

// Check availability first
const available = await Storage.biometricIsAvailable();
```

### Key expiry

```typescript
import { Storage } from 'react-native-security-suite';

const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
await Storage.setItemWithExpiry('session', sessionToken, expiresAt);

// Returns null if expired; does not delete the key
const session = await Storage.getItemIfValid('session');

// Remove only if expired (returns true when removed)
const removed = await Storage.removeIfExpired('session');
```

### Key rotation

```typescript
import { Storage } from 'react-native-security-suite';

// Atomically replace the value and increment the version counter
await Storage.rotateItem('api-key', newApiKey);

// Inspect version and expiry metadata
const meta = await Storage.getMetadata('api-key');
// { version: 2, createdAt: 1234567890, expiresAt?: … }
```

---

## Network Security

### Global fetch interceptor

Route all outbound `fetch` calls through the native SSL-pinned transport.

```typescript
import { NetworkSecurity } from 'react-native-security-suite';

// Configure once at app startup
NetworkSecurity.configurePinning({
  certificates: ['sha256/AAAA…=', 'sha256/BBBB…='],
  validDomains: ['api.example.com'],
});

// Install the interceptor — returns an uninstall function
const uninstall = NetworkSecurity.installFetchInterceptor();

// Any subsequent fetch('https://api.example.com/…') is now pinned
const res = await fetch('https://api.example.com/data');

// Restore original fetch when done (e.g. in tests)
uninstall();
```

### Per-instance pinned transport

Use `createPinnedFetch` when you want pinning only for specific calls.

```typescript
import { NetworkSecurity } from 'react-native-security-suite';

const pinnedFetch = NetworkSecurity.createPinnedFetch({
  certificates: ['sha256/AAAA…='],
  validDomains: ['api.example.com'],
});

const res = await pinnedFetch('https://api.example.com/resource', {
  method: 'GET',
  headers: { Authorization: 'Bearer token' },
});
```

### SSL pinning with the legacy `fetch`

```typescript
import { fetch } from 'react-native-security-suite';

await fetch('https://api.example.com/secure', {
  method: 'GET',
  headers: {},
  certificates: ['sha256/AAAA…='],
  validDomains: ['api.example.com'],
});
```

---

## Screen Protection

### Protect individual views from screenshots

```tsx
import { SecureView } from 'react-native-security-suite';

function PaymentScreen() {
  return (
    <SecureView style={{ flex: 1 }}>
      <Text>Card number: •••• •••• •••• 4242</Text>
    </SecureView>
  );
}
```

### Background / app-switcher privacy

Prevent the OS from capturing sensitive content in the app switcher.

**Component approach** — wrap your root navigator:

```tsx
import { BackgroundProtection } from 'react-native-security-suite';

function App() {
  return (
    <BackgroundProtection
      backgroundColor="#1a1a1a"
      useNativeWindowSecure={true}  // also sets FLAG_SECURE / UIVisualEffectView
    >
      <NavigationContainer>…</NavigationContainer>
    </BackgroundProtection>
  );
}
```

**Hook approach** — conditionally hide content:

```tsx
import { useBackgroundProtection } from 'react-native-security-suite';

function SensitiveScreen() {
  const isBackground = useBackgroundProtection();

  if (isBackground) {
    return <View style={{ flex: 1, backgroundColor: '#000' }} />;
  }

  return <YourSensitiveContent />;
}
```

**Imperative native API:**

```typescript
import { ScreenSecurity } from 'react-native-security-suite';

// Enable FLAG_SECURE (Android) or blur overlay (iOS)
await ScreenSecurity.setWindowSecure(true);

// Remove when no longer needed
await ScreenSecurity.setWindowSecure(false);
```

---

## Clipboard Protection

Automatically clear sensitive data from the clipboard.

```typescript
import { ClipboardGuard } from 'react-native-security-suite';

// Copy and auto-clear after 30 seconds
ClipboardGuard.copy('4111 1111 1111 1111', { clearAfterMs: 30_000 });

// Cancel the pending auto-clear (e.g. user navigated away)
ClipboardGuard.cancelAutoClear();

// Clear immediately
ClipboardGuard.clear();

// Read clipboard
const text = await ClipboardGuard.read();
```

Requires `@react-native-clipboard/clipboard` (recommended) or the deprecated built-in `Clipboard` from `react-native`.

---

## Device Attestation

Cryptographically verify to your server that a request originated from a genuine, unmodified app instance.

```typescript
import { DeviceAttestation } from 'react-native-security-suite';

// 1. Check support
const supported = await DeviceAttestation.isSupported();

// 2. Fetch a challenge from your server, then attest the device
const { platform, attestation, keyId } = await DeviceAttestation.attestDevice(
  challengeHashBase64  // SHA-256 of server nonce (iOS) or raw nonce (Android)
);

// 3. Send { platform, attestation, keyId } to your server for verification

// 4. For subsequent requests (iOS only), generate an assertion
const { assertion } = await DeviceAttestation.generateAssertion(
  keyId!,
  requestHashBase64  // SHA-256 of the request data
);
```

**iOS (App Attest)**
- Requires the "App Attest" capability in your Apple Developer account
- `keyId` is a persistent key identifier stored by the OS
- Verification uses Apple's public attestation root CA

**Android (Play Integrity)**
- Requires `com.google.android.play:integrity` as an `implementation` dependency
- Returns a Play Integrity token — verify server-side via Google's API
- No persistent key; each call produces a fresh token from a server nonce

---

## API Reference

### SecuritySuite

| Method | Description |
|--------|-------------|
| `initialize(config)` | Initialize once at startup. Required before using crypto or HKDF-derived features. |
| `configure(config)` | Update behavior config after initialization. |
| `getSecurityReport()` | Full `SecurityReport` with device, runtime, app integrity, and risk score. |
| `protect(policy?)` | Throws `SecurityError` if any policy condition is met. |
| `isInitialized()` | `true` if `initialize()` has been called. |

### DeviceSecurity

| Method | Description |
|--------|-------------|
| `isCompromised()` | `true` if device is rooted (Android) or jailbroken (iOS). |
| `isRooted()` | Android only. |
| `isJailbroken()` | iOS only. |
| `isEmulator()` | `true` if running on an emulator or simulator. |
| `getEnvironment()` | `{ isEmulator, isSimulator, indicators: string[] }` |
| `protectEnvironment(policy?)` | Throws `SecurityError` when `blockEmulator: true`. |

### RuntimeSecurity

| Method | Description |
|--------|-------------|
| `detect()` | `RuntimeThreatReport` — all runtime signals. |
| `isDebuggerAttached()` | `true` if a debugger is connected. |
| `isHooked()` | `true` if Frida, Xposed, Substrate, or Magisk is detected. |
| `protect(policy?)` | Throws `SecurityError` on configured violations. |

### AppIntegrity

| Method | Description |
|--------|-------------|
| `verify()` | `AppIntegrityReport` — signature validity, tamper state, build type, installer info. |

### ThreatMonitor

| Method | Description |
|--------|-------------|
| `start(options)` | Begin polling. Returns `{ stop() }`. |

`ThreatMonitorOptions`: `intervalMs` (default 30 000), `minRiskLevel` (default `'medium'`), `onThreat`, `onError`, `runImmediately` (default `true`).

### Crypto modules

| Export | Methods |
|--------|---------|
| `Hashing` | `hash(input, algorithm)` — `'SHA-256'` or `'SHA-512'` |
| `KDF` | `deriveKeys(params)` — HKDF with HMAC |
| `KeyExchange` | `getEcdhPublicKey()`, `ecdhComputeAndDeriveKeys(params)`, `getX25519PublicKey()`, `x25519ComputeAndDeriveKeys(params)` |
| `Encryption` | `encryptAesGcm(plaintext, keyBase64)`, `decryptAesGcm(ciphertext, keyBase64)` |
| `Signatures` | `generateEd25519KeyPair()`, `signEd25519(msg, pk)`, `verifyEd25519(msg, sig, pub)`, `generateEcdsaKeyPair()`, `signEcdsa(msg, pk)`, `verifyEcdsa(msg, sig, pub)` |
| `Random` | `randomBytes(count)` → base64 string, `randomUUID()` → UUID v4 string |
| `CryptoManager` | Lower-level wrapper (same operations, single import) |

### JWS

| Export | Description |
|--------|-------------|
| `generateJWS(options)` | Symmetric JWS — HS256, HS384, HS512. Requires `secret`. |
| `generateAsymmetricJWS(options)` | Asymmetric JWS — ES256 (ECDSA P-256) or EdDSA (Ed25519). Requires `privateKey`. |

`GenerateJWSOptions`: `secret`, `algorithm?`, `payload?`, `headers?`  
`GenerateAsymmetricJWSOptions`: `privateKey`, `algorithm` (`'ES256'` or `'EdDSA'`), `payload?`, `headers?`, `detached?`

### SecureStorage (legacy export)

The top-level `SecureStorage` export provides basic CRUD without lifecycle or biometric options.

| Method | Description |
|--------|-------------|
| `setItem(key, value)` | Store a value. |
| `getItem(key)` | Retrieve a value or `null`. |
| `removeItem(key)` | Delete a key. |
| `getAllKeys()` | All stored keys. |
| `clear()` | Delete all entries. |
| `multiSet(pairs)` | Batch write. |
| `multiGet(keys)` | Batch read. |
| `multiRemove(keys)` | Batch delete. |

### Storage (new namespace with biometric + lifecycle)

Extends `SecureStorage` with biometric options, expiry, and rotation. All methods take an optional `SecureStorageOptions` argument (`requireBiometric?`, `prompt?`, `subtitle?`).

| Method | Description |
|--------|-------------|
| `setItem(key, value, options?)` | Write; biometric auth if `requireBiometric: true`. |
| `getItem(key, options?)` | Read; biometric auth if `requireBiometric: true`. |
| `removeItem(key)` | Delete a key. |
| `getAllKeys()` | All stored keys (excludes internal metadata keys). |
| `clear()` | Delete all entries. |
| `multiSet/Get/Remove` | Batch operations (no biometric option). |
| `biometricIsAvailable()` | Check biometric hardware availability. |
| `setItemWithExpiry(key, value, expiresAt, options?)` | Store with expiry date. |
| `getItemIfValid(key, options?)` | Read; returns `null` if expired. |
| `removeIfExpired(key)` | Delete if past expiry. Returns `true` when removed. |
| `rotateItem(key, newValue, options?)` | Atomically replace and increment version. |
| `getMetadata(key)` | `{ version, createdAt, expiresAt? }` or `null`. |

### NetworkSecurity

| Method | Description |
|--------|-------------|
| `configurePinning(config)` | Set a global `PinningConfig` used by `installFetchInterceptor`. |
| `clearPinningConfig()` | Remove the global config. |
| `installFetchInterceptor(config?)` | Patch `global.fetch`. Returns an uninstall function. |
| `uninstallFetchInterceptor()` | Restore original `global.fetch`. |
| `createPinnedFetch(config)` | Return a standalone pinned fetch function. |

`PinningConfig`: `{ certificates: string[], validDomains: string[] }`

### ClipboardGuard

| Method | Description |
|--------|-------------|
| `copy(text, options?)` | Write to clipboard. `options.clearAfterMs` schedules auto-clear. |
| `clear()` | Immediately clear clipboard and cancel any pending auto-clear. |
| `cancelAutoClear()` | Cancel pending auto-clear without wiping the clipboard. |
| `read()` | Return clipboard contents. |

### Screen

| Export | Description |
|--------|-------------|
| `SecureView` | Component that blocks screenshots and screen recordings per-view. |
| `BackgroundProtection` | Component that overlays a privacy screen when the app is inactive. Props: `backgroundColor`, `opacity`, `useNativeWindowSecure`. |
| `useBackgroundProtection(options?)` | Hook that returns `true` while the app is not active. |
| `ScreenSecurity.setWindowSecure(enabled)` | Imperatively enable/disable native window security. |

### DeviceAttestation

| Method | Description |
|--------|-------------|
| `isSupported()` | `true` if App Attest (iOS) or Play Services (Android) is available. |
| `generateKey()` | iOS: generate and persist an App Attest key; returns `keyId`. Android: no-op. |
| `attestKey(keyId, clientDataHash)` | iOS: attest key against Apple. Returns base64 CBOR attestation object. |
| `generateAssertion(keyId, clientDataHash)` | iOS: generate request assertion. Returns `{ assertion, keyId }`. |
| `getPlayIntegrityToken(nonce)` | Android: request Play Integrity token. iOS: returns `''`. |
| `attestDevice(challengeHash)` | Unified helper — App Attest on iOS, Play Integrity on Android. |

### Errors

```typescript
import { SecurityError, SecurityErrorCode, isSecurityError } from 'react-native-security-suite';

// SecurityErrorCode values:
// ROOT_DETECTED, JAILBREAK_DETECTED, EMULATOR_DETECTED
// DEBUGGER_DETECTED, FRIDA_DETECTED, XPOSED_DETECTED, SUBSTRATE_DETECTED, MAGISK_DETECTED
// SECURITY_RISK_THRESHOLD, SSL_PINNING_FAILED
// BIOMETRIC_UNAVAILABLE, BIOMETRIC_AUTH_FAILED
// ATTESTATION_UNSUPPORTED, ATTESTATION_ERROR
// NETWORK_PINNING_FAILED, CLIPBOARD_UNAVAILABLE, CRYPTO_RANDOM_ERROR
// SECURE_STORAGE_UNAVAILABLE, CRYPTO_KEY_NOT_FOUND, CONFIGURATION_ERROR
```

---

## Security Best Practices

1. **Call `SecuritySuite.protect()` at startup** before rendering sensitive UI. Pair client-side checks with server-side policy enforcement — client checks are advisory.

2. **Use `Storage` (not `SecureStorage`) for sensitive long-lived keys.** Add `requireBiometric: true` for values like encryption keys or signing secrets. Use `setItemWithExpiry` for session tokens.

3. **Pin certificates in production.** Use `NetworkSecurity.installFetchInterceptor()` once at startup so all `fetch` calls are covered. Include a backup pin to survive certificate rotation.

4. **Treat JWS secrets as short-lived.** `jws.secret` on `fetch` is visible in JS memory. Use a server-issued, request-scoped or session-scoped secret, or use asymmetric signing (`ES256`/`EdDSA`) with a hardware-backed private key.

5. **Combine `BackgroundProtection` with `ScreenSecurity.setWindowSecure(true)`** for defense in depth — the component handles JS-side hiding; the native flag prevents OS-level capture.

6. **Auto-clear clipboard.** Any value copied to the clipboard via `ClipboardGuard.copy` should use `clearAfterMs` — 30 seconds is a reasonable default for sensitive content.

7. **Verify attestation server-side.** `DeviceAttestation.attestDevice()` returns an opaque blob. Your backend must verify it with Apple or Google before trusting it. Never use the client-side result alone to grant access.

8. **Start `ThreatMonitor` after authentication,** not at app open. A 30-second interval is a reasonable balance between security and battery life.

---

## Troubleshooting

**iOS pod install / build fails:**
```bash
cd ios && pod install
npx react-native run-ios
```

**Android build fails:**
```bash
cd android && ./gradlew clean
npx react-native run-android
```

**Metro cache issues:**
```bash
npx react-native start --reset-cache
```

**Biometric prompt not appearing:** Make sure the host Activity extends `FragmentActivity` (the default in React Native). Biometric requires Android API 28+.

**App Attest returns "unsupported":** `DCAppAttestService.isSupported` is `false` on the iOS Simulator and on devices running iOS < 14. Test on a real device.

**Play Integrity returns an error:** Ensure `com.google.android.play:integrity` is in your app's (not the library's) `build.gradle` as `implementation`, and that the device has Google Play Services.

---

## Contributing

```bash
git clone https://github.com/mohamadnavabi/react-native-security-suite.git
cd react-native-security-suite
yarn install
cd example && yarn install && cd ..
yarn example android  # or ios
```

Run tests: `yarn test`  
Type check: `yarn typecheck`  
Lint: `yarn lint`

---

## License

MIT — see [LICENSE](LICENSE).

---

## Acknowledgments

- [IOSSecuritySuite](https://github.com/securing/IOSSecuritySuite) — jailbreak and runtime detection on iOS
- [RootBeer](https://github.com/scottyab/rootbeer) — root detection on Android
- [Chucker](https://github.com/ChuckerTeam/chucker) — Android network monitor
- [Pulse](https://github.com/kean/Pulse) — iOS network monitor

---

Issues: [github.com/mohamadnavabi/react-native-security-suite/issues](https://github.com/mohamadnavabi/react-native-security-suite/issues)  
Author: Mohammad Navabi — 7navabi@gmail.com
