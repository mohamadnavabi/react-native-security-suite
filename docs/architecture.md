# Architecture — v1.0 Proposal

## Overview

The library evolves from a **monolithic native module + flat exports** to a **layered security framework** with namespaced TypeScript APIs, a thin bridge, and domain-specific native modules — while preserving backward compatibility via re-exports.

## Current state (v0.9.x)

```
JavaScript (src/index.tsx)
        │
        ▼
SecuritySuite NativeModule (single bridge)
        │
        ├── RootBeer / IOSSecuritySuite
        ├── EcdhKeyStore / KeychainHelper
        ├── SecureStorageNative
        ├── JWSGenerator (HS*)
        ├── SslPinning / SSLPinning + fetch
        └── SecureView
```

**Gaps identified:**

- `getSharedKey()` returns derived encryption key to JavaScript
- iOS uses P-256 ECDH; Android Keystore uses P-256 but TS advertises X25519
- No runtime threat detection beyond root/jailbreak
- No app integrity or emulator APIs
- SecureStorage lacks biometric gating and namespaces
- JWS is HMAC-only with secrets in JS
- SSL pinning lacks backup pins and structured errors
- Screen protection is view-only, no programmatic API

## Target architecture (v1.0)

```
┌─────────────────────────────────────────────────────────────────┐
│                     Application (React Native)                   │
└───────────────────────────────┬─────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────┐
│  TypeScript Public Layer                                         │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────────────────┐  │
│  │ SecuritySuite│ │ Namespaces   │ │ Legacy re-exports (0.9)  │  │
│  │ .configure  │ │ DeviceSecurity│ │ fetch, getPublicKey, ... │  │
│  │ .getReport  │ │ RuntimeSecurity│ └──────────────────────────┘  │
│  └─────────────┘ │ AppIntegrity  │                                │
│                  │ SecureStorage │                                │
│                  │ Crypto, JWS   │                                │
│                  │ SecureNetwork │                                │
│                  │ ScreenSecurity│                                │
│                  │ SecureClipboard│                               │
│  ┌───────────────▼───────────────────────────────────────────┐  │
│  │ errors.ts — SecurityError, SecurityErrorCode              │  │
│  │ native/SecuritySuiteNative.ts — typed bridge                │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────┬─────────────────────────────────┘
                                │ React Native Bridge
┌───────────────────────────────▼─────────────────────────────────┐
│  Native Orchestrator                                             │
│  SecuritySuiteModule / SecuritySuite.swift (facade)              │
└───┬─────────┬─────────┬─────────┬─────────┬─────────┬───────────┘
    │         │         │         │         │         │
    ▼         ▼         ▼         ▼         ▼         ▼
 Runtime   Integrity  Device   Crypto    Network   Screen
 Detection Detection  Env      + JWS     + Pinning  + Storage
```

## TypeScript module layout

```
src/
├── index.tsx                 # Public entry + backward compat
├── configure.ts              # Global defaults
├── errors.ts                 # SecurityErrorCode enum
├── types/
│   ├── securityReport.ts
│   ├── secureStorage.ts
│   └── sslPinning.ts
├── namespaces/
│   ├── DeviceSecurity.ts
│   ├── RuntimeSecurity.ts
│   ├── AppIntegrity.ts
│   ├── SecureStorage.ts
│   ├── Crypto.ts
│   ├── JWS.ts
│   ├── SecureNetwork.ts
│   ├── ScreenSecurity.ts
│   └── SecureClipboard.ts
├── native/
│   └── SecuritySuiteNative.ts
├── jws.ts                    # Existing — extended for ES256/EdDSA
├── SecureView.tsx
└── helpers.ts
```

## Native module layout

### Android (`android/src/main/java/com/securitysuite/`)

```
security/
├── runtime/
│   ├── FridaDetector.java
│   ├── XposedDetector.java
│   ├── MagiskDetector.java
│   ├── DebuggerDetector.java
│   ├── PortScanner.java
│   └── NativeLibraryScanner.java
├── integrity/
│   ├── ApkSignatureVerifier.java
│   ├── InstallerVerifier.java
│   ├── DebuggableChecker.java
│   └── PlayIntegrityClient.java      # optional, requires Play Services
├── device/
│   ├── EmulatorDetector.java
│   └── RootDetector.java             # wraps RootBeer + custom signals
crypto/
├── KeystoreKeyManager.java           # unified key alias CRUD
├── X25519KeyStore.java               # API 31+ / fallback P-256
├── SecureRandomProvider.java
└── NativeEncryptor.java              # encrypt/decrypt without exposing key
storage/
├── SecureStorageNative.java          # extended: biometric, namespace
└── BiometricPromptHelper.java
network/
├── Sslpinning.java                   # extended errors + backup pins
├── CertificateTransparency.java      # optional
└── BodyRedactor.java
screen/
├── ScreenSecurityManager.java
└── SecureWindowHelper.java           # existing
jws/
├── JWSGenerator.java                 # HS* + ES256 via AndroidKeyStore
└── Ed25519Signer.java                # API 33+ / BouncyCastle optional
```

### iOS (`ios/`)

```
Security/
├── Runtime/
│   ├── FridaDetector.swift
│   ├── SubstrateDetector.swift
│   ├── DebuggerDetector.swift
│   └── DylibScanner.swift
├── Integrity/
│   ├── CodeSigningVerifier.swift
│   ├── BundleVerifier.swift
│   └── AppAttestClient.swift         # optional
├── Device/
│   ├── SimulatorDetector.swift
│   └── JailbreakDetector.swift       # IOSSecuritySuite + custom
Crypto/
├── KeychainKeyManager.swift
├── X25519KeyAgreement.swift            # CryptoKit Curve25519
├── SecureEnclaveSigner.swift         # ES256
└── NativeEncryptor.swift
Storage/
├── SecureStorageNative.swift         # extended access control
└── LAContextHelper.swift             # biometric
Network/
├── SslPinning.swift
└── NetworkRedactor.swift
Screen/
├── ScreenSecurityManager.swift
└── CaptureObserver.swift
JWS/
├── JWSGenerator.swift                # HS* + ES256/EdDSA
└── CanonicalJSON.swift
```

## Bridge design

**Option A (recommended for v1.0):** Single facade module with namespaced method prefixes to avoid multiple bridge registrations:

```java
@ReactMethod void runtimeDetect(Promise promise);
@ReactMethod void appIntegrityVerify(Promise promise);
@ReactMethod void deviceGetEnvironment(Promise promise);
@ReactMethod void securityGetReport(Promise promise);
```

**Option B (v1.1+):** Turbo Modules with codegen for type safety and lazy loading.

## Risk scoring engine

Implemented in TypeScript (`src/risk/score.ts`) so weights are tunable without native releases:

| Signal | Weight |
|--------|--------|
| Root/jailbreak | 40 |
| Frida/debugger | 35 |
| Emulator | 20 |
| App tampered | 50 |
| Debug build | 15 |
| Xposed/Substrate | 30 |

```typescript
riskScore = min(100, sum(weights for true signals))
riskLevel = score >= 70 ? 'high' : score >= 35 ? 'medium' : 'low'
```

## Threading & performance

- Detection APIs run on background native queues; results marshalled to JS
- `getSecurityReport()` parallelizes independent checks via `Promise.all`
- Port scanning and dylib enumeration cached for 30s to avoid UI jank
- Crypto operations never block the main thread

## Testing strategy

| Layer | Approach |
|-------|----------|
| TypeScript | Unit tests for validation, risk scoring, error mapping |
| Android | Robolectric for storage/JWS; instrumented tests for Keystore |
| iOS | XCTest for JWS/canonical JSON; simulator for Keychain |
| Integration | Example app "Security Dashboard" screen |

## Rollout phases

1. **Phase 1** — Namespaces, errors, `getSecurityReport`, runtime/integrity/emulator (read-only detection)
2. **Phase 2** — SecureStorage biometric, Crypto namespace, native-only key exchange
3. **Phase 3** — ES256/EdDSA JWS, SSL pin rotation, ScreenSecurity API, SecureClipboard
4. **Phase 4** — Play Integrity, App Attest, Certificate Transparency (optional)
