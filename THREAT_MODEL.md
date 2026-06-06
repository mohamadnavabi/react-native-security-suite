# Threat Model — react-native-security-suite

## Scope

This document describes threats addressed by **react-native-security-suite** (RSS) when integrated into a React Native mobile application handling sensitive data (banking, fintech, healthcare, enterprise).

### In scope

- Client-side device and runtime compromise detection
- Transport security (TLS + certificate/public-key pinning)
- At-rest secret storage (Keychain / Android Keystore)
- Request integrity signing (JWS)
- Key agreement and symmetric encryption for session data
- Screen capture / screenshot mitigation
- Development-only network inspection with redaction

### Out of scope

- Server-side authentication and authorization
- Backend fraud scoring and device attestation verification (Play Integrity / App Attest token validation)
- Protection against a fully compromised host OS with kernel-level hooks that patch all detection routines
- Protection against physical extraction of device storage with unlocked bootloader and extracted keys
- JavaScript bundle obfuscation or Hermes bytecode protection
- Supply-chain attacks on npm dependencies (consumer responsibility)

## Assets

| Asset | Location | Sensitivity |
|-------|----------|-------------|
| Refresh / access tokens | SecureStorage, memory | Critical |
| Private signing keys | OS Keystore / Secure Enclave | Critical |
| Session shared secrets | Native memory (target state) | High |
| User PII displayed on screen | UI layer | High |
| API credentials in transit | TLS + pinning | High |
| JWS HMAC secrets (legacy) | JS memory | Medium–High |
| Device identifiers | Native APIs | Low–Medium |

## Adversaries

| Adversary | Capability | Goal |
|-----------|------------|------|
| Casual user | Screenshots, backup extraction | Share credentials |
| Rooted/jailbroken user | Hook native APIs, read app sandbox | Extract secrets, bypass checks |
| Reverse engineer | Static analysis, Frida, Xposed | Patch detection, MITM, clone app |
| Network attacker | MITM on untrusted Wi‑Fi | Intercept/modify API traffic |
| Malware / sideload | Repackaged APK/IPA | Phishing, credential theft |
| Insider (dev build) | Chucker/Pulse logs | Leak prod-like data in staging |

## Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                     Backend (trusted)                        │
│  Verifies JWS, attestation tokens, risk signals             │
└──────────────────────────▲──────────────────────────────────┘
                           │ TLS + pinning + JWS
┌──────────────────────────┴──────────────────────────────────┐
│              Native layer (partially trusted)                │
│  Keystore, Keychain, SSL delegate, threat detectors         │
└──────────────────────────▲──────────────────────────────────┘
                           │ React Native bridge
┌──────────────────────────┴──────────────────────────────────┐
│           JavaScript layer (untrusted under hooking)         │
│  UI, business logic — assume readable/modifiable              │
└─────────────────────────────────────────────────────────────┘
```

**Design principle:** Secrets and private keys must not cross into JavaScript unless strictly necessary. Detection results are advisory on the client; enforcement belongs on the server.

## Threats and mitigations

### T1 — Rooted / jailbroken device

- **Risk:** Key extraction, hooking, SSL bypass
- **Mitigation:** `DeviceSecurity.isCompromised()`, aggregated in `SecuritySuite.getSecurityReport()`
- **Limitation:** Determined attackers bypass client checks; server must enforce policy

### T2 — Runtime instrumentation (Frida, Xposed, Substrate)

- **Risk:** Hook `deviceHasSecurityRisk`, `fetch`, crypto APIs
- **Mitigation:** `RuntimeSecurity.detect()` — multi-signal native checks, periodic re-evaluation
- **Limitation:** Cat-and-mouse; combine with server-side behavioral analytics

### T3 — Man-in-the-middle

- **Risk:** Stolen session tokens, modified transactions
- **Mitigation:** HTTPS-only fetch, SPKI pinning, backup pins, structured `SSL_PINNING_FAILED` errors
- **Limitation:** Pinning fails open if misconfigured; user-installed CAs on some Android builds

### T4 — Secret exposure in JS heap

- **Risk:** `getSharedKey()` currently returns derived key to JS
- **Mitigation (v1.x):** Native-only encrypt/decrypt; optional `returnSharedKey: false` (default)
- **Limitation:** Strings returned from `getItem` still exist in JS until GC

### T5 — Screenshot / screen recording

- **Risk:** OTP, account numbers captured
- **Mitigation:** `ScreenSecurity.enable()`, `SecureView`
- **Limitation:** External cameras; iOS cannot fully block all recording in all OS versions

### T6 — Repackaged / tampered app

- **Risk:** Fake banking app
- **Mitigation:** `AppIntegrity.verify()` — signature, installer, debuggable flag
- **Limitation:** Client checks bypassable; use Play Integrity / App Attest server-side

### T7 — Emulator / simulator abuse

- **Risk:** Automated fraud at scale
- **Mitigation:** `DeviceSecurity.getEnvironment()`
- **Limitation:** Some emulators evade fingerprint checks

### T8 — Debug logging leakage

- **Risk:** Chucker/Pulse capture tokens in dev builds
- **Mitigation:** Logger disabled in release; configurable redaction lists
- **Limitation:** Developers can re-enable; discipline required

### T9 — Clipboard sniffing

- **Risk:** OTP pasted and read by other apps
- **Mitigation:** `SecureClipboard.setString()` with auto-expiry
- **Limitation:** OS clipboard APIs vary; Android 13+ shows paste indicators

### T10 — Weak client-side JWS (HS*)

- **Risk:** Shared secret extracted from binary
- **Mitigation:** Prefer ES256/EdDSA with Keystore keys; server verifies public key / JWKS
- **Limitation:** HS* retained for backward compatibility only

## Security goals (target v1.0)

1. **Confidentiality:** Tokens at rest in hardware-backed storage; TLS + pinning in transit
2. **Integrity:** JWS on requests; app signature verification
3. **Availability:** Graceful degradation when Keystore unavailable (clear errors, no silent fallback to plaintext)
4. **Detectability:** Structured security report for server risk engines
5. **Minimal exposure:** Private keys never exported; shared secrets stay native when possible

## Known limitations

- Client-side detection is **best-effort**, not proof of security
- React Native bridge strings are copies; zeroization in JS is not guaranteed
- Hermes/JSC heap is inspectable under debugger
- Play Integrity / DeviceCheck require Google/Apple developer setup and server verification
- Certificate Transparency validation adds latency and network dependency
- Biometric-gated Keychain access requires user interaction per read (by design)

## Recommended server-side pairing

1. Accept `SecuritySuite.getSecurityReport()` payload on login / sensitive actions
2. Verify JWS with server-held secrets or client public keys (for ES256/EdDSA)
3. Validate Play Integrity / App Attest tokens for high-value operations
4. Rate-limit and block elevated `riskLevel: "high"` devices per policy
5. Rotate pinning backup keys before primary cert expiry

See [SECURITY.md](./SECURITY.md) and [docs/](./docs/) for implementation guidance.
