# Phase 1 — Detection APIs

Phase 1 adds namespaced detection APIs without breaking v0.9 exports.

## New exports

```typescript
import {
  SecuritySuite,
  DeviceSecurity,
  RuntimeSecurity,
  AppIntegrity,
  Crypto,
  SecurityError,
  SecurityErrorCode,
} from 'react-native-security-suite';
```

## Example

```typescript
const report = await SecuritySuite.getSecurityReport();

if (report.riskLevel === 'high') {
  // Server-side policy: block, step-up auth, or limit features
}

const runtime = await RuntimeSecurity.detect();
const integrity = await AppIntegrity.verify();
const environment = await DeviceSecurity.getEnvironment();

// Protection (throws SecurityError on configured threats)
await SecuritySuite.protect({
  blockEmulator: true,
  blockDebugger: true,
  blockHooking: true,
});

// Secure key exchange (does not return key to JS by default)
await Crypto.establishSharedKey(serverPublicKey);
await encryptBySharedKey('secret message'); // legacy bridge encrypt
```

## Native bridge methods

| Method | Purpose |
|--------|---------|
| `runtimeDetect()` | Runtime instrumentation signals |
| `appIntegrityVerify()` | APK/IPA integrity |
| `deviceGetEnvironment()` | Emulator/simulator indicators |
| `establishSharedKey()` | Native-only shared key derivation |

## Platform limitations

- **Detection is heuristic** — determined attackers can bypass client checks.
- **Android missing sensors** — some physical devices lack gyroscope; may appear in `indicators`.
- **Android tampered** — sideloaded release builds flag `installerTrusted: false`.
- **iOS App Integrity** — no installer API; `installerTrusted` omitted on iOS.
- **iOS simulator** — always detected via `TARGET_OS_SIMULATOR`.
- **Frida port scan** — 300ms timeout per port on a background native thread.

See [migration-v1.md](./migration-v1.md) for upgrade notes.
