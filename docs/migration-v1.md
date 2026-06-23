# Migration Guide — v0.9.x → v1.0

## Overview

v1.0 introduces namespaced APIs and enhanced security defaults. **All v0.9 exports remain available** — no breaking changes for existing imports.

## Import changes (recommended)

```typescript
// Before (still works)
import { fetch, SecureStorage, deviceHasSecurityRisk } from 'react-native-security-suite';

// After (recommended)
import {
  SecuritySuite,
  DeviceSecurity,
  RuntimeSecurity,
  SecureStorage,
  SecureNetwork,
} from 'react-native-security-suite';
```

## API mapping

| v0.9 | v1.0 equivalent |
|------|-----------------|
| `deviceHasSecurityRisk()` | `DeviceSecurity.isCompromised()` or `report.device.isRooted \|\| report.device.isJailbroken` |
| `fetch()` | `SecureNetwork.fetch()` (alias preserved) |
| `getPublicKey(options?)` | `Crypto.getPublicKey(options?)` |
| `getSharedKey()` | `Crypto.establishSharedKey()` — **does not return key by default** |
| `encryptBySharedKey()` | `Crypto.encrypt()` |
| `decryptBySharedKey()` | `Crypto.decrypt()` |
| `generateJWS()` | `JWS.generate()` |
| `SecureView` | `SecureView` + `ScreenSecurity.enable()` |
| `obfuscate()` / `deobfuscate()` | Unchanged (still not for secrets at rest) |

## Breaking behavior changes (opt-in)

These apply only when using new APIs or explicit configuration:

### 1. Shared key no longer returned to JS

```typescript
// v0.9 — key returned (avoid in new code)
const key = await getSharedKey(serverPublicKey);

// v1.0 — default: native-only
await Crypto.establishSharedKey(serverPublicKey, { alias: 'session' });
const ciphertext = await Crypto.encrypt('secret', { alias: 'session' });

// Opt-in legacy (deprecated)
await Crypto.establishSharedKey(serverPublicKey, { returnSharedKey: true });
```

### 2. SecureStorage options object

```typescript
// v0.9
await SecureStorage.setItem('token', value);

// v1.0 — optional access control
await SecureStorage.setItem('token', value, {
  service: 'com.myapp.auth',
  requireAuthentication: true,
  accessibility: 'whenPasscodeSetThisDeviceOnly',
});
```

Existing keys without `service` continue using default namespace `com.securitysuite.secure_storage`.

### 3. SSL pinning errors

```typescript
// v0.9 — string error
catch (e) { console.log(e.message); }

// v1.0 — structured
catch (e) {
  if (e.code === 'SSL_PINNING_FAILED') {
    console.log(e.domain, e.reason);
  }
}
```

### 4. Network logger

Release builds now **force-disable** logging even if `loggerIsEnabled: true` is passed. Use `SecuritySuite.configure({ secureNetwork: { logger: { enabled: __DEV__ } } })`.

## JWS migration

HS* with `secret` in JS continues to work. For new integrations:

```typescript
// Generate keypair once (stored in Keystore)
await JWS.generateKeyPair({ alias: 'api-signing', algorithm: 'ES256' });

const token = await JWS.generate({
  algorithm: 'ES256',
  keyAlias: 'api-signing',
  payload: { amount: 1000 },
  headers: JWS.createReplayProtectedHeaders(),
});
```

Server must verify ES256 with the registered public key — see [jws-server-verification.md](./jws-server-verification.md).

## Step-by-step migration checklist

- [ ] Replace `deviceHasSecurityRisk()` with `SecuritySuite.getSecurityReport()` for richer signals
- [ ] Move tokens to `SecureStorage` with `requireAuthentication: true` for high-value secrets
- [ ] Stop relying on `getSharedKey()` return value; use native encrypt/decrypt
- [ ] Add backup SSL pins before cert rotation
- [ ] Replace inline JWS secrets with Keystore-backed ES256 where possible
- [ ] Enable `ScreenSecurity.enable()` on sensitive screens
- [ ] Send `getSecurityReport()` to backend on login (server-side policy)
- [ ] Remove `loggerIsEnabled: true` from production code paths

## Deprecation timeline

| API | Deprecated | Removal |
|-----|------------|---------|
| `encrypt()` / `decrypt()` (storage) | v0.9 | v2.0 |
| `getSharedKey()` return value | v1.0 | v2.0 |
| Top-level `fetch` without namespace | v1.0 | Never (alias retained) |
| HS* JWS as primary signing | v1.0 | Never (supported indefinitely) |
