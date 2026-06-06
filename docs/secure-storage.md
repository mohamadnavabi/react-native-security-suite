# Secure Storage Guide

## Basic usage

```typescript
import { SecureStorage } from 'react-native-security-suite';

await SecureStorage.setItem('refresh_token', token);
const stored = await SecureStorage.getItem('refresh_token');
await SecureStorage.removeItem('refresh_token');
```

## Namespaces (service)

Isolate storage per feature or tenant:

```typescript
await SecureStorage.setItem('token', value, {
  service: 'com.myapp.auth',
});

await SecureStorage.setItem('prefs', json, {
  service: 'com.myapp.settings',
});
```

Keys are scoped to `(service, key)` — no collision across services.

## Access control (iOS)

| Option | Maps to | Use case |
|--------|---------|----------|
| `whenUnlocked` | `kSecAttrAccessibleWhenUnlocked` | General secrets |
| `whenUnlockedThisDeviceOnly` | Default | No iCloud backup |
| `afterFirstUnlock` | After first unlock post-reboot | Background refresh tokens |
| `whenPasscodeSetThisDeviceOnly` | Requires device passcode | High-value keys |

```typescript
await SecureStorage.setItem('pin_seed', seed, {
  accessibility: 'whenPasscodeSetThisDeviceOnly',
  requireAuthentication: true,
});
```

## Biometric protection

When `requireAuthentication: true`:

- **iOS:** Keychain item protected with `SecAccessControl` + biometry or passcode
- **Android:** `BiometricPrompt` before Keystore unlock; key invalidated on biometric enrollment change

```typescript
try {
  const secret = await SecureStorage.getItem('vault', {
    requireAuthentication: true,
    authenticationPrompt: 'Authenticate to access your vault',
  });
} catch (e) {
  if (e.code === 'BIOMETRIC_AUTH_FAILED') {
    // User cancelled or lockout
  }
}
```

## Android StrongBox

On devices with StrongBox SE, enable hardware isolation:

```typescript
await SecureStorage.setItem('key', value, {
  useStrongBox: true, // falls back gracefully if unavailable
});
```

## Memory hygiene

- Minimize time secrets spend in JS variables
- Clear sensitive strings from state after use (best-effort; not cryptographically guaranteed in JS)
- Prefer native JWS signing and native encrypt over reading keys into JS

```typescript
// Good — sign without reading secret into JS state
await JWS.generate({ keyAlias: 'signing', payload, algorithm: 'ES256' });

// Avoid — long-lived token in React state
const [token, setToken] = useState(await SecureStorage.getItem('token'));
```

## Error recovery (Android)

If Keystore keys are permanently invalidated (biometric change), operations throw `SECURE_STORAGE_UNAVAILABLE`. App should:

1. Clear local session
2. Prompt re-authentication
3. Re-provision secrets from server

## What NOT to store

- Passwords in plaintext (use server-side auth)
- Large blobs (> 4KB may hit Keychain limits on iOS)
- Non-sensitive UI preferences (use AsyncStorage)

## Migration from v0.9

Existing entries under default service `com.securitysuite.secure_storage` with `rss:` prefix remain readable. New `service` option creates isolated Keychain access groups / separate EncryptedSharedPreferences files.
