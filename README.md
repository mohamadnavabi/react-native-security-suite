# React Native Security Suite 🔒

[![npm version](https://badge.fury.io/js/react-native-security-suite.svg)](https://www.npmjs.com/package/react-native-security-suite)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://img.shields.io/npm/dm/react-native-security-suite.svg)](https://www.npmjs.com/package/react-native-security-suite)

**Comprehensive security solutions for React Native applications** — Protect your mobile apps with root/jailbreak detection, SSL certificate pinning, RFC 7515 JWS request signing, hardware-backed secure storage, configurable ECDH key exchange, screenshot protection, and network monitoring.

<div style="display: flex; flex-direction: row; justify-content: center; align-items: center; gap: 20px;">
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/pulse.gif" alt="iOS Pulse Network Monitor" width="200" />
<img src="https://raw.githubusercontent.com/mohamadnavabi/react-native-security-suite/master/chucker.gif" alt="Android Chucker Network Monitor" width="200" />
</div>

## 🚀 Features

### Security Detection & Protection

- **Root Detection**: Detect rooted Android devices
- **Jailbreak Detection**: Detect jailbroken iOS devices
- **Screenshot Protection**: Prevent screenshots and screen recordings
- **SSL Certificate Pinning**: Secure network communications
- **Public Key Pinning**: Advanced certificate validation

### Data Security & Encryption

- **Secure Storage**: Hardware-backed encrypted storage (Keychain on iOS, EncryptedSharedPreferences on Android)
- **Diffie-Hellman Key Exchange**: Application-defined algorithms and GCM parameters via `CryptoOptions`
- **Shared-Key Encryption**: AES-GCM encrypt/decrypt using a derived shared secret
- **Obfuscation**: Local string obfuscation with an explicit secret (not for credentials at rest)

### Network Security & Monitoring

- **JWS Request Signing (RFC 7515)**: HMAC-signed compact JWS tokens for `fetch` requests (HS256/HS384/HS512)
- **SSL Certificate Pinning**: Pin SPKI SHA-256 hashes with domain allowlists
- **Network Logger**: Built-in request/response logging
- **Android Chucker Integration**: Advanced network debugging
- **iOS Pulse Integration**: Network monitoring for iOS

## 📱 Supported Platforms

- ✅ **Android** (API 21+)
- ✅ **iOS** (iOS 11.0+)
- ✅ **React Native** (0.60+)

## 🛠 Installation

### Using Yarn

```bash
yarn add react-native-security-suite
```

### Using NPM

```bash
npm install react-native-security-suite
```

### iOS Setup

```bash
cd ios && pod install
```

## 📁 Project Structure

The public API is exported from `src/index.tsx`. JWS validation and normalization live in a dedicated module so TypeScript and native code share the same contract.

```
src/
├── index.tsx          # Public API (fetch, crypto, SecureStorage, SecureView)
├── jws.ts             # JWS types, validation, payload normalization
├── SecureView.tsx     # Screenshot-protected view component
└── helpers.ts         # Internal utilities

android/src/main/java/com/securitysuite/
├── SecureStorageNative.java # EncryptedSharedPreferences + Android Keystore
├── JWSGenerator.java      # RFC 7515 compact JWS (sign + verify)
├── JwsFetchPayload.java   # Default fetch signing payload builder
├── SecuritySuiteModule.java
└── Sslpinning.java        # fetch + SSL pinning + JWS header injection

ios/
├── SecureStorageNative.swift # Keychain-backed secure storage
├── KeychainHelper.swift      # Keychain read/write/query helpers
├── JWSGenerator.swift     # RFC 7515 compact JWS (sign + verify)
├── SecuritySuite.swift    # Native module + fetch
└── SslPinning.swift
```

**JWS flow:** JavaScript validates options in `src/jws.ts` (secret, algorithm, headers, payload shape), normalizes the payload to the exact UTF-8 signing string, then calls native `generateJWS` on Android/iOS. For `fetch`, native code builds the signing payload when `jws.payload` is omitted, signs it, and attaches the compact token to the request header.

## 📖 Usage Examples

### 1. Root/Jailbreak Detection

Detect compromised devices to protect your app from security risks:

```javascript
import { deviceHasSecurityRisk } from 'react-native-security-suite';

const checkDeviceSecurity = async () => {
  const isRiskyDevice = await deviceHasSecurityRisk();

  if (isRiskyDevice) {
    console.log('⚠️ Device is rooted/jailbroken - Security risk detected');
    // Handle security risk - show warning or restrict features
  } else {
    console.log('✅ Device security check passed');
  }
};
```

### 2. Screenshot Protection

Protect sensitive content from screenshots and screen recordings:

```javascript
import { SecureView } from 'react-native-security-suite';

const SensitiveScreen = () => {
  return (
    <View style={styles.container}>
      <SecureView style={styles.secureContainer}>
        <Text style={styles.sensitiveText}>
          🔒 This content is protected from screenshots
        </Text>
        <TextInput
          placeholder="Enter sensitive information"
          secureTextEntry={true}
        />
      </SecureView>
    </View>
  );
};
```

### 3. Obfuscation (local only)

Obfuscation requires an explicit secret and is intended for non-sensitive local encoding — not for credentials, tokens, or PII at rest. Use `SecureStorage` for persisted secrets.

```javascript
import { obfuscate, deobfuscate } from 'react-native-security-suite';

const encoded = await obfuscate('local-cache-value', 'app-specific-secret');
const decoded = await deobfuscate(encoded, 'app-specific-secret');
```

> `encrypt()` / `decrypt()` remain available but are deprecated. They now require an explicit `secretKey` and should be replaced with `obfuscate()` / `deobfuscate()` or `SecureStorage`.

### 4. Secure Storage

Store sensitive data in hardware-backed encrypted storage. On **iOS**, values are stored in the Keychain (`kSecClassGenericPassword`). On **Android**, values are encrypted with **EncryptedSharedPreferences** backed by Android Keystore (`AES256_GCM`).

```javascript
import { SecureStorage } from 'react-native-security-suite';

const handleSecureStorage = async () => {
  try {
    // Store encrypted data
    await SecureStorage.setItem(
      'userToken',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'
    );
    await SecureStorage.setItem(
      'userCredentials',
      JSON.stringify({
        username: 'user@example.com',
        password: 'encrypted_password',
      })
    );

    // Retrieve data
    const token = await SecureStorage.getItem('userToken');
    const credentials = await SecureStorage.getItem('userCredentials');
    const allKeys = await SecureStorage.getAllKeys();

    console.log('Retrieved token:', token);
    console.log('Retrieved credentials:', JSON.parse(credentials));
    console.log('Stored keys:', allKeys);

    // Remove sensitive data
    await SecureStorage.removeItem('userToken');

    // Clear all secure storage entries
    await SecureStorage.clear();
  } catch (error) {
    console.error('Secure storage error:', error);
  }
};
```

#### Security Guarantee

`SecureStorage` no longer uses AsyncStorage or any JavaScript-side persistence. All keys and values are:

- **Encrypted at rest** — AES-GCM (Android) / Keychain-protected blobs (iOS)
- **Hardware-backed where available** — Android Keystore master key; iOS Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- **System-managed keys** — No hardcoded salts or encryption keys in app code; the OS generates and protects master keys

If a native read/write fails (for example, KeyStore initialization errors on Android), the Promise rejects with a clear `Secure storage operation failed` error.

### 5. Diffie-Hellman Key Exchange

Derive a shared encryption key from the client and server public keys. **All cryptographic algorithms and GCM lengths must be supplied by your application** — the native layer does not apply defaults.

Use **`Crypto.establishSharedKey()`** so the derived key stays in native memory. Pass the same `cryptoOptions` to `encryptBySharedKey` / `decryptBySharedKey`.

```typescript
import {
  Crypto,
  getPublicKey,
  encryptBySharedKey,
  decryptBySharedKey,
  type CryptoOptions,
} from 'react-native-security-suite';

/**
 * Pick one value per field. Unions match exported package types.
 * Use JCA names (e.g. 'HmacSHA256', 'AES/GCM/NoPadding') for native crypto.
 */
const cryptoOptions: CryptoOptions = {
  keyAgreementAlgorithm: 'X25519', // 'X25519' | 'ECDH'
  keyType: 'EC', // 'OKP' | 'EC'
  encryptionKeyAlgorithm: 'AES-256', // 'AES-256' | 'AES'
  hmacAlgorithm: 'HmacSHA256', // 'HmacSHA256' | 'HmacSHA384' | 'HmacSHA512' | 'HMAC-SHA-256' | 'HMAC-SHA-384' | 'HMAC-SHA-512'
  cipher: 'AES-GCM', // 'AES-GCM' | 'AES/GCM/NoPadding'
  tagLength: 256, // GCM auth tag size in bits
  ivLength: 12, // GCM IV size in bytes
};

const handleKeyExchange = async () => {
  const clientPublicKey = await getPublicKey();
  const serverPublicKey = 'SERVER_PUBLIC_KEY_FROM_API';

  // Keeps the shared key in native memory (recommended)
  await Crypto.establishSharedKey(serverPublicKey, cryptoOptions);

  const encryptedMessage = await encryptBySharedKey('Secret message', cryptoOptions);
  const decryptedMessage = await decryptBySharedKey(encryptedMessage, cryptoOptions);
};
```

**Legacy API** (returns the derived key to JavaScript — avoid in production):

```javascript
import { getSharedKey } from 'react-native-security-suite';

const sharedKeyBase64 = await getSharedKey(serverPublicKey, cryptoOptions);
```

#### Algorithm and length options

| Option | Required | Allowed values | Description |
|--------|----------|----------------|-------------|
| `keyAgreementAlgorithm` | yes | `'X25519' \| 'ECDH'` | Key-agreement algorithm passed to native `KeyAgreement` |
| `keyType` | yes* | `'OKP' \| 'EC'` | Key-factory algorithm for the server public key (`keyFactoryAlgorithm` alias) |
| `encryptionKeyAlgorithm` | yes | `'AES-256' \| 'AES'` | Symmetric key algorithm for the derived encryption key |
| `hmacAlgorithm` | yes* | `'HmacSHA256' \| 'HmacSHA384' \| 'HmacSHA512' \| 'HMAC-SHA-256' \| 'HMAC-SHA-384' \| 'HMAC-SHA-512'` | HMAC for HKDF and MAC key material (`hmacKeyAlgorithm` alias) |
| `cipher` | yes* | `'AES-GCM' \| 'AES/GCM/NoPadding'` | Cipher transformation for encrypt/decrypt (`cipherTransformation` alias) |
| `tagLength` | yes* | `number` (e.g. `128`) | GCM authentication tag length in **bits** (`gcmTagLength` alias) |
| `ivLength` | yes* | `number` (e.g. `12`) | GCM IV/nonce length in **bytes** (`gcmIvLength` alias) |

\*Provide via the preferred name or its deprecated alias (see [API Reference](#cryptooptions)).

Use **JCA-style names** on both Android and iOS (e.g. `HmacSHA256`, not `HMAC-SHA-256`). Omitting any required option throws before native code runs.

**Typical production profile (P-256 ECDH + AES-256-GCM):**

```typescript
import type { CryptoOptions } from 'react-native-security-suite';

const cryptoOptions: CryptoOptions = {
  keyAgreementAlgorithm: 'ECDH',
  keyType: 'EC',
  encryptionKeyAlgorithm: 'AES',
  hmacAlgorithm: 'HmacSHA256',
  cipher: 'AES/GCM/NoPadding',
  tagLength: 128,
  ivLength: 12,
};
```

### 6. JWS Generation (RFC 7515)

Generate [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515) compact JWS tokens. Supported algorithms: **HS256**, **HS384**, **HS512**. An explicit `secret` is always required.

**How it works**

1. TypeScript (`src/jws.ts`) validates `secret`, `algorithm`, and custom headers.
2. The payload is normalized to the exact UTF-8 string used for signing (objects/arrays are `JSON.stringify`'d; `undefined`/`null`/`''` become an empty payload).
3. Native code builds sorted protected headers (always including `alg`), base64url-encodes header and payload, signs `base64url(header).base64url(payload)` with HMAC, and returns the compact token.

**Empty payload** (`undefined`, `null`, or `''`) produces three segments with an empty middle segment:

```javascript
import { generateJWS } from 'react-native-security-suite';

const jws = await generateJWS({
  algorithm: 'HS256',
  secret: 'my-temporary-secret',
  headers: { kid: 'key-1' },
});

// compact form: <protectedHeader>.<payload>.<signature>
// jws.split('.').length === 3
// jws.split('.')[1] === ''   // empty payload segment
```

**JSON payload:**

```javascript
const jws = await generateJWS({
  algorithm: 'HS512',
  secret: 'my-temporary-secret',
  payload: { amount: 1000, currency: 'USD' },
  headers: { kid: 'key-1', request_id: 'req-123', typ: 'JWS' },
});
```

**Header rules:** keys must match `^[a-zA-Z][a-zA-Z0-9_-]*$`; values must be JSON primitives (`string`, `number`, `boolean`, `null`). String values must be printable ASCII (`0x20`–`0x7E`). If both `algorithm` and `headers.alg` are set, they must match.

> **Security note:** HS* JWS on mobile uses a client-side shared secret. It helps with request integrity when combined with TLS, but it is not proof against a fully compromised client.

### 7. Fetch Request Signing with JWS

Pass a `jws` object on `fetch` options. The signed token is sent as an HTTP header (default: `X-Request-Signature`).

```javascript
import { fetch } from 'react-native-security-suite';

await fetch('https://api.example.com/payments', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: { amount: 1000 },
  jws: {
    algorithm: 'HS256',
    secret: 'temporary-session-secret',
    headers: {
      kid: 'key-1',
      request_id: 'req-123',
      timestamp: Date.now(),
      nonce: 'unique-nonce-per-request',
    },
    headerName: 'X-Request-Signature',
    detached: false,
  },
});
```

**Default signing payload** (when `jws.payload` is omitted): native code builds a sorted JSON object from:

| Field | Source |
|-------|--------|
| `method` | HTTP method (uppercased) |
| `path` | URL path (`/` if empty) |
| `query` | Query string (if present) |
| `bodyHash` | Base64url SHA-256 of request body (if body present) |
| `timestamp`, `nonce`, `request_id` | Copied from `jws.headers` when provided |

**Explicit fetch payload:** when you set `jws.payload`, it must already be a string (use `JSON.stringify` for objects). For fetch, object payloads are not auto-serialized — only `generateJWS` accepts object payloads directly.

```javascript
jws: {
  secret: 'temporary-session-secret',
  payload: JSON.stringify({ amount: 1000, currency: 'USD' }),
}
```

**Detached fetch signing** — set `jws.detached: true` to send `header..signature` while the raw payload remains in the request body:

```javascript
jws: {
  secret: 'temporary-session-secret',
  detached: true,
  headers: { kid: 'key-1', request_id: 'req-123' },
}
```

**Migration from legacy options:** `options.keyId`, `options.requestId`, and top-level `options.secret` are deprecated. Use `options.jws` with `secret`, `headers.kid`, and `headers.request_id` instead. Legacy signing always used detached HS256 and the `X-JWS-Signature` header.

### 8. SSL Certificate Pinning

Secure your API communications with certificate pinning:

```javascript
import { fetch } from 'react-native-security-suite';

const secureApiCall = async () => {
  try {
    const response = await fetch('https://api.yourapp.com/secure-endpoint', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer your-token',
      },
      body: JSON.stringify({
        userId: 123,
        action: 'sensitive_operation',
      }),
      certificates: [
        'sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
        'sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
      ],
      validDomains: ['api.yourapp.com', 'secure.yourapp.com'],
      timeout: 10000,
    });

    const data = await response.json();
    console.log('Secure API response:', data);
  } catch (error) {
    console.error('SSL pinning failed:', error);
    // Handle certificate validation failure
  }
};
```

### 9. Network Monitoring & Debugging

Monitor network requests in development:

```javascript
import { fetch } from 'react-native-security-suite';

const monitoredRequest = async () => {
  try {
    const response = await fetch(
      'https://api.example.com/data',
      {
        method: 'GET',
        headers: {
          Accept: 'application/json',
        },
      },
      __DEV__
    ); // Enable logging in development

    return await response.json();
  } catch (error) {
    console.error('Network request failed:', error);
  }
};
```

## 🔧 API Reference

### Security Detection

- `deviceHasSecurityRisk()` — Detect rooted/jailbroken devices

### Encryption & Storage

- `obfuscate(input, secret)` — Local obfuscation with explicit secret
- `deobfuscate(input, secret)` — Reverse `obfuscate`
- `SecureStorage` — Hardware-backed encrypted storage (`setItem`, `getItem`, `removeItem`, `getAllKeys`, `clear`, `multiGet`, `multiSet`, `multiRemove`)
- `encrypt(text, hardEncryption?, secretKey?)` — **deprecated**; requires `secretKey`
- `decrypt(encryptedText, hardEncryption?, secretKey?)` — **deprecated**; requires `secretKey`

### Key Exchange

- `Crypto.getPublicKey()` — Client public key (base64-encoded SPKI / DER)
- `Crypto.establishSharedKey(serverPublicKey, options)` — Derive shared key in native memory; **`options` required**
- `getPublicKey()` — Legacy alias for `Crypto.getPublicKey()`
- `getSharedKey(serverPublicKey, options)` — **Deprecated**; returns derived key to JS; **`options` required**
- `encryptBySharedKey(text, options)` — Encrypt with derived key; **`options` required**
- `decryptBySharedKey(encryptedText, options)` — Decrypt with derived key; **`options` required**

#### `CryptoOptions`

All fields below are **required** on every key-exchange and encrypt/decrypt call. There are no library defaults — define a shared `cryptoOptions` object in your app and reuse it.

| Option | Allowed values |
|--------|----------------|
| `keyAgreementAlgorithm` | `'X25519' \| 'ECDH'` |
| `keyType` | `'OKP' \| 'EC'` (alias: `keyFactoryAlgorithm`) |
| `encryptionKeyAlgorithm` | `'AES-256' \| 'AES'` |
| `hmacAlgorithm` | `'HmacSHA256' \| 'HmacSHA384' \| 'HmacSHA512' \| 'HMAC-SHA-256' \| 'HMAC-SHA-384' \| 'HMAC-SHA-512'` (alias: `hmacKeyAlgorithm`) |
| `cipher` | `'AES-GCM' \| 'AES/GCM/NoPadding'` (alias: `cipherTransformation`) |
| `tagLength` | `number` — GCM tag length in bits (alias: `gcmTagLength`) |
| `ivLength` | `number` — GCM IV length in bytes (alias: `gcmIvLength`) |

Exported types: `CryptoOptions`, `KeyAgreementAlgorithm`, `KeyType`, `EncryptionKeyAlgorithm`, `HmacAlgorithm`, `CipherAlgorithm`.

### JWS

- `generateJWS(options: GenerateJWSOptions)` — Generate compact or detached JWS

#### `GenerateJWSOptions`

| Field | Required | Description |
|-------|----------|-------------|
| `secret` | yes | Non-empty HMAC secret |
| `algorithm` | no | `HS256` (default), `HS384`, or `HS512` |
| `payload` | no | String, object, array, number, boolean, `null`, or `undefined` |
| `headers` | no | Custom protected headers (`kid`, `request_id`, etc.) |

#### `JwsFetchOptions` (on `fetch` options)

| Field | Required | Description |
|-------|----------|-------------|
| `secret` | yes | Non-empty HMAC secret |
| `algorithm` | no | `HS256` (default), `HS384`, or `HS512` |
| `headers` | no | Protected headers; `timestamp`/`nonce`/`request_id` also feed the default payload |
| `payload` | no | Explicit signing string; omit to use the default fetch payload |
| `detached` | no | Detached compact form (default: `false`) |
| `headerName` | no | Request header name (default: `X-Request-Signature`) |

Exported types: `JwsAlgorithm`, `JwsPayload`, `JwsHeaders`, `JwsHeaderValue`, `GenerateJWSOptions`, `JwsFetchOptions`.

### Network Security

- `fetch(url, options, loggerEnabled?)` — Secure fetch with SSL pinning and optional JWS signing

`fetch` `options` also accepts `certificates` + `validDomains` for SSL pinning, and deprecated top-level `keyId`, `requestId`, `secret` for legacy JWS.

### UI Components

- `SecureView` — Screenshot-protected view component

## 🛡️ Security Best Practices

1. **Always validate certificates** — Use SSL pinning for production APIs
2. **Detect compromised devices** — Check for root/jailbreak before sensitive operations
3. **Store secrets in SecureStorage** — Use hardware-backed storage for tokens and credentials
4. **Protect sensitive UI** — Wrap sensitive content in `SecureView`
5. **Sign requests with JWS** — Include `timestamp`, `nonce`, and `request_id` in `jws.headers` for replay protection; never embed long-lived secrets in the app binary
6. **Use detached JWS for body signing** — When the request body is the signed payload, set `jws.detached: true` so the body is not duplicated inside the token
7. **Monitor network traffic** — Use built-in logging for debugging only; disable in production
8. **Rotate session secrets** — Treat `jws.secret` as a short-lived session or request-scoped value from your backend

## 🐛 Troubleshooting

### Common Issues

**iOS Build Errors:**

```bash
cd ios && pod install && cd ..
npx react-native run-ios
```

**Android Build Errors:**

```bash
cd android && ./gradlew clean && cd ..
npx react-native run-android
```

**Metro Cache Issues:**

```bash
npx react-native start --reset-cache
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/mohamadnavabi/react-native-security-suite.git
cd react-native-security-suite
yarn install
cd example && yarn install && cd ..
yarn example android # or ios
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Chucker](https://github.com/ChuckerTeam/chucker) for Android network monitoring
- [Pulse](https://github.com/kean/Pulse) for iOS network monitoring
- React Native community for continuous support

## 📞 Support

- 📧 Email: 7navabi@gmail.com
- 🐛 Issues: [GitHub Issues](https://github.com/mohamadnavabi/react-native-security-suite/issues)
- 📖 Documentation: [GitHub Wiki](#)

---

**Made with ❤️ for the React Native community**
