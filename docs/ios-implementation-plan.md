# iOS Native Implementation Plan

## Module structure

Extend `SecuritySuite.swift` as facade; add `Security/` subdirectory with focused Swift types.

## 1. Runtime threat detection

### FridaDetector

| Check | Technique |
|-------|-----------|
| Dyld env | `_DYLD_INSERT_LIBRARIES` non-empty |
| Suspicious ports | Connect probe to `127.0.0.1:27042` |
| File paths | `frida-server`, `/usr/sbin/frida-server` |
| Symbol hooks | `dlsym` sanity on `sysctl`, `ptrace` |

```swift
enum FridaDetector {
  static func detect() -> Bool {
    hasDyldInsert() || canConnect(port: 27042) || hasFridaPaths()
  }
}
```

### SubstrateDetector

- Check for `/Library/MobileSubstrate/MobileSubstrate.dylib`
- `IOSSecuritySuite.amIJailbrokenWithFailMessage()` fail messages
- Enumerate loaded images via `_dyld_image_count` for `substrate`, `substitute`, `ellekit`

### DebuggerDetector

```swift
var info = kinfo_proc()
var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
sysctl(&mib, ..., &info, ...)
(info.kp_proc.p_flag & P_TRACED) != 0
```

Also use `IOSSecuritySuite.amIDebugged()`.

### DylibScanner

```swift
func suspiciousLibraries() -> [String] {
  (0..<_dyld_image_count()).compactMap { i in
    let name = String(cString: _dyld_get_image_name(i))
    return isSuspicious(name) ? name : nil
  }
}
```

Filter: frida, substrate, cycript, flex, hooker.

## 2. App integrity

### CodeSigningVerifier

```swift
var staticCode: SecStaticCode?
SecStaticCodeCreateWithPath(bundleURL as CFURL, [], &staticCode)
SecStaticCodeCheckValidity(staticCode!, [], &error)
```

Compare `TeamIdentifier` and `ApplicationIdentifier` against expected values from Info.plist config (`RSSExpectedTeamId`, `RSSExpectedBundleId`).

### Build type detection

```swift
#if DEBUG
  buildType = .debug
#else
  if Bundle.main.appStoreReceiptURL?.lastPathComponent == "sandboxReceipt" {
    buildType = .testflight
  } else {
    buildType = .release
  }
#endif
```

### AppAttestClient (optional)

- `DCAppAttestService.shared.isSupported`
- `generateKey` → `attestKey` → return attestation object
- Requires iOS 14+; reject gracefully on Simulator

## 3. Simulator / emulator detection

```swift
enum SimulatorDetector {
  static func detect() -> (isSimulator: Bool, indicators: [String]) {
    var indicators: [String] = []
    #if targetEnvironment(simulator)
    indicators.append("TARGET_OS_SIMULATOR")
    #endif
    if IOSSecuritySuite.amIRunInEmulator() { indicators.append("IOSSecuritySuite") }
    // Check hw.model sysctl for x86_64 / arm64 simulator
    return (!indicators.isEmpty, indicators)
  }
}
```

## 4. SecureStorage upgrades

Extend `KeychainHelper.save()`:

```swift
var access = SecAccessControlCreateWithFlags(
  nil,
  kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
  [.biometryCurrentSet, .or, .devicePasscode],
  nil
)
attributes[kSecAttrAccessControl as String] = access
```

Map TS `accessibility` strings to `kSecAttrAccessible*` constants.

Use `LAContext` for explicit biometric prompt on read when `requireAuthentication: true`.

## 5. Crypto upgrades

### X25519KeyAgreement (CryptoKit)

```swift
let privateKey = Curve25519.KeyAgreement.PrivateKey()
try KeychainHelper.shared.save(privateKey.rawRepresentation, ...)
// Never export private key to JS
```

Align with Android X25519 for cross-platform key exchange (v1.0 goal). Current P-256 ECDH remains as fallback.

### NativeEncryptor

Store `SymmetricKey` in actor-isolated native dictionary by alias. `encrypt`/`decrypt` methods operate without exposing key material to bridge.

### Secure random

```swift
var bytes = [UInt8](repeating: 0, count: length)
_ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
defer { bytes.resetBytes(in: 0..<length) }
return Data(bytes).base64EncodedString()
```

## 6. JWS — ES256 / EdDSA

### SecureEnclaveSigner

```swift
let access = SecAccessControlCreateWithFlags(
  nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
  [.privateKeyUsage], nil)!
let attributes: [String: Any] = [
  kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
  kSecAttrKeySizeInBits: 256,
  kSecAttrTokenID: kSecAttrTokenIDSecureEnclave,
  kSecPrivateKeyAttrs: [
    kSecAttrIsPermanent: true,
    kSecAttrApplicationTag: alias.data(using: .utf8)!,
    kSecAttrAccessControl: access,
  ],
]
SecKeyCreateRandomKey(attributes as CFDictionary, nil)
```

Ed25519: CryptoKit `Curve25519.Signing.PrivateKey` stored in Keychain.

### CanonicalJSON.swift

Sort keys recursively; no whitespace; UTF-8 NFC normalization for strings.

## 7. SSL pinning enhancements

Extend `PinningConfiguration`:

```swift
struct PinSet {
  let primary: Set<Data>
  let backup: Set<Data>
}
```

In `urlSession(_:didReceive:completionHandler:)`:

```swift
if !pinMatches && !backupMatches {
  callback([NSNull(), [
    "code": "SSL_PINNING_FAILED",
    "domain": host,
    "reason": "PIN_MISMATCH",
  ]])
}
```

Optional CT: use `NSURLSession` + custom trust evaluation with `SecPolicyCreateSSL` and OCSP stapling check.

## 8. Screen security

### ScreenSecurityManager

```swift
NotificationCenter.default.addObserver(
  forName: UIScreen.capturedDidChangeNotification, ...
)
// UIScreen.main.isCaptured for recording detection
```

### App switcher blur

On `UIApplication.willResignActiveNotification`, overlay `UIVisualEffectView` on key window. Remove on `didBecomeActive`.

`SecureView` continues to use secure text field subview technique for screenshot blocking.

## 9. Secure clipboard

```swift
UIPasteboard.general.string = value
DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(expiresInMs)) {
  if UIPasteboard.general.string == value {
    UIPasteboard.general.string = ""
  }
}
```

iOS 16+: consider `UIPasteboard.general.setItems(_:options:)` with expiration.

## 10. Network redaction

Extend Pulse logger configuration:

```swift
struct RedactionConfig {
  let headers: Set<String>
  let bodyFields: Set<String>  // JSON key paths
}
```

Recursively redact JSON body fields before logging.

## 11. Testing

| Component | Test |
|-----------|------|
| JWSGenerator | Existing XCTest |
| CanonicalJSON | Unit tests for sort order |
| CodeSigningVerifier | Unit test in dev build |
| KeychainHelper | Simulator (limited) + device CI |
| DylibScanner | Mock dyld in debug test target |

## Info.plist additions

```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access secure data</string>
```

## Pod dependencies

```ruby
s.dependency 'IOSSecuritySuite'  # existing
# DeviceCheck framework for App Attest (system)
```

## Swift concurrency

Use `@MainActor` for UI-adjacent screen security; detection runs on `DispatchQueue.global(qos: .userInitiated)`.
