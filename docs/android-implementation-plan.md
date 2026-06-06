# Android Native Implementation Plan

## Module structure

Extend `SecuritySuiteModule.java` as a facade delegating to focused packages under `com.securitysuite.security.*`.

## 1. Runtime threat detection

### FridaDetector

| Check | Technique |
|-------|-----------|
| Named pipes | Scan `/proc/self/fd` for `linjector`, `frida` |
| Maps | Parse `/proc/self/maps` for `frida-agent`, `gadget` |
| D-Bus port | Default Frida server 27042 |
| Thread names | `gmain`, `gdbus`, `pool-frida` |

```java
public final class FridaDetector {
  public static boolean detect(Context ctx) {
    return hasSuspiciousMaps() || hasFridaPort() || hasFridaThreads();
  }
}
```

**Anti-tamper:** Split checks across classes; verify integrity of DEX checksum for detection classes in release builds.

### XposedDetector / LSPosed

- Stack trace inspection for `de.robv.android.xposed`
- Check for `XposedBridge.jar` in `/system/framework`
- LSPosed: look for `org.lsposed.lspd` in `/data/adb/modules`
- `ClassLoader` hook detection via known Xposed installer package names

### MagiskDetector

- `RootBeer` + custom: `/sbin/.magisk`, `magisk`, `zygisk` in maps
- Check `ro.boot.verifiedbootstate`, `ro.debuggable`
- Parse `/proc/mounts` for overlay filesystems

### DebuggerDetector

```java
Debug.isDebuggerConnected()
Debug.waitingForDebugger()
android.os.Process.myPid() → TracerPid in /proc/self/status != 0
Settings.Global.ADB_ENABLED (informational, not blocking alone)
```

### PortScanner

Scan localhost TCP ports: `27042`, `27043`, `4444` (common Frida defaults). Run on background thread with 2s timeout.

### NativeLibraryScanner

Enumerate `/proc/self/maps` for non-system paths containing: `substrate`, `frida`, `xposed`, `libhooker`.

**Return shape:** WritableMap matching `RuntimeThreatReport`.

## 2. App integrity

### ApkSignatureVerifier

```java
PackageManager pm = context.getPackageManager();
PackageInfo info = pm.getPackageInfo(packageName,
    PackageManager.GET_SIGNING_CERTIFICATES);
// Compare SHA-256 of signing cert to embedded expected hash (BuildConfig.EXPECTED_CERT_SHA256)
```

Ship `expected_cert_sha256` via gradle `buildConfigField` per flavor (dev/staging/prod).

### InstallerVerifier

```java
String installer = pm.getInstallSourceInfo(packageName).getInstallingPackageName();
// Trusted: com.android.vending, com.huawei.appmarket (optional list)
```

### DebuggableChecker

```java
(context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0
```

### PlayIntegrityClient (optional module)

- Dependency: `com.google.android.play:integrity:1.4.0`
- Requires Cloud project + Play Console linkage
- Expose `@ReactMethod requestPlayIntegrity(nonce, Promise)`

## 3. Emulator detection

| Signal | Implementation |
|--------|----------------|
| Build.FINGERPRINT contains `generic`, `unknown` | String match |
| Build.MODEL / MANUFACTURER | Known emulator values |
| QEMU | `ro.kernel.qemu == 1` |
| Sensors | SensorManager.getDefaultSensor(TYPE_ACCELEROMETER) == null |
| Telephony | `ro.telephony.call_ring.multiple` |
| Hardware | `Build.HARDWARE` contains `goldfish`, `ranchu` |

Combine with RootBeer emulator check. Return `indicators[]` for transparency.

## 4. SecureStorage upgrades

### BiometricPromptHelper

```java
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .setRequestStrongBoxBacked(useStrongBox)
    .setUserAuthenticationRequired(requireAuth)
    .setUserAuthenticationValidityDurationSeconds(-1) // per-use
    .build();
```

Handle `KeyPermanentlyInvalidatedException` → reject with `BIOMETRIC_AUTH_FAILED`.

### Namespace support

Separate EncryptedSharedPreferences files per service:
`com.securitysuite.secure_storage.{service_hash}`

## 5. Crypto upgrades

### X25519KeyStore (API 31+)

Use `KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_XDH, ANDROID_KEYSTORE)`.

Fallback: existing P-256 ECDH in `EcdhKeyStore.java`.

### NativeEncryptor

Move `encryptionKey`/`hmacKey` from module fields to `ConcurrentHashMap<String, SecretKey>` keyed by alias. Never call `promise.resolve` with raw key bytes unless `returnSharedKey: true`.

### SecureRandomProvider

```java
SecureRandom sr = new SecureRandom();
byte[] bytes = new byte[length];
sr.nextBytes(bytes);
// Base64 encode for bridge; zeroize bytes array after
Arrays.fill(bytes, (byte) 0);
```

## 6. JWS — ES256

```java
KeyPairGenerator kpg = KeyPairGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE);
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
    KeyProperties.PURPOSE_SIGN)
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .build();
```

Sign with `Signature.getInstance("SHA256withECDSA")`; encode JWS per RFC 7515.

Ed25519: API 33+ native; else optional BouncyCastle dependency (document size impact).

## 7. SSL pinning enhancements

Extend `PinningConfig`:

```java
CertificatePinner.Builder builder = new CertificatePinner.Builder();
for (String pin : primaryPins) builder.add(hostname, "sha256/" + pin);
for (String pin : backupPins) builder.add(hostname, "sha256/" + pin);
```

Structured error callback:

```java
WritableMap error = Arguments.createMap();
error.putString("code", "SSL_PINNING_FAILED");
error.putString("domain", hostname);
error.putString("reason", "PIN_MISMATCH");
```

## 8. Screen security

`ScreenSecurityManager.java`:

```java
activity.getWindow().setFlags(FLAG_SECURE, FLAG_SECURE);
// FLAG_SECURE also hides content in recents on most devices
```

Register `ActivityLifecycleCallbacks` to re-apply flags after config changes.

## 9. Secure clipboard

Use `ClipboardManager` with `ClipData` + `Handler.postDelayed` to clear after `expiresInMs`. On Android 13+, use `setPrimaryClip` with sensitive content flag where available.

## 10. Testing

| Component | Test type |
|-----------|-----------|
| JWSGenerator | Unit (existing) |
| SecureStorageNative | Robolectric + instrumented |
| FridaDetector | Mock `/proc` files in test assets |
| ApkSignatureVerifier | Unit with test APKs |
| SslPinning | MockWebServer with custom certs |

## Dependencies to add

```gradle
implementation 'com.google.android.play:integrity:1.4.0' // optional
implementation 'androidx.biometric:biometric:1.2.0-alpha05'
```

## ProGuard rules

Keep detection class names obfuscated but preserve `@ReactMethod` entry points. Do not strip `BuildConfig.EXPECTED_CERT_SHA256`.
