import Foundation
import CryptoKit
import Security
import UIKit
import IOSSecuritySuite

@objc(SecuritySuite)
class SecuritySuite: NSObject {
    private var hkdfSalt: Data?
    private var hkdfInfoEncryption: Data?
    private var hkdfInfoHmac: Data?
    private var configuredLegacyV09Crypto = false
    private var suiteConfigured = false

    private var privateKeyData: Data?
    private var encryptionKeyData: Data?
    private var hmacKeyData: Data?
    private var cryptoConfig: CryptoConfig?
    private var keyAgreementProfile: KeyAgreementProfile?
    private var usesLegacyV09Crypto = false

    private func ensureConfigured() throws {
        guard suiteConfigured else {
            throw NSError(domain: "SecuritySuite", code: 11, userInfo: [
                NSLocalizedDescriptionKey:
                    "Call SecuritySuite.initialize() before using security APIs.",
            ])
        }
    }

  private func ensureHkdfConfigured() throws {
        guard let hkdfSalt, let hkdfInfoEncryption, let hkdfInfoHmac else {
            throw NSError(domain: "SecuritySuite", code: 12, userInfo: [
                NSLocalizedDescriptionKey:
                    "HKDF is not configured. Call SecuritySuite.initialize() before crypto APIs.",
            ])
        }
    }

    @objc(configure:withResolver:withRejecter:)
    func configure(
        config: NSDictionary,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        if let legacy = config["legacyV09Crypto"] as? Bool {
            configuredLegacyV09Crypto = legacy
        }

        if !configuredLegacyV09Crypto {
            guard let salt = config["hkdfSalt"] as? String,
                  !salt.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  salt.count >= 16,
                  let infoEncryption = config["hkdfInfoEncryption"] as? String,
                  !infoEncryption.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  let infoHmac = config["hkdfInfoHmac"] as? String,
                  !infoHmac.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                reject(
                    "CONFIGURATION_ERROR",
                    "hkdf.salt, hkdf.encryptionInfo, and hkdf.hmacInfo are required",
                    nil
                )
                return
            }

            hkdfSalt = salt.data(using: .utf8)
            hkdfInfoEncryption = infoEncryption.data(using: .utf8)
            hkdfInfoHmac = infoHmac.data(using: .utf8)
        }

        suiteConfigured = true
        resolve(nil)
    }

    private func isLegacyCryptoMode() -> Bool {
        configuredLegacyV09Crypto
    }

    /// v0.9.x compatibility: ephemeral keypair, no keychain, no HKDF.
    private func legacyGetPublicKey(
        options: NSDictionary?,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            usesLegacyV09Crypto = true
            cryptoConfig = try CryptoConfig.from(dictionary: options)
            let profile = try KeyAgreementProfile.from(dictionary: options)
            keyAgreementProfile = profile
            switch profile.kind {
            case .p256Ecdh:
                let key = P256.KeyAgreement.PrivateKey()
                privateKeyData = key.derRepresentation
                resolve(key.publicKey.derRepresentation.base64EncodedString())
            case .x25519:
                let key = Curve25519.KeyAgreement.PrivateKey()
                privateKeyData = key.rawRepresentation
                resolve(key.publicKey.rawRepresentation.base64EncodedString())
            }
        } catch {
            reject("GET_PUBLIC_KEY_ERROR", error.localizedDescription, error)
        }
    }

    private func legacyComputeSharedSecret(
        privateKeyData: Data,
        serverPublicKeyData: Data
    ) throws -> SharedSecret {
        switch keyAgreementProfile?.kind ?? .p256Ecdh {
        case .p256Ecdh:
            let privateKey = try P256.KeyAgreement.PrivateKey(derRepresentation: privateKeyData)
            let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyData)
            return try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
        case .x25519:
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let serverPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKeyData)
            return try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
        }
    }

    private func legacyEstablishSharedKey(
        serverPK: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            guard let privateKeyData else {
                reject("GET_SHARED_KEY_ERROR", "Call getPublicKey before getSharedKey", nil)
                return
            }

            let serverKeyString = (serverPK as String).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !serverKeyString.isEmpty,
                  let serverPublicKeyData = Data(base64Encoded: serverKeyString) else {
                reject("GET_SHARED_KEY_ERROR", "Invalid server public key", nil)
                return
            }

            let sharedSecret = try legacyComputeSharedSecret(
                privateKeyData: privateKeyData,
                serverPublicKeyData: serverPublicKeyData
            )
            let rawKey = sharedSecret.withUnsafeBytes { Data($0) }
            encryptionKeyData = rawKey
            hmacKeyData = rawKey
            resolve(nil)
        } catch {
            reject("GET_SHARED_KEY_ERROR", error.localizedDescription, error)
        }
    }

    private func legacyGetSharedKey(
        serverPK: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            guard let privateKeyData else {
                reject("GET_SHARED_KEY_ERROR", "Call getPublicKey before getSharedKey", nil)
                return
            }

            let serverKeyString = (serverPK as String).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !serverKeyString.isEmpty,
                  let serverPublicKeyData = Data(base64Encoded: serverKeyString) else {
                reject("GET_SHARED_KEY_ERROR", "Invalid server public key", nil)
                return
            }

            let sharedSecret = try legacyComputeSharedSecret(
                privateKeyData: privateKeyData,
                serverPublicKeyData: serverPublicKeyData
            )
            let rawKey = sharedSecret.withUnsafeBytes { Data($0) }
            encryptionKeyData = rawKey
            hmacKeyData = rawKey
            resolve(rawKey.base64EncodedString())
        } catch {
            reject("GET_SHARED_KEY_ERROR", error.localizedDescription, error)
        }
    }

    private func loadOrCreateKeyPair(profile: KeyAgreementProfile) throws -> KeyAgreementKeyPair {
        keyAgreementProfile = profile

        if profile.kind == .p256Ecdh,
           let migrated = try KeychainHelper.shared.loadECDHKeyPair() {
            privateKeyData = migrated.privateKey
            return KeyAgreementKeyPair(
                profile: profile,
                privateKeyData: migrated.privateKey,
                publicKeyData: migrated.publicKey
            )
        }

        if let stored = try KeychainHelper.shared.loadKeyAgreementKeyPair(profile: profile.storageId) {
            privateKeyData = stored.privateKey
            return KeyAgreementKeyPair(
                profile: profile,
                privateKeyData: stored.privateKey,
                publicKeyData: stored.publicKey
            )
        }

        switch profile.kind {
        case .p256Ecdh:
            let key = P256.KeyAgreement.PrivateKey()
            privateKeyData = key.derRepresentation
            let publicKeyData = key.publicKey.derRepresentation
            try KeychainHelper.shared.saveKeyAgreementKeyPair(
                privateKey: key.derRepresentation,
                publicKey: publicKeyData,
                profile: profile.storageId
            )
            return KeyAgreementKeyPair(
                profile: profile,
                privateKeyData: key.derRepresentation,
                publicKeyData: publicKeyData
            )
        case .x25519:
            let key = Curve25519.KeyAgreement.PrivateKey()
            privateKeyData = key.rawRepresentation
            let publicKeyData = key.publicKey.rawRepresentation
            try KeychainHelper.shared.saveKeyAgreementKeyPair(
                privateKey: key.rawRepresentation,
                publicKey: publicKeyData,
                profile: profile.storageId
            )
            return KeyAgreementKeyPair(
                profile: profile,
                privateKeyData: key.rawRepresentation,
                publicKeyData: publicKeyData
            )
        }
    }

    private func normalizeServerPublicKey(_ data: Data, profile: KeyAgreementProfile) throws -> Data {
        switch profile.kind {
        case .p256Ecdh:
            return data
        case .x25519:
            if data.count == 32 {
                return data
            }
            guard data.count >= 32 else {
                throw NSError(domain: "KeyAgreementProfile", code: 2, userInfo: [
                    NSLocalizedDescriptionKey: "Invalid X25519 public key length",
                ])
            }
            return data.suffix(32)
        }
    }

    private func resolveCryptoConfig(options: NSDictionary?) throws -> CryptoConfig {
        if let cryptoConfig {
            return try cryptoConfig.merged(with: options)
        }
        return try CryptoConfig.from(dictionary: options)
    }

    private func randomBytes(count: Int) throws -> Data {
        var bytes = Data(count: count)
        let status = bytes.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
        }
        guard status == errSecSuccess else {
            throw NSError(domain: "SecuritySuite", code: 7, userInfo: [
                NSLocalizedDescriptionKey: "Failed to generate random bytes",
            ])
        }
        return bytes
    }

    private func hkdfHash(for macAlgorithm: String) throws -> any HashFunction.Type {
        switch macAlgorithm {
        case "HmacSHA256", "HMAC-SHA-256":
            return SHA256.self
        case "HmacSHA384", "HMAC-SHA-384":
            return SHA384.self
        case "HmacSHA512", "HMAC-SHA-512":
            return SHA512.self
        default:
            throw NSError(domain: "CryptoConfig", code: 6, userInfo: [
                NSLocalizedDescriptionKey: "Unsupported hkdf mac algorithm: \(macAlgorithm)",
            ])
        }
    }

    private func deriveSymmetricKey(
        from sharedSecret: SharedSecret,
        macAlgorithm: String,
        info: Data,
        outputByteCount: Int
    ) throws -> Data {
        try ensureHkdfConfigured()
        guard let salt = hkdfSalt else {
            throw NSError(domain: "SecuritySuite", code: 12, userInfo: [
                NSLocalizedDescriptionKey: "HKDF is not configured",
            ])
        }
        let hash = try hkdfHash(for: macAlgorithm)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: hash,
            salt: salt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        ).withUnsafeBytes { Data($0) }
    }

    @objc(getPublicKey:withResolver:withRejecter:)
    func getPublicKey(
        options: NSDictionary?,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            try ensureConfigured()
        } catch {
            reject("GET_PUBLIC_KEY_ERROR", error.localizedDescription, error)
            return
        }

        if isLegacyCryptoMode() {
            legacyGetPublicKey(options: options, resolve: resolve, reject: reject)
            return
        }

        do {
            usesLegacyV09Crypto = false
            let profile = try KeyAgreementProfile.from(dictionary: options)
            let keyPair = try loadOrCreateKeyPair(profile: profile)
            resolve(keyPair.publicKeyData.base64EncodedString())
        } catch {
            reject("GET_PUBLIC_KEY_ERROR", error.localizedDescription, error)
        }
    }

    @objc(establishSharedKey:withOptions:withResolver:withRejecter:)
    func establishSharedKey(
        serverPK: NSString,
        options: NSDictionary?,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            try ensureConfigured()
        } catch {
            reject("GET_SHARED_KEY_ERROR", error.localizedDescription, error)
            return
        }

        if isLegacyCryptoMode() {
            usesLegacyV09Crypto = true
            cryptoConfig = try? CryptoConfig.from(dictionary: options)
            legacyEstablishSharedKey(serverPK: serverPK, resolve: resolve, reject: reject)
            return
        }

        do {
            usesLegacyV09Crypto = false
            let config = try CryptoConfig.from(dictionary: options)
            cryptoConfig = config
            let profile = try KeyAgreementProfile.from(config: config)

            let serverKeyString = (serverPK as String).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !serverKeyString.isEmpty,
                  let serverPublicKeyData = Data(base64Encoded: serverKeyString) else {
                reject("GET_SHARED_KEY_ERROR", "Invalid server public key", nil)
                return
            }

            let keyPair = try loadOrCreateKeyPair(profile: profile)
            let normalizedServerKey = try normalizeServerPublicKey(serverPublicKeyData, profile: profile)
            let sharedSecret = try keyPair.sharedSecret(with: normalizedServerKey)

            guard let encInfo = hkdfInfoEncryption, let macInfo = hkdfInfoHmac else {
                reject("GET_SHARED_KEY_ERROR", "HKDF is not configured", nil)
                return
            }

            encryptionKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: encInfo,
                outputByteCount: 32
            )

            hmacKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: macInfo,
                outputByteCount: 32
            )

            resolve(nil)
        } catch {
            reject("GET_SHARED_KEY_ERROR", error.localizedDescription, error)
        }
    }

    @objc(getSharedKey:withOptions:withResolver:withRejecter:)
    func getSharedKey(
        serverPK: NSString,
        options: NSDictionary?,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            try ensureConfigured()
        } catch {
            reject("GET_SHARED_KEY_ERROR", error.localizedDescription, error)
            return
        }

        if isLegacyCryptoMode() {
            usesLegacyV09Crypto = true
            cryptoConfig = try? CryptoConfig.from(dictionary: options)
            legacyGetSharedKey(serverPK: serverPK, resolve: resolve, reject: reject)
            return
        }

        do {
            usesLegacyV09Crypto = false
            let config = try CryptoConfig.from(dictionary: options)
            cryptoConfig = config
            let profile = try KeyAgreementProfile.from(config: config)

            let serverKeyString = (serverPK as String).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !serverKeyString.isEmpty,
                  let serverPublicKeyData = Data(base64Encoded: serverKeyString) else {
                reject("GET_SHARED_KEY_ERROR", "Invalid server public key", nil)
                return
            }

            let keyPair = try loadOrCreateKeyPair(profile: profile)
            let normalizedServerKey = try normalizeServerPublicKey(serverPublicKeyData, profile: profile)
            let sharedSecret = try keyPair.sharedSecret(with: normalizedServerKey)

            guard let encInfo = hkdfInfoEncryption, let macInfo = hkdfInfoHmac else {
                reject("GET_SHARED_KEY_ERROR", "HKDF is not configured", nil)
                return
            }

            encryptionKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: encInfo,
                outputByteCount: 32
            )

            hmacKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: macInfo,
                outputByteCount: 32
            )

            resolve(encryptionKeyData?.base64EncodedString())
        } catch {
            reject("GET_SHARED_KEY_ERROR", error.localizedDescription, error)
        }
    }

    @objc(encrypt:withOptions:withResolver:withRejecter:)
    func encrypt(
        input: NSString,
        options: NSDictionary?,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        guard let keyData = encryptionKeyData else {
            reject(
                "ENCRYPT_ERROR",
                "Encryption key not established. Call establishSharedKey or getSharedKey first.",
                nil
            )
            return
        }
        do {
            let config = try resolveCryptoConfig(options: options)
            cryptoConfig = config
            let data = Data((input as String).utf8)
            let key = SymmetricKey(data: keyData)
            guard let output = try AES.GCM.seal(data, using: key).combined?.base64EncodedString() else {
                reject("ENCRYPT_ERROR", "Encryption failed", nil)
                return
            }
            resolve(output)
        } catch {
            reject("ENCRYPT_ERROR", error.localizedDescription, error)
        }
    }

    @objc(decrypt:withOptions:withResolver:withRejecter:)
    func decrypt(
        input: NSString,
        options: NSDictionary?,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        guard let keyData = encryptionKeyData else {
            reject(
                "DECRYPT_ERROR",
                "Encryption key not established. Call establishSharedKey or getSharedKey first.",
                nil
            )
            return
        }
        guard let data = Data(base64Encoded: input as String) else {
            reject("DECRYPT_ERROR", "Invalid ciphertext", nil)
            return
        }
        do {
            let config = try resolveCryptoConfig(options: options)
            cryptoConfig = config
            let key = SymmetricKey(data: keyData)
            let output = try AES.GCM.open(AES.GCM.SealedBox(combined: data), using: key)
            resolve(String(decoding: output, as: UTF8.self))
        } catch {
            reject("DECRYPT_ERROR", error.localizedDescription, error)
        }
    }

    @objc(generateJWS:withResolver:withRejecter:)
    func generateJWS(options: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        guard let secret = options["secret"] as? String,
              !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            reject("JWS_ERROR", "JWS secret is required and must be a non-empty string", nil)
            return
        }

        do {
            let payloadString: String
            if let payload = options["payload"] {
                if payload is NSNull {
                    payloadString = ""
                } else if let value = payload as? String {
                    payloadString = value
                } else {
                    reject("JWS_ERROR", "JWS payload must be normalized to a string before calling native code", nil)
                    return
                }
            } else {
                payloadString = ""
            }

            let algorithm = options["algorithm"] as? String
            let headers = options["headers"] as? [String: Any]
            let detached = options["detached"] as? Bool ?? false
            let jws = try JWSGenerator.generate(
                payloadString: payloadString,
                secret: secret,
                algorithm: algorithm,
                headers: headers,
                detached: detached
            )
            resolve(jws)
        } catch {
            reject("JWS_ERROR", error.localizedDescription, error)
        }
    }

    @objc(obfuscate:withSecret:withResolver:withRejecter:)
    func obfuscate(input: NSString, secret: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            let result = try Obfuscation().obfuscate(plain: input as String, secret: secret as String)
            resolve(result)
        } catch {
            reject("OBFUSCATE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(deobfuscate:withSecret:withResolver:withRejecter:)
    func deobfuscate(input: NSString, secret: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            let result = try Obfuscation().deobfuscate(encoded: input as String, secret: secret as String)
            resolve(result)
        } catch {
            reject("DEOBFUSCATE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(storageEncrypt:withSecretKey:withHardEncryption:withResolver:withRejecter:)
    func storageEncrypt(
        input: NSString,
        secretKey: NSString,
        hardEncryption: Bool,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        guard secretKey != nil, !(secretKey as String).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            reject(
                "ENCRYPT_ERROR",
                "secretKey is required. Device identifiers are not accepted as encryption keys.",
                nil
            )
            return
        }
        if hardEncryption {
            reject(
                "ENCRYPT_ERROR",
                "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data.",
                nil
            )
            return
        }
        do {
            let encrypted = try Obfuscation().obfuscate(plain: input as String, secret: secretKey as String)
            resolve(encrypted)
        } catch {
            reject("ENCRYPT_ERROR", error.localizedDescription, error)
        }
    }

    @objc(storageDecrypt:withSecretKey:withHardEncryption:withResolver:withRejecter:)
    func storageDecrypt(
        input: NSString,
        secretKey: NSString,
        hardEncryption: Bool,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        guard secretKey != nil, !(secretKey as String).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            reject(
                "DECRYPT_ERROR",
                "secretKey is required. Device identifiers are not accepted as encryption keys.",
                nil
            )
            return
        }
        if hardEncryption {
            reject(
                "DECRYPT_ERROR",
                "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data.",
                nil
            )
            return
        }
        do {
            let decrypted = try Obfuscation().deobfuscate(encoded: input as String, secret: secretKey as String)
            resolve(decrypted)
        } catch {
            reject("DECRYPT_ERROR", error.localizedDescription, error)
        }
    }

    @objc(secureStorageSetItem:withValue:withResolver:withRejecter:)
    func secureStorageSetItem(key: NSString, value: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            try SecureStorageNative.shared.setItem(key: key as String, value: value as String)
            resolve(nil)
        } catch {
            reject("SECURE_STORAGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(secureStorageGetItem:withResolver:withRejecter:)
    func secureStorageGetItem(key: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            resolve(try SecureStorageNative.shared.getItem(key: key as String))
        } catch {
            reject("SECURE_STORAGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(secureStorageRemoveItem:withResolver:withRejecter:)
    func secureStorageRemoveItem(key: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            try SecureStorageNative.shared.removeItem(key: key as String)
            resolve(nil)
        } catch {
            reject("SECURE_STORAGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(secureStorageClear:withRejecter:)
    func secureStorageClear(resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            try SecureStorageNative.shared.clear()
            resolve(nil)
        } catch {
            reject("SECURE_STORAGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(secureStorageGetAllKeys:withRejecter:)
    func secureStorageGetAllKeys(resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            resolve(try SecureStorageNative.shared.getAllKeys())
        } catch {
            reject("SECURE_STORAGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(fetch:withData:withCallback:)
    func fetch(url: NSString, data: NSDictionary, callback: @escaping RCTResponseSenderBlock) {
        let urlString = url as String
        guard SSLPinning.isHttpsURL(urlString) else {
            callback([NSNull(), "Only HTTPS URLs are allowed"])
            return
        }

        let pinningConfig = PinningConfiguration(data: data)
        if let error = pinningConfig.error {
            callback([NSNull(), error])
            return
        }

        guard let requestUrl = URL(string: urlString) else {
            callback([NSNull(), "Invalid URL"])
            return
        }

        if pinningConfig.enabled {
            guard let host = requestUrl.host,
                  SSLPinning.hostnameMatchesValidDomains(host, validDomains: pinningConfig.validDomains) else {
                callback([NSNull(), "Hostname is not in validDomains"])
                return
            }
        }

        let configuration = URLSessionConfiguration.default
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.networkServiceType = .responsiveData
        configuration.shouldUseExtendedBackgroundIdleMode = true

        var request = URLRequest(url: requestUrl)
        request.httpMethod = data["method"] as? String ?? "GET"
        request.timeoutInterval = data["timeout"] as? TimeInterval ?? 60.0
        request.allHTTPHeaderFields = data["headers"] as? [String: String]

        if let body = data["body"] {
            if let bodyString = body as? String {
                request.httpBody = bodyString.data(using: .utf8)
            } else if let bodyDict = body as? [String: Any] {
                request.httpBody = try? JSONSerialization.data(withJSONObject: bodyDict, options: [])
            }
        }

        var jwsHeaderName = JwsFetchSigner.modernHeaderName
        do {
            if let jwsResult = try JwsFetchSigner.sign(
                url: urlString,
                method: data["method"] as? String ?? "GET",
                requestBody: request.httpBody,
                options: data,
                nativeHmacKey: hmacKeyData
            ) {
                jwsHeaderName = jwsResult.headerName
                request.setValue(jwsResult.signature, forHTTPHeaderField: jwsHeaderName)
            }
        } catch {
            callback([NSNull(), error.localizedDescription])
            return
        }

        let sslPinning = SSLPinning(url: url, data: data, callback: callback)
        let session = URLSession(configuration: configuration, delegate: sslPinning, delegateQueue: .main)
        session.dataTask(with: request).resume()
    }

    @objc(getDeviceId:)
    func getDeviceId(callback: RCTResponseSenderBlock) {
        guard let id = UIDevice.current.identifierForVendor?.uuidString else {
            callback([NSNull(), "GET_DEVICE_ID_ERROR"])
            return
        }
        callback([id.replacingOccurrences(of: "-", with: ""), NSNull()])
    }

    @objc(runtimeDetect:withRejecter:)
    func runtimeDetect(resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        resolve(RuntimeDetector.detect())
    }

    @objc(appIntegrityVerify:withRejecter:)
    func appIntegrityVerify(resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        resolve(AppIntegrityChecker.verify())
    }

    @objc(deviceGetEnvironment:withRejecter:)
    func deviceGetEnvironment(resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        resolve(EmulatorDetector.detect())
    }

    @objc(deviceHasSecurityRisk:withRejecter:)
    func deviceHasSecurityRisk(resolve: RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
        resolve(jailbreakStatus.jailbroken)
    }

    // ─── CryptoManager bridge ──────────────────────────────────────────────

    @objc(cryptoHash:withAlgorithm:withResolver:withRejecter:)
    func cryptoHash(
        input: NSString,
        algorithm: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.hash(input: input as String, algorithm: algorithm as String))
        } catch {
            reject("CRYPTO_HASH_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoDeriveKeys:withResolver:withRejecter:)
    func cryptoDeriveKeys(
        params: NSDictionary,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            guard
                let sharedSecret = params["sharedSecret"] as? String,
                let salt = params["salt"] as? String,
                let encryptionInfo = params["encryptionInfo"] as? String,
                let macInfo = params["macInfo"] as? String,
                let hmacAlgorithm = params["hmacAlgorithm"] as? String
            else {
                reject("CRYPTO_KDF_ERROR", "Missing required parameters: sharedSecret, salt, encryptionInfo, macInfo, hmacAlgorithm", nil)
                return
            }
            let keys = try CryptoManager.deriveKeys(
                sharedSecretBase64: sharedSecret,
                saltBase64: salt,
                encryptionInfoBase64: encryptionInfo,
                macInfoBase64: macInfo,
                hmacAlgorithm: hmacAlgorithm
            )
            resolve(keys)
        } catch {
            reject("CRYPTO_KDF_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoEncryptAesGcm:withKey:withResolver:withRejecter:)
    func cryptoEncryptAesGcm(
        plaintext: NSString,
        key: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.encryptAesGcm(plaintext: plaintext as String, keyBase64: key as String))
        } catch {
            reject("CRYPTO_ENCRYPT_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoDecryptAesGcm:withKey:withResolver:withRejecter:)
    func cryptoDecryptAesGcm(
        ciphertext: NSString,
        key: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.decryptAesGcm(ciphertextBase64: ciphertext as String, keyBase64: key as String))
        } catch {
            reject("CRYPTO_DECRYPT_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoGetEcdhPublicKey:withRejecter:)
    func cryptoGetEcdhPublicKey(
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.getEcdhPublicKey())
        } catch {
            reject("CRYPTO_KEY_EXCHANGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoEcdhComputeAndDeriveKeys:withResolver:withRejecter:)
    func cryptoEcdhComputeAndDeriveKeys(
        params: NSDictionary,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            guard
                let serverPublicKey = params["serverPublicKey"] as? String,
                let salt = params["salt"] as? String,
                let encryptionInfo = params["encryptionInfo"] as? String,
                let macInfo = params["macInfo"] as? String,
                let hmacAlgorithm = params["hmacAlgorithm"] as? String
            else {
                reject("CRYPTO_KEY_EXCHANGE_ERROR", "Missing required parameters", nil)
                return
            }
            let keys = try CryptoManager.ecdhComputeAndDeriveKeys(
                serverPublicKeyBase64: serverPublicKey,
                saltBase64: salt,
                encryptionInfoBase64: encryptionInfo,
                macInfoBase64: macInfo,
                hmacAlgorithm: hmacAlgorithm
            )
            resolve(keys)
        } catch {
            reject("CRYPTO_KEY_EXCHANGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoGetX25519PublicKey:withRejecter:)
    func cryptoGetX25519PublicKey(
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.getX25519PublicKey())
        } catch {
            reject("CRYPTO_KEY_EXCHANGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoX25519ComputeAndDeriveKeys:withResolver:withRejecter:)
    func cryptoX25519ComputeAndDeriveKeys(
        params: NSDictionary,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            guard
                let serverPublicKey = params["serverPublicKey"] as? String,
                let salt = params["salt"] as? String,
                let encryptionInfo = params["encryptionInfo"] as? String,
                let macInfo = params["macInfo"] as? String,
                let hmacAlgorithm = params["hmacAlgorithm"] as? String
            else {
                reject("CRYPTO_KEY_EXCHANGE_ERROR", "Missing required parameters", nil)
                return
            }
            let keys = try CryptoManager.x25519ComputeAndDeriveKeys(
                serverPublicKeyBase64: serverPublicKey,
                saltBase64: salt,
                encryptionInfoBase64: encryptionInfo,
                macInfoBase64: macInfo,
                hmacAlgorithm: hmacAlgorithm
            )
            resolve(keys)
        } catch {
            reject("CRYPTO_KEY_EXCHANGE_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoGenerateEd25519KeyPair:withRejecter:)
    func cryptoGenerateEd25519KeyPair(
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        resolve(CryptoManager.generateEd25519KeyPair())
    }

    @objc(cryptoSignEd25519:withPrivateKey:withResolver:withRejecter:)
    func cryptoSignEd25519(
        message: NSString,
        privateKey: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.signEd25519(message: message as String, privateKeyBase64: privateKey as String))
        } catch {
            reject("CRYPTO_SIGN_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoVerifyEd25519:withSignature:withPublicKey:withResolver:withRejecter:)
    func cryptoVerifyEd25519(
        message: NSString,
        signature: NSString,
        publicKey: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.verifyEd25519(
                message: message as String,
                signatureBase64: signature as String,
                publicKeyBase64: publicKey as String
            ))
        } catch {
            reject("CRYPTO_VERIFY_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoGenerateEcdsaKeyPair:withRejecter:)
    func cryptoGenerateEcdsaKeyPair(
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        resolve(CryptoManager.generateEcdsaKeyPair())
    }

    @objc(cryptoSignEcdsa:withPrivateKey:withResolver:withRejecter:)
    func cryptoSignEcdsa(
        message: NSString,
        privateKey: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.signEcdsa(message: message as String, privateKeyBase64: privateKey as String))
        } catch {
            reject("CRYPTO_SIGN_ERROR", error.localizedDescription, error)
        }
    }

    @objc(cryptoVerifyEcdsa:withSignature:withPublicKey:withResolver:withRejecter:)
    func cryptoVerifyEcdsa(
        message: NSString,
        signature: NSString,
        publicKey: NSString,
        resolve: @escaping RCTPromiseResolveBlock,
        reject: RCTPromiseRejectBlock
    ) {
        do {
            resolve(try CryptoManager.verifyEcdsa(
                message: message as String,
                signatureBase64: signature as String,
                publicKeyBase64: publicKey as String
            ))
        } catch {
            reject("CRYPTO_VERIFY_ERROR", error.localizedDescription, error)
        }
    }
}
