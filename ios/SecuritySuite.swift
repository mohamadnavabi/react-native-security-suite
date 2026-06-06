import Foundation
import CryptoKit
import Security
import UIKit
import IOSSecuritySuite

@objc(SecuritySuite)
class SecuritySuite: NSObject {
    private let hkdfSalt = "react-native-security-suite".data(using: .utf8)!
    private let hkdfInfoEncryption = "rss-encryption-v1".data(using: .utf8)!
    private let hkdfInfoHmac = "rss-hmac-v1".data(using: .utf8)!

    private var privateKeyData: Data?
    private var encryptionKeyData: Data?
    private var hmacKeyData: Data?
    private var cryptoConfig: CryptoConfig?

    private func loadOrCreateECDHKeyPair() throws -> P256.KeyAgreement.PrivateKey {
        if let stored = try KeychainHelper.shared.loadECDHKeyPair() {
            privateKeyData = stored.privateKey
            return try P256.KeyAgreement.PrivateKey(derRepresentation: stored.privateKey)
        }

        let key = P256.KeyAgreement.PrivateKey()
        privateKeyData = key.derRepresentation
        try KeychainHelper.shared.saveECDHKeyPair(
            privateKey: key.derRepresentation,
            publicKey: key.publicKey.derRepresentation
        )
        return key
    }

    private func resolveCryptoConfig(options: NSDictionary?) throws -> CryptoConfig {
        if let cryptoConfig {
            return try cryptoConfig.merged(with: options)
        }
        return try CryptoConfig.from(dictionary: options)
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
        let hash = try hkdfHash(for: macAlgorithm)
        return sharedSecret.hkdfDerivedSymmetricKey(
            using: hash,
            salt: hkdfSalt,
            sharedInfo: info,
            outputByteCount: outputByteCount
        ).withUnsafeBytes { Data($0) }
    }

    @objc(getPublicKey:withRejecter:)
    func getPublicKey(resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) {
        do {
            let key = try loadOrCreateECDHKeyPair()
            resolve(key.publicKey.derRepresentation.base64EncodedString())
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
            let config = try CryptoConfig.from(dictionary: options)
            cryptoConfig = config

            let serverKeyString = (serverPK as String).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !serverKeyString.isEmpty,
                  let serverPublicKeyData = Data(base64Encoded: serverKeyString) else {
                reject("GET_SHARED_KEY_ERROR", "Invalid server public key", nil)
                return
            }

            let privateKey = try loadOrCreateECDHKeyPair()
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
                with: P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyData)
            )

            encryptionKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: hkdfInfoEncryption,
                outputByteCount: 32
            )

            hmacKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: hkdfInfoHmac,
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
            let config = try CryptoConfig.from(dictionary: options)
            cryptoConfig = config

            let serverKeyString = (serverPK as String).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !serverKeyString.isEmpty,
                  let serverPublicKeyData = Data(base64Encoded: serverKeyString) else {
                reject("GET_SHARED_KEY_ERROR", "Invalid server public key", nil)
                return
            }

            let privateKey = try loadOrCreateECDHKeyPair()
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
                with: P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyData)
            )

            encryptionKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: hkdfInfoEncryption,
                outputByteCount: 32
            )

            hmacKeyData = try deriveSymmetricKey(
                from: sharedSecret,
                macAlgorithm: config.hmacKeyAlgorithm,
                info: hkdfInfoHmac,
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
            reject("ENCRYPT_ERROR", "Encryption key not established. Call getSharedKey first.", nil)
            return
        }
        do {
            _ = try resolveCryptoConfig(options: options)

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
            reject("DECRYPT_ERROR", "Encryption key not established. Call getSharedKey first.", nil)
            return
        }
        guard let data = Data(base64Encoded: input as String) else {
            reject("DECRYPT_ERROR", "Invalid ciphertext", nil)
            return
        }
        do {
            _ = try resolveCryptoConfig(options: options)

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

    @objc(storageEncrypt:withSecretKey:withHardEncryption:withCallback:)
    func storageEncrypt(input: NSString, secretKey: NSString, hardEncryption: Bool, callback: RCTResponseSenderBlock) {
        guard secretKey != nil, !(secretKey as String).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            callback([NSNull(), "secretKey is required. Device identifiers are not accepted as encryption keys."])
            return
        }
        if hardEncryption {
            callback([NSNull(), "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data."])
            return
        }
        do {
            let encrypted = try Obfuscation().obfuscate(plain: input as String, secret: secretKey as String)
            callback([encrypted, NSNull()])
        } catch {
            callback([NSNull(), error.localizedDescription])
        }
    }

    @objc(storageDecrypt:withSecretKey:withHardEncryption:withCallback:)
    func storageDecrypt(input: NSString, secretKey: NSString, hardEncryption: Bool, callback: RCTResponseSenderBlock) {
        guard secretKey != nil, !(secretKey as String).trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            callback([NSNull(), "secretKey is required. Device identifiers are not accepted as encryption keys."])
            return
        }
        if hardEncryption {
            callback([NSNull(), "hardEncryption is deprecated. Use SecureStorage for encrypted-at-rest data."])
            return
        }
        do {
            let decrypted = try Obfuscation().deobfuscate(encoded: input as String, secret: secretKey as String)
            callback([decrypted, NSNull()])
        } catch {
            callback([NSNull(), error.localizedDescription])
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

        var jwsHeaderName = "X-Request-Signature"
        if let jwsOptions = data["jws"] as? [String: Any] {
            guard let secret = jwsOptions["secret"] as? String,
                  !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                callback([NSNull(), "JWS secret is required and must be a non-empty string"])
                return
            }
            do {
                if let customHeaderName = jwsOptions["headerName"] as? String, !customHeaderName.isEmpty {
                    jwsHeaderName = customHeaderName
                }
                let headers = jwsOptions["headers"] as? [String: Any]
                let algorithm = jwsOptions["algorithm"] as? String
                let detached = jwsOptions["detached"] as? Bool ?? false
                let method = data["method"] as? String ?? "GET"
                let payloadString = try JwsFetchPayload.build(
                    url: urlString,
                    method: method,
                    requestBody: request.httpBody,
                    jwsOptions: jwsOptions
                )
                let signature = try JWSGenerator.generate(
                    payloadString: payloadString,
                    secret: secret,
                    algorithm: algorithm,
                    headers: headers,
                    detached: detached
                )
                request.setValue(signature, forHTTPHeaderField: jwsHeaderName)
            } catch {
                callback([NSNull(), error.localizedDescription])
                return
            }
        } else if data["keyId"] != nil && data["requestId"] != nil {
            guard let secret = data["secret"] as? String,
                  !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  let keyId = data["keyId"] as? String,
                  let requestId = data["requestId"] as? String else {
                callback([NSNull(), "JWS secret is required. Pass options.jws.secret or options.secret for legacy signing."])
                return
            }
            do {
                let payloadString = request.httpBody.flatMap { String(data: $0, encoding: .utf8) } ?? ""
                let signature = try JWSGenerator.generate(
                    payloadString: payloadString,
                    secret: secret,
                    algorithm: "HS256",
                    headers: ["kid": keyId, "request_id": requestId],
                    detached: true
                )
                jwsHeaderName = "X-JWS-Signature"
                request.setValue(signature, forHTTPHeaderField: jwsHeaderName)
            } catch {
                callback([NSNull(), error.localizedDescription])
                return
            }
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
}
