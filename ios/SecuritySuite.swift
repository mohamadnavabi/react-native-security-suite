import Foundation
import CryptoKit
import SwiftUI
import Security
import CommonCrypto
import IOSSecuritySuite

@available(iOS 14.0, *)
@objc(SecuritySuite)
class SecuritySuite: NSObject {
    var privateKey: String!,
        publicKey: String!,
        sharedKey: String!,
        keyData: Data!
    
    @objc(getPublicKey:withRejecter:)
    func getPublicKey(resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
        do {
            let key = P256.KeyAgreement.PrivateKey()
            privateKey = key.derRepresentation.base64EncodedString()
            publicKey = key.publicKey.derRepresentation.base64EncodedString()
            
            resolve(publicKey)
        } catch {
            reject("error", "GET_PUBLIC_KEY_ERROR", nil)
        }
    }
    
    @objc(getSharedKey:withResolver:withRejecter:)
    func getSharedKey(serverPK: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
        do {
            guard let serverPublicKeyData = Data(base64Encoded: serverPK as String),
                  let privateKeyData = Data(base64Encoded: privateKey as String) else { return }

            sharedKey = try? P256.KeyAgreement.PrivateKey(derRepresentation: privateKeyData).sharedSecretFromKeyAgreement(with: .init(derRepresentation: serverPublicKeyData)).withUnsafeBytes { Data($0).base64EncodedString() }

            resolve(sharedKey)
        } catch {
            reject("error", "GET_SHARED_KEY_ERROR", nil)
        }
    }
    
    @objc(encrypt:withResolver:withRejecter:)
    func encrypt(input: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
        do {
            guard let keyData = Data(base64Encoded: sharedKey) else {
                reject("error", "DECRYPT_SHARED_KEY_ERROR", nil)
                return
            }
            let data = Data((input as String).utf8)
            if keyData == nil {
                reject("error", "keyData is null", nil)
                return
            }
            let key = SymmetricKey(data: keyData)

            let output = try? AES.GCM.seal(data, using: key).combined?.base64EncodedString()

            resolve(output)
        } catch {
            reject("error", "ENCRYPT_ERROR", nil)
        }
    }
    
    @objc(decrypt:withResolver:withRejecter:)
    func decrypt(input: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
        do {
            guard let keyData = Data(base64Encoded: sharedKey) else {
                reject("error", "DECRYPT_SHARED_KEY_ERROR", nil)
                return
            }
            guard let data = Data(base64Encoded: "\(input)") else {
                reject("error", "INPUT_ERROR", nil)
                return
            }
            let key = SymmetricKey(data: keyData)
            let output = ( try? AES.GCM.open(.init(combined: data), using: key)).map({String(decoding: $0, as: UTF8.self)})
            
            resolve(output)
        } catch {
            reject("error", "DECRYPT_ERROR", nil)
        }
    }
    
    @objc(storageEncrypt:withSecretKey:withHardEncryption:withCallback:)
    func storageEncrypt(input: NSString, secretKey: NSString, hardEncryption: Bool, callback: RCTResponseSenderBlock) -> Void {
        do {
            var encryptionKey = getDeviceId();
            if secretKey != nil {
                encryptionKey = secretKey as String;
            }
            let storageEncryption: StorageEncryption = StorageEncryption()
            let encrypted = try? storageEncryption.encrypt(plain: "\(input)", encryptionKey: encryptionKey, hardEncryption: hardEncryption)
            callback([encrypted, NSNull()])
        } catch {
            callback([NSNull(), "SOFT_DECRYPT_ERROR"])
        }
    }
    
    @objc(storageDecrypt:withSecretKey:withHardEncryption:withCallback:)
    func storageDecrypt(input: NSString, secretKey: NSString, hardEncryption: Bool, callback: RCTResponseSenderBlock) -> Void {
        do {
            var encryptionKey = getDeviceId()
            if secretKey != nil {
                encryptionKey = secretKey as String;
            }
            let storageEncryption: StorageEncryption = StorageEncryption()
            let decrypted = try? storageEncryption.decrypt(decoded: "\(input)", encryptionKey: encryptionKey, hardEncryption: hardEncryption)
            callback([decrypted, NSNull()])
        } catch {
            callback([NSNull(), "SOFT_DECRYPT_ERROR"])
        }
    }
    
    @objc(getDeviceId:)
    func getDeviceId(callback: RCTResponseSenderBlock) -> Void {
        do {
            callback([getDeviceId(), NSNull()]);
        } catch {
            callback([NSNull(), "GET_DEVICE_ID_ERROR"]);
        }
    }
    
    func getDeviceId() -> String {
        return UIDevice.current.identifierForVendor!.uuidString.replacingOccurrences(of: "-", with: "", options: [], range: nil)
    }
    
    @objc(fetch:withData:withCallback:)
    func fetch(url: NSString, data: NSDictionary, callback: @escaping RCTResponseSenderBlock) -> Void {
        let config = URLSessionConfiguration.default
        config.httpShouldSetCookies = false
        config.httpCookieAcceptPolicy = .never
        config.networkServiceType = .responsiveData
        config.shouldUseExtendedBackgroundIdleMode = true
        
        let sslPinning = SSLPinning(data: data)
        
        let startTime = Date()
        var request = URLRequest(url: URL(string: url as String)!)
        
        request.httpMethod = data["method"] as? String ?? "POST"
        request.timeoutInterval = data["timeout"] as? TimeInterval ?? 60.0
        request.allHTTPHeaderFields = data["headers"] as? [String : String]
        if data["body"] != nil { request.httpBody = (data["body"] as! String).data(using: .utf8)! } else { request.httpBody = "".data(using: .utf8)! }
        
        if data["keyId"] != nil && data["requestId"] != nil {
            request.setValue(jwsHeader(payload: request.httpBody ?? .init(), keyId: data["keyId"] as! String, requestId: data["requestId"] as! String), forHTTPHeaderField: "X-JWS-Signature")
        }
        
        let session = URLSession(configuration: config, delegate: sslPinning, delegateQueue: .main)

        let task = session.dataTask(with: request) { data, response, error in
            let response = response as? HTTPURLResponse
            
            if error == nil {
                let responseCode = response?.statusCode
                let responseString = String.init(decoding: data ?? .init(), as: UTF8.self)
                let errorString = error?.localizedDescription
                let responseJSON = try? JSONSerialization.jsonObject(with: data!, options: [])
                
                var result:NSMutableDictionary = [
                    "status": response?.statusCode,
                    "url": url,
                ]
                if errorString == nil && responseCode! < 400 {
                    result["response"] = responseString
                    result["duration"] = "\(Int(Date().timeIntervalSince(startTime) * 1000))ms"
                    result["responseJSON"] = responseJSON
                    callback([result, NSNull()])
                } else {
                    result["error"] = responseString
                    result["errorJSON"] = responseJSON
                    do {
                        let jsonData = try JSONSerialization.data(withJSONObject: result)
                        callback([NSNull(), result])
                    } catch {
                        callback([NSNull(), "JSON_PARSE_ERROR"])
                    }
                }
            } else {
                callback([NSNull(), "MUST_BE_UPDATE"])
            }
        }
        
        task.resume()
    }
    
    @objc(deviceHasSecurityRisk:withRejecter:)
    func deviceHasSecurityRisk(resolve:RCTPromiseResolveBlock, reject:RCTPromiseRejectBlock) -> Void {
        do {
            let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailMessage()
            resolve(jailbreakStatus.jailbroken)
        } catch {
            reject("ERROR", nil, nil)
        }
    }
    
    private func convertHMACToBase64URL(hmac: Data) -> String {
        let base64Encoded = hmac.base64EncodedString()
        let base64URL = base64Encoded
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        
        return base64URL
    }
    
    private func jwsHeader(payload: Data, keyId: String, requestId: String) -> String {
        do {
            return (try? JSONEncoder().encode(JoseHeader(kid: keyId, requestId: requestId)))
                    .flatMap { data in
                        data.base64EncodedData().urlsafeBase64
                    }
                    .flatMap { (data: Data) -> String? in
                        let value = data + Data([0x2e] /* "." */) + payload
                        let signature = HMAC<SHA256>.authenticationCode(for: value, using: SymmetricKey(data: Data(base64Encoded: self.sharedKey)!))
                        let base64URL = convertHMACToBase64URL(hmac: signature.withUnsafeBytes({ Data($0) }))

                        return String(decoding: data, as: UTF8.self) + ".." + base64URL
                    } ?? ""
        } catch {
            return "";
        }
    }
}

struct ASN1 {
    static let rsa2048 = Data(base64Encoded: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")!
    static let rsa4096 = Data(base64Encoded: "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A")!
    static let ec256   = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA=")!
    static let ec384   = Data(base64Encoded: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgA=")!
    static let ec521   = Data(base64Encoded: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ=")!
}

struct JoseHeader: Codable {
    internal init(alg: String = "HS256", kid: String, b64: Bool = false, crit: [String] = ["b64"], requestId: String) {
        self.alg = alg
        self.kid = kid
        self.b64 = b64
        self.crit = crit
        self.requestId = requestId
    }
    
    private enum CodingKeys: String, CodingKey {
        case alg, kid, b64, crit
        case requestId = "request_id"
    }
    
    let alg: String
    let kid: String
    let b64: Bool
    let crit: [String]
    let requestId: String
}
