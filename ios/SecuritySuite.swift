import Foundation
import CryptoKit
import SwiftUI
import Security
import CommonCrypto
import IOSSecuritySuite

@available(iOS 13.0, *)
@objc(SecuritySuite)
class SecuritySuite: NSObject {
    var privateKey: String!,
        publicKey: String!,
        sharedKey: String!,
        keyData: Data!

    @objc(getPublicKey:withRejecter:)
    func getPublicKey(resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
        do {
            privateKey = P256.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString()
            keyData = Data(base64Encoded: privateKey as! String)!
            publicKey = try? (ASN1.ec384 + [0x04] + P256.KeyAgreement.PrivateKey(rawRepresentation: keyData).publicKey.rawRepresentation).base64EncodedString()
            
            resolve(publicKey)
        } catch {
            reject("error", "GET_PUBLIC_KEY_ERROR", nil)
        }
    }
    
    @objc(getSharedKey:withResolver:withRejecter:)
    func getSharedKey(serverPK: NSString, resolve: @escaping RCTPromiseResolveBlock, reject: RCTPromiseRejectBlock) -> Void {
        do {
            print("privateKey", privateKey)
            guard let serverPublicKeyData = Data(base64Encoded: serverPK as String),
                  let privateKeyData = Data(base64Encoded: privateKey as String) else { return }
            
            sharedKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData).sharedSecretFromKeyAgreement(with: .init(rawRepresentation: serverPublicKeyData.dropFirst(ASN1.ec384.count + 1)))
                .withUnsafeBytes({ Data(buffer: $0.bindMemory(to: UInt8.self)) })
                .base64EncodedString()
         
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

        if data["method"] != nil { request.httpMethod = data["method"] as! String } else { request.httpMethod =  "POST" }
        if data["body"] != nil { request.httpBody = (data["body"] as! String).data(using: .utf8)! } else { request.httpBody = "".data(using: .utf8)! }
        if data["headers"] != nil { request.allHTTPHeaderFields = data["headers"] as! [String : String] }
        if data["timeout"] != nil { request.timeoutInterval = data["timeout"] as! TimeInterval }
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
                    result["curl"] = request.cURL();
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
                print("test", error)
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
}

struct ASN1 {
    static let rsa2048 = Data(base64Encoded: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")!
    static let rsa4096 = Data(base64Encoded: "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A")!
    static let ec256   = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA=")!
    static let ec384   = Data(base64Encoded: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgA=")!
    static let ec521   = Data(base64Encoded: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ=")!
}
