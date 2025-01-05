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
        keyData: Data!,
        session: URLSession!
  
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
        let configuration = URLSessionConfiguration.default
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.networkServiceType = .responsiveData
        configuration.shouldUseExtendedBackgroundIdleMode = true
        
        var request = URLRequest(url: URL(string: url as String)!)
        request.httpMethod = data["method"] as? String ?? "POST"
        request.timeoutInterval = data["timeout"] as? TimeInterval ?? 60.0
        request.allHTTPHeaderFields = data["headers"] as? [String : String]
        // Prepare body
        if let body = data["body"] {
            if let bodyString = body as? String {
                request.httpBody = bodyString.data(using: .utf8)
            } else if let bodyDict = body as? [String: Any] {
                request.httpBody = try? JSONSerialization.data(withJSONObject: bodyDict, options: [])
            }
        }
      if data["keyId"] != nil && data["requestId"] != nil {
        request
          .setValue(
            jwsHeader(
              payload: request.httpBody ?? .init(),
              keyId: data["keyId"] as! String,
              requestId: data["requestId"] as! String
            ),
            forHTTPHeaderField: "X-JWS-Signature"
          )
      }

      let sslPinning = SSLPinning(url: url, data: data, callback: callback)
      let session = URLSession(
        configuration: configuration,
        delegate: sslPinning,
        delegateQueue: .main
      )
      session.dataTask(with: request).resume()
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
