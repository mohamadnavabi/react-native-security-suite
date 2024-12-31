//
//  SoftEncryption.swift
//  EncryptionSecurity
//
//  Created by Mohammad on 5/9/1401 AP.
//  Copyright © 1401 AP Facebook. All rights reserved.
//

import Foundation
import CryptoKit

@available(iOS 13.0, *)
class StorageEncryption {
    let nonce = try! AES.GCM.Nonce(data: Data(base64Encoded: "bj1nixTVoYpSvpdA")!)

    func encrypt(plain: String, encryptionKey: String, hardEncryption: Bool) throws -> String {
        do {
            guard let encryptionKeyData = Data(base64Encoded: encryptionKey) else {
                return "Could not decode encryptionKey text: \(encryptionKey)"
            }
            guard let plainData = plain.data(using: .utf8) else {
                return "Could not decode plain text: \(plain)"
            }
            let symmetricKey = SymmetricKey(data: encryptionKeyData)
            var encrypted = try AES.GCM.seal(plainData, using: symmetricKey, nonce: nonce, authenticating: ASN1.ec256)
            if (hardEncryption) {
                encrypted = try AES.GCM.seal(plainData, using: symmetricKey)
            }
            return encrypted.combined!.base64EncodedString()
        } catch let error {
            return "Error encrypting message: \(error.localizedDescription)"
        }
    }

    func decrypt(decoded: String, encryptionKey: String, hardEncryption: Bool) throws -> String {
        do {
            guard let encryptionKeyData = Data(base64Encoded: encryptionKey) else {
                return "Could not decode encryption key: \(encryptionKey)"
            }
            guard let decodedData = Data(base64Encoded: decoded) else {
                return "Could not decode decoded text: \(decoded)"
            }
            let symmetricKey = SymmetricKey(data: encryptionKeyData)
            if (hardEncryption) {
                let sealedBoxToOpen = try AES.GCM.SealedBox(combined: decodedData)
                let decrypted = try AES.GCM.open(sealedBoxToOpen, using: symmetricKey)
                return String(data: decrypted, encoding: .utf8)!
            } else {
                let sealedBoxRestored = try AES.GCM.SealedBox(combined: decodedData)
                let decrypted = try AES.GCM.open(sealedBoxRestored, using: symmetricKey, authenticating: ASN1.ec256)
                return String(data: decrypted, encoding: .utf8)!
            }
        } catch let error {
            return "Error decrypting message: \(error.localizedDescription)"
        }
    }
}

public extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            let bytes = hexString[i..<j]
            if var num = UInt8(bytes, radix: 16) {
              data.append(&num, count: 1)
            } else {
              return nil
            }
            i = j
        }
        self = data
    }
    /// Hexadecimal string representation of `Data` object.
    var hexadecimal: String {
        return map { String(format: "%02x", $0) }
            .joined()
    }
}

struct ASN1 {
    static let rsa2048 = Data(base64Encoded: "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A")!
    static let rsa4096 = Data(base64Encoded: "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A")!
    static let ec256   = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgA=")!
    static let ec384   = Data(base64Encoded: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgA=")!
    static let ec521   = Data(base64Encoded: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQ=")!
}
