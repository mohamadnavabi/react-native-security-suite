import Foundation
import CryptoKit

@available(iOS 13.0, *)
final class Obfuscation {
    private func deriveKey(_ secret: String) throws -> SymmetricKey {
        guard !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NSError(
                domain: "Obfuscation",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Obfuscation secret is required"]
            )
        }
        let hash = SHA256.hash(data: Data(secret.utf8))
        return SymmetricKey(data: Data(hash))
    }

    func obfuscate(plain: String, secret: String) throws -> String {
        let symmetricKey = try deriveKey(secret)
        guard let plainData = plain.data(using: .utf8) else {
            throw NSError(domain: "Obfuscation", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid plaintext"])
        }
        let encrypted = try AES.GCM.seal(plainData, using: symmetricKey)
        guard let combined = encrypted.combined else {
            throw NSError(domain: "Obfuscation", code: 3, userInfo: [NSLocalizedDescriptionKey: "Obfuscation failed"])
        }
        return combined.base64EncodedString()
    }

    func deobfuscate(encoded: String, secret: String) throws -> String {
        guard let decodedData = Data(base64Encoded: encoded) else {
            throw NSError(domain: "Obfuscation", code: 4, userInfo: [NSLocalizedDescriptionKey: "Invalid obfuscated payload"])
        }
        let symmetricKey = try deriveKey(secret)
        let sealedBox = try AES.GCM.SealedBox(combined: decodedData)
        let decrypted = try AES.GCM.open(sealedBox, using: symmetricKey)
        guard let result = String(data: decrypted, encoding: .utf8) else {
            throw NSError(domain: "Obfuscation", code: 5, userInfo: [NSLocalizedDescriptionKey: "Invalid UTF-8 output"])
        }
        return result
    }
}
