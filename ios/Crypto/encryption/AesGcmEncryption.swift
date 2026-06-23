import Foundation
import CryptoKit

/**
 * AES-256-GCM authenticated encryption.
 *
 * Output format: nonce (12 bytes) || ciphertext || authTag (16 bytes)
 * — identical to AES.GCM.SealedBox.combined and Android's AES/GCM/NoPadding output.
 * This layout guarantees cross-platform compatibility.
 */
@available(iOS 13.0, *)
enum AesGcmEncryption {
  static let ivLength = 12
  static let tagLength = 16
  private static let keyLength = 32

  /**
   * Encrypts plaintext and returns nonce || ciphertext || authTag.
   * key must be exactly 32 bytes (AES-256).
   */
  static func encrypt(plaintext: Data, key: Data) throws -> Data {
    try requireKeyLength(key)
    let symmetricKey = SymmetricKey(data: key)
    let nonce = try AES.GCM.Nonce(data: CryptoBytes.randomBytes(count: ivLength))
    let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey, nonce: nonce)
    guard let combined = sealedBox.combined else {
      throw NSError(domain: "AesGcmEncryption", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "AES.GCM.seal did not produce a combined output",
      ])
    }
    return combined
  }

  /**
   * Decrypts payload structured as nonce (12 bytes) || ciphertext || authTag (16 bytes).
   */
  static func decrypt(payload: Data, key: Data) throws -> Data {
    try requireKeyLength(key)
    guard payload.count >= ivLength + tagLength else {
      throw NSError(domain: "AesGcmEncryption", code: 1, userInfo: [
        NSLocalizedDescriptionKey: "Ciphertext is too short to be valid AES-GCM output",
      ])
    }
    let symmetricKey = SymmetricKey(data: key)
    let sealedBox = try AES.GCM.SealedBox(combined: payload)
    return try AES.GCM.open(sealedBox, using: symmetricKey)
  }

  private static func requireKeyLength(_ key: Data) throws {
    guard key.count == keyLength else {
      throw NSError(domain: "AesGcmEncryption", code: 2, userInfo: [
        NSLocalizedDescriptionKey: "AES-256-GCM requires exactly 32-byte key; received \(key.count) bytes",
      ])
    }
  }
}
