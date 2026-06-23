import Foundation
import CryptoKit

@available(iOS 13.0, *)
struct DerivedKeys {
  let encryptionKey: Data
  let macKey: Data
}

/**
 * RFC 5869 HKDF using CryptoKit.
 * Derives independent encryption and HMAC keys from a shared secret.
 */
@available(iOS 13.0, *)
enum HkdfDerivation {
  private static func deriveKey<H: HashFunction>(
    inputKeyMaterial: Data,
    salt: Data,
    info: Data,
    outputByteCount: Int,
    using _: H.Type
  ) -> Data {
    let ikm = SymmetricKey(data: inputKeyMaterial)
    return HKDF<H>.deriveKey(
      inputKeyMaterial: ikm,
      salt: salt,
      info: info,
      outputByteCount: outputByteCount
    ).withUnsafeBytes { Data($0) }
  }

  static func deriveKeys(
    sharedSecret: Data,
    salt: Data,
    encryptionInfo: Data,
    macInfo: Data,
    outputByteCount: Int = 32,
    hmacAlgorithm: String
  ) throws -> DerivedKeys {
    switch hmacAlgorithm {
    case "HmacSHA256", "HMAC-SHA-256":
      return DerivedKeys(
        encryptionKey: deriveKey(inputKeyMaterial: sharedSecret, salt: salt, info: encryptionInfo, outputByteCount: outputByteCount, using: SHA256.self),
        macKey: deriveKey(inputKeyMaterial: sharedSecret, salt: salt, info: macInfo, outputByteCount: outputByteCount, using: SHA256.self)
      )
    case "HmacSHA384", "HMAC-SHA-384":
      return DerivedKeys(
        encryptionKey: deriveKey(inputKeyMaterial: sharedSecret, salt: salt, info: encryptionInfo, outputByteCount: outputByteCount, using: SHA384.self),
        macKey: deriveKey(inputKeyMaterial: sharedSecret, salt: salt, info: macInfo, outputByteCount: outputByteCount, using: SHA384.self)
      )
    case "HmacSHA512", "HMAC-SHA-512":
      return DerivedKeys(
        encryptionKey: deriveKey(inputKeyMaterial: sharedSecret, salt: salt, info: encryptionInfo, outputByteCount: outputByteCount, using: SHA512.self),
        macKey: deriveKey(inputKeyMaterial: sharedSecret, salt: salt, info: macInfo, outputByteCount: outputByteCount, using: SHA512.self)
      )
    default:
      throw NSError(domain: "HkdfDerivation", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "Unsupported HMAC algorithm: \(hmacAlgorithm). Allowed: HmacSHA256, HmacSHA384, HmacSHA512",
      ])
    }
  }
}
