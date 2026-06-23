import Foundation
import CryptoKit

@available(iOS 13.0, *)
enum HashUtils {
  static func sha256(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  static func sha512(_ data: Data) -> Data {
    Data(SHA512.hash(data: data))
  }

  static func hash(_ data: Data, algorithm: String) throws -> Data {
    switch algorithm {
    case "SHA-256":
      return sha256(data)
    case "SHA-512":
      return sha512(data)
    default:
      throw NSError(domain: "HashUtils", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "Unsupported hash algorithm: \(algorithm). Allowed: SHA-256, SHA-512",
      ])
    }
  }
}
