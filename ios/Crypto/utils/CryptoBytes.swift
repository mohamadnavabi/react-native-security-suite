import Foundation
import Security

@available(iOS 13.0, *)
enum CryptoBytes {
  static func randomBytes(count: Int) throws -> Data {
    guard count > 0 else {
      throw NSError(domain: "CryptoBytes", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "count must be positive",
      ])
    }
    var bytes = Data(count: count)
    let status = bytes.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else {
      throw NSError(domain: "CryptoBytes", code: Int(status), userInfo: [
        NSLocalizedDescriptionKey: "SecRandomCopyBytes failed with status \(status)",
      ])
    }
    return bytes
  }
}
