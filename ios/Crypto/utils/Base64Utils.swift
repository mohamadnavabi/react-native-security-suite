import Foundation

@available(iOS 13.0, *)
enum Base64Utils {
  static func encode(_ data: Data) -> String {
    data.base64EncodedString()
  }

  static func decode(_ string: String) -> Data? {
    Data(base64Encoded: string.trimmingCharacters(in: .whitespacesAndNewlines))
  }

  static func encodeURLSafe(_ data: Data) -> String {
    data.base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  static func decodeURLSafe(_ string: String) -> Data? {
    var base64 = string
      .replacingOccurrences(of: "-", with: "+")
      .replacingOccurrences(of: "_", with: "/")
    let remainder = base64.count % 4
    if remainder > 0 {
      base64 += String(repeating: "=", count: 4 - remainder)
    }
    return Data(base64Encoded: base64)
  }
}
