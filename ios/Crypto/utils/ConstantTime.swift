import Foundation

@available(iOS 13.0, *)
enum ConstantTime {
  /**
   * Compares two Data values in constant time to prevent timing side-channels.
   * Returns false immediately if lengths differ (length itself is not secret).
   */
  static func equals(_ a: Data, _ b: Data) -> Bool {
    guard a.count == b.count else { return false }
    var result: UInt8 = 0
    for (x, y) in zip(a, b) {
      result |= x ^ y
    }
    return result == 0
  }
}
