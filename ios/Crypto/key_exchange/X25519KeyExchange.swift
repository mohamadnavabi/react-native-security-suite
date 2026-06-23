import Foundation
import CryptoKit
import Security

/**
 * X25519 key exchange (Curve25519 Diffie-Hellman).
 * The private key is persisted in the iOS Keychain.
 *
 * Public key I/O uses raw 32-byte representation, matching Android's X25519 normalizeToRaw32 output.
 * Server public keys may be raw 32 bytes or SPKI-wrapped — both are normalized automatically.
 */
@available(iOS 13.0, *)
enum X25519KeyExchange {
  private static let service = "com.securitysuite.crypto.x25519"
  private static let privateKeyAccount = "private"

  static func getOrCreatePrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey {
    if let stored = try loadPrivateKey() { return stored }
    let key = Curve25519.KeyAgreement.PrivateKey()
    try savePrivateKey(key)
    return key
  }

  /** Returns the raw 32-byte public key, Base64-encoded. */
  static func getPublicKeyBase64() throws -> String {
    let key = try getOrCreatePrivateKey()
    return Base64Utils.encode(key.publicKey.rawRepresentation)
  }

  /**
   * Performs X25519 key agreement.
   * serverPublicKeyRaw may be 32 raw bytes or SPKI-wrapped (suffix-normalized to 32 bytes).
   * Returns raw shared secret bytes — always pass through HKDF before use.
   */
  static func computeSharedSecret(serverPublicKeyRaw: Data) throws -> Data {
    let privateKey = try getOrCreatePrivateKey()
    let normalized = try normalizeToRaw32(serverPublicKeyRaw)
    let serverPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: normalized)
    return try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
      .withUnsafeBytes { Data($0) }
  }

  private static let spkiPrefix = Data([
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
  ])

  private static func normalizeToRaw32(_ data: Data) throws -> Data {
    if data.count == 32 { return data }
    if data.count == 44 && data.prefix(12) == spkiPrefix { return data.dropFirst(12) }
    throw NSError(domain: "X25519KeyExchange", code: 0, userInfo: [
      NSLocalizedDescriptionKey: "Invalid X25519 public key: expected 32 raw bytes or a 44-byte SPKI-wrapped key, got \(data.count) bytes",
    ])
  }

  private static func loadPrivateKey() throws -> Curve25519.KeyAgreement.PrivateKey? {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: privateKeyAccount,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var result: AnyObject?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else { return nil }
    return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: data)
  }

  private static func savePrivateKey(_ key: Curve25519.KeyAgreement.PrivateKey) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: privateKeyAccount,
    ]
    SecItemDelete(query as CFDictionary)
    var attributes = query
    attributes[kSecValueData as String] = key.rawRepresentation
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NSError(domain: "X25519KeyExchange", code: Int(status), userInfo: [
        NSLocalizedDescriptionKey: "Failed to save X25519 private key to Keychain (OSStatus \(status))",
      ])
    }
  }

  static func deleteKeyPair() throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: privateKeyAccount,
    ]
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      throw NSError(domain: "X25519KeyExchange", code: Int(status), userInfo: [
        NSLocalizedDescriptionKey: "Failed to delete X25519 key pair (OSStatus \(status))",
      ])
    }
  }

  /**
   * Generates an in-memory-only X25519 ephemeral key pair, performs key agreement with
   * the server's public key, and returns the raw shared secret plus the ephemeral public
   * key (raw 32 bytes). The ephemeral private key is never persisted.
   */
  static func generateEphemeralAndComputeSharedSecret(
    serverPublicKeyRaw: Data
  ) throws -> (publicKey: Data, sharedSecret: Data) {
    let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
    let normalized = try normalizeToRaw32(serverPublicKeyRaw)
    let serverPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: normalized)
    let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
      .withUnsafeBytes { Data($0) }
    return (publicKey: ephemeralKey.publicKey.rawRepresentation, sharedSecret: sharedSecret)
  }
}
