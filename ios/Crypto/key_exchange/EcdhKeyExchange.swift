import Foundation
import CryptoKit
import Security

/**
 * ECDH P-256 key exchange.
 * The private key is persisted in the iOS Keychain (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly).
 *
 * Public key I/O uses X.509 SubjectPublicKeyInfo DER encoding,
 * matching Android KeyStore EC public key format.
 */
@available(iOS 13.0, *)
enum EcdhKeyExchange {
  private static let service = "com.securitysuite.crypto.ecdh"
  private static let privateKeyAccount = "p256.private"

  static func getOrCreatePrivateKey() throws -> P256.KeyAgreement.PrivateKey {
    if let stored = try loadPrivateKey() { return stored }
    let key = P256.KeyAgreement.PrivateKey()
    try savePrivateKey(key)
    return key
  }

  /** Returns the DER-encoded X.509 SubjectPublicKeyInfo, Base64-encoded. */
  static func getPublicKeyBase64() throws -> String {
    let key = try getOrCreatePrivateKey()
    return Base64Utils.encode(key.publicKey.derRepresentation)
  }

  /**
   * Performs ECDH key agreement with the server's DER-encoded P-256 public key.
   * Returns raw shared secret bytes — always pass through HKDF before use.
   */
  static func computeSharedSecret(serverPublicKeyDer: Data) throws -> Data {
    let privateKey = try getOrCreatePrivateKey()
    let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyDer)
    return try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
      .withUnsafeBytes { Data($0) }
  }

  private static func loadPrivateKey() throws -> P256.KeyAgreement.PrivateKey? {
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
    return try? P256.KeyAgreement.PrivateKey(derRepresentation: data)
  }

  private static func savePrivateKey(_ key: P256.KeyAgreement.PrivateKey) throws {
    let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: privateKeyAccount,
    ]
    SecItemDelete(query as CFDictionary)
    var attributes = query
    attributes[kSecValueData as String] = key.derRepresentation
    attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let status = SecItemAdd(attributes as CFDictionary, nil)
    guard status == errSecSuccess else {
      throw NSError(domain: "EcdhKeyExchange", code: Int(status), userInfo: [
        NSLocalizedDescriptionKey: "Failed to save ECDH P-256 private key to Keychain (OSStatus \(status))",
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
      throw NSError(domain: "EcdhKeyExchange", code: Int(status), userInfo: [
        NSLocalizedDescriptionKey: "Failed to delete ECDH P-256 key pair (OSStatus \(status))",
      ])
    }
  }

  /**
   * Generates an in-memory-only P-256 ephemeral key pair, performs ECDH with the
   * server's DER-encoded public key, and returns the raw shared secret plus the
   * ephemeral public key (DER). The ephemeral private key is never persisted.
   */
  static func generateEphemeralAndComputeSharedSecret(
    serverPublicKeyDer: Data
  ) throws -> (publicKey: Data, sharedSecret: Data) {
    let ephemeralKey = P256.KeyAgreement.PrivateKey()
    let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyDer)
    let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
      .withUnsafeBytes { Data($0) }
    return (publicKey: ephemeralKey.publicKey.derRepresentation, sharedSecret: sharedSecret)
  }
}
