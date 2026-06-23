import Foundation
import CryptoKit

/**
 * Ed25519 digital signatures via CryptoKit's Curve25519.Signing.
 *
 * Key encoding: raw 32-byte representation for both private and public keys.
 * Signature: raw 64 bytes.
 *
 * Cross-platform note: Android API 33+ Ed25519 Signature uses DER-encoded PKCS#8 / SPKI keys.
 * When exchanging keys with Android, wrap/unwrap the raw bytes to/from DER accordingly.
 * The 64-byte signature format itself is compatible across platforms.
 */
@available(iOS 13.0, *)
struct Ed25519KeyPair {
  let privateKey: Data
  let publicKey: Data
}

@available(iOS 13.0, *)
enum Ed25519Signer {
  static func generateKeyPair() -> Ed25519KeyPair {
    let key = Curve25519.Signing.PrivateKey()
    return Ed25519KeyPair(
      privateKey: key.rawRepresentation,
      publicKey: key.publicKey.rawRepresentation
    )
  }

  /** Signs message bytes and returns the raw 64-byte Ed25519 signature. */
  static func sign(message: Data, privateKeyRaw: Data) throws -> Data {
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyRaw)
    return try privateKey.signature(for: message)
  }

  static func verify(message: Data, signature: Data, publicKeyRaw: Data) throws -> Bool {
    let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyRaw)
    return publicKey.isValidSignature(signature, for: message)
  }
}
