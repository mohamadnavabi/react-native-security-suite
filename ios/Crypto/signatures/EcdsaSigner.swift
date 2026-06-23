import Foundation
import CryptoKit

/**
 * ECDSA P-256 digital signatures (SHA-256 / P-256).
 *
 * Key encoding: DER (PKCS#8-compatible derRepresentation for private, X.509 for public).
 * Signature: DER-encoded ASN.1 SEQUENCE — matches Android SHA256withECDSA output format.
 */
@available(iOS 13.0, *)
struct EcdsaKeyPair {
  let privateKeyDer: Data
  let publicKeyDer: Data
}

@available(iOS 13.0, *)
enum EcdsaSigner {
  static func generateKeyPair() -> EcdsaKeyPair {
    let key = P256.Signing.PrivateKey()
    return EcdsaKeyPair(
      privateKeyDer: key.derRepresentation,
      publicKeyDer: key.publicKey.derRepresentation
    )
  }

  /** Signs message bytes using SHA-256 over P-256 and returns the DER-encoded signature. */
  static func sign(message: Data, privateKeyDer: Data) throws -> Data {
    let privateKey = try P256.Signing.PrivateKey(derRepresentation: privateKeyDer)
    return try privateKey.signature(for: message).derRepresentation
  }

  static func verify(message: Data, signatureDer: Data, publicKeyDer: Data) throws -> Bool {
    let publicKey = try P256.Signing.PublicKey(derRepresentation: publicKeyDer)
    let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDer)
    return publicKey.isValidSignature(signature, for: message)
  }
}
