import Foundation
import CryptoKit

/**
 * Central high-level cryptography API exposed to the React Native bridge.
 *
 * All binary inputs and outputs are Base64-encoded strings.
 * Text inputs (message, plaintext) are UTF-8 strings.
 */
@available(iOS 13.0, *)
enum CryptoManager {

  // ─── Hashing ──────────────────────────────────────────────────────────────

  static func hash(input: String, algorithm: String) throws -> String {
    let digest = try HashUtils.hash(Data(input.utf8), algorithm: algorithm)
    return Base64Utils.encode(digest)
  }

  // ─── HKDF ─────────────────────────────────────────────────────────────────

  static func deriveKeys(
    sharedSecretBase64: String,
    saltBase64: String,
    encryptionInfoBase64: String,
    macInfoBase64: String,
    hmacAlgorithm: String
  ) throws -> [String: String] {
    guard
      let sharedSecret = Base64Utils.decode(sharedSecretBase64),
      let salt = Base64Utils.decode(saltBase64),
      let encInfo = Base64Utils.decode(encryptionInfoBase64),
      let macInfo = Base64Utils.decode(macInfoBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    let keys = try HkdfDerivation.deriveKeys(
      sharedSecret: sharedSecret,
      salt: salt,
      encryptionInfo: encInfo,
      macInfo: macInfo,
      hmacAlgorithm: hmacAlgorithm
    )
    return [
      "encryptionKey": Base64Utils.encode(keys.encryptionKey),
      "macKey": Base64Utils.encode(keys.macKey),
    ]
  }

  // ─── AES-256-GCM ──────────────────────────────────────────────────────────

  static func encryptAesGcm(plaintext: String, keyBase64: String) throws -> String {
    guard let keyData = Base64Utils.decode(keyBase64) else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "key is not valid Base64",
      ])
    }
    let ciphertext = try AesGcmEncryption.encrypt(plaintext: Data(plaintext.utf8), key: keyData)
    return Base64Utils.encode(ciphertext)
  }

  static func decryptAesGcm(ciphertextBase64: String, keyBase64: String) throws -> String {
    guard
      let keyData = Base64Utils.decode(keyBase64),
      let ciphertextData = Base64Utils.decode(ciphertextBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    let plaintext = try AesGcmEncryption.decrypt(payload: ciphertextData, key: keyData)
    guard let result = String(data: plaintext, encoding: .utf8) else {
      throw NSError(domain: "CryptoManager", code: 1, userInfo: [
        NSLocalizedDescriptionKey: "Decrypted bytes are not valid UTF-8",
      ])
    }
    return result
  }

  // ─── ECDH P-256 ───────────────────────────────────────────────────────────

  static func getEcdhPublicKey() throws -> String {
    try EcdhKeyExchange.getPublicKeyBase64()
  }

  static func ecdhComputeAndDeriveKeys(
    serverPublicKeyBase64: String,
    saltBase64: String,
    encryptionInfoBase64: String,
    macInfoBase64: String,
    hmacAlgorithm: String
  ) throws -> [String: String] {
    guard
      let serverPublicKeyDer = Base64Utils.decode(serverPublicKeyBase64),
      let salt = Base64Utils.decode(saltBase64),
      let encInfo = Base64Utils.decode(encryptionInfoBase64),
      let macInfo = Base64Utils.decode(macInfoBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    let sharedSecret = try EcdhKeyExchange.computeSharedSecret(serverPublicKeyDer: serverPublicKeyDer)
    let keys = try HkdfDerivation.deriveKeys(
      sharedSecret: sharedSecret,
      salt: salt,
      encryptionInfo: encInfo,
      macInfo: macInfo,
      hmacAlgorithm: hmacAlgorithm
    )
    return [
      "encryptionKey": Base64Utils.encode(keys.encryptionKey),
      "macKey": Base64Utils.encode(keys.macKey),
    ]
  }

  // ─── ECDH key rotation / deletion ─────────────────────────────────────────

  static func rotateEcdhKeyPair() throws -> String {
    try EcdhKeyExchange.deleteKeyPair()
    return try EcdhKeyExchange.getPublicKeyBase64()
  }

  static func deleteEcdhKeyPair() throws {
    try EcdhKeyExchange.deleteKeyPair()
  }

  // ─── ECDH ephemeral ───────────────────────────────────────────────────────

  static func ecdhEphemeralComputeAndDeriveKeys(
    serverPublicKeyBase64: String,
    saltBase64: String,
    encryptionInfoBase64: String,
    macInfoBase64: String,
    hmacAlgorithm: String
  ) throws -> [String: String] {
    guard
      let serverPublicKeyDer = Base64Utils.decode(serverPublicKeyBase64),
      let salt = Base64Utils.decode(saltBase64),
      let encInfo = Base64Utils.decode(encryptionInfoBase64),
      let macInfo = Base64Utils.decode(macInfoBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    let result = try EcdhKeyExchange.generateEphemeralAndComputeSharedSecret(
      serverPublicKeyDer: serverPublicKeyDer
    )
    let keys = try HkdfDerivation.deriveKeys(
      sharedSecret: result.sharedSecret,
      salt: salt,
      encryptionInfo: encInfo,
      macInfo: macInfo,
      hmacAlgorithm: hmacAlgorithm
    )
    return [
      "devicePublicKey": Base64Utils.encode(result.publicKey),
      "encryptionKey": Base64Utils.encode(keys.encryptionKey),
      "macKey": Base64Utils.encode(keys.macKey),
    ]
  }

  // ─── X25519 ───────────────────────────────────────────────────────────────

  static func getX25519PublicKey() throws -> String {
    try X25519KeyExchange.getPublicKeyBase64()
  }

  static func x25519ComputeAndDeriveKeys(
    serverPublicKeyBase64: String,
    saltBase64: String,
    encryptionInfoBase64: String,
    macInfoBase64: String,
    hmacAlgorithm: String
  ) throws -> [String: String] {
    guard
      let serverPublicKeyRaw = Base64Utils.decode(serverPublicKeyBase64),
      let salt = Base64Utils.decode(saltBase64),
      let encInfo = Base64Utils.decode(encryptionInfoBase64),
      let macInfo = Base64Utils.decode(macInfoBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    let sharedSecret = try X25519KeyExchange.computeSharedSecret(serverPublicKeyRaw: serverPublicKeyRaw)
    let keys = try HkdfDerivation.deriveKeys(
      sharedSecret: sharedSecret,
      salt: salt,
      encryptionInfo: encInfo,
      macInfo: macInfo,
      hmacAlgorithm: hmacAlgorithm
    )
    return [
      "encryptionKey": Base64Utils.encode(keys.encryptionKey),
      "macKey": Base64Utils.encode(keys.macKey),
    ]
  }

  // ─── X25519 key rotation / deletion ───────────────────────────────────────

  static func rotateX25519KeyPair() throws -> String {
    try X25519KeyExchange.deleteKeyPair()
    return try X25519KeyExchange.getPublicKeyBase64()
  }

  static func deleteX25519KeyPair() throws {
    try X25519KeyExchange.deleteKeyPair()
  }

  // ─── X25519 ephemeral ─────────────────────────────────────────────────────

  static func x25519EphemeralComputeAndDeriveKeys(
    serverPublicKeyBase64: String,
    saltBase64: String,
    encryptionInfoBase64: String,
    macInfoBase64: String,
    hmacAlgorithm: String
  ) throws -> [String: String] {
    guard
      let serverPublicKeyRaw = Base64Utils.decode(serverPublicKeyBase64),
      let salt = Base64Utils.decode(saltBase64),
      let encInfo = Base64Utils.decode(encryptionInfoBase64),
      let macInfo = Base64Utils.decode(macInfoBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    let result = try X25519KeyExchange.generateEphemeralAndComputeSharedSecret(
      serverPublicKeyRaw: serverPublicKeyRaw
    )
    let keys = try HkdfDerivation.deriveKeys(
      sharedSecret: result.sharedSecret,
      salt: salt,
      encryptionInfo: encInfo,
      macInfo: macInfo,
      hmacAlgorithm: hmacAlgorithm
    )
    return [
      "devicePublicKey": Base64Utils.encode(result.publicKey),
      "encryptionKey": Base64Utils.encode(keys.encryptionKey),
      "macKey": Base64Utils.encode(keys.macKey),
    ]
  }

  // ─── Ed25519 ──────────────────────────────────────────────────────────────

  static func generateEd25519KeyPair() -> [String: String] {
    let pair = Ed25519Signer.generateKeyPair()
    return [
      "publicKey": Base64Utils.encode(pair.publicKey),
      "privateKey": Base64Utils.encode(pair.privateKey),
    ]
  }

  static func signEd25519(message: String, privateKeyBase64: String) throws -> String {
    guard let privateKeyData = Base64Utils.decode(privateKeyBase64) else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "privateKey is not valid Base64",
      ])
    }
    let signature = try Ed25519Signer.sign(message: Data(message.utf8), privateKeyRaw: privateKeyData)
    return Base64Utils.encode(signature)
  }

  static func verifyEd25519(
    message: String,
    signatureBase64: String,
    publicKeyBase64: String
  ) throws -> Bool {
    guard
      let signatureData = Base64Utils.decode(signatureBase64),
      let publicKeyData = Base64Utils.decode(publicKeyBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    return try Ed25519Signer.verify(
      message: Data(message.utf8),
      signature: signatureData,
      publicKeyRaw: publicKeyData
    )
  }

  // ─── ECDSA P-256 ──────────────────────────────────────────────────────────

  static func generateEcdsaKeyPair() -> [String: String] {
    let pair = EcdsaSigner.generateKeyPair()
    return [
      "publicKey": Base64Utils.encode(pair.publicKeyDer),
      "privateKey": Base64Utils.encode(pair.privateKeyDer),
    ]
  }

  static func signEcdsa(message: String, privateKeyBase64: String) throws -> String {
    guard let privateKeyDer = Base64Utils.decode(privateKeyBase64) else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "privateKey is not valid Base64",
      ])
    }
    let signature = try EcdsaSigner.sign(message: Data(message.utf8), privateKeyDer: privateKeyDer)
    return Base64Utils.encode(signature)
  }

  static func verifyEcdsa(
    message: String,
    signatureBase64: String,
    publicKeyBase64: String
  ) throws -> Bool {
    guard
      let signatureDer = Base64Utils.decode(signatureBase64),
      let publicKeyDer = Base64Utils.decode(publicKeyBase64)
    else {
      throw NSError(domain: "CryptoManager", code: 0, userInfo: [
        NSLocalizedDescriptionKey: "One or more inputs are not valid Base64",
      ])
    }
    return try EcdsaSigner.verify(
      message: Data(message.utf8),
      signatureDer: signatureDer,
      publicKeyDer: publicKeyDer
    )
  }
}
