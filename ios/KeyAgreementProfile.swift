import Foundation
import CryptoKit

@available(iOS 13.0, *)
enum KeyAgreementProfileKind {
    case p256Ecdh
    case x25519
}

@available(iOS 13.0, *)
struct KeyAgreementProfile {
    let kind: KeyAgreementProfileKind
    let storageId: String
    let keyAgreementAlgorithm: String
    let keyFactoryAlgorithm: String

    static func from(dictionary: NSDictionary?) throws -> KeyAgreementProfile {
        guard let dictionary = dictionary else {
            throw NSError(domain: "KeyAgreementProfile", code: 0, userInfo: [
                NSLocalizedDescriptionKey:
                    "Crypto options are required. Call SecuritySuite.initialize() before crypto APIs.",
            ])
        }

        let keyAgreementAlgorithm = try requireString(dictionary, key: "keyAgreementAlgorithm")
        let keyFactoryAlgorithm = normalizeKeyFactoryAlgorithm(
            try requireString(dictionary, key: "keyFactoryAlgorithm")
        )

        switch (keyFactoryAlgorithm.uppercased(), keyAgreementAlgorithm.uppercased()) {
        case ("EC", "ECDH"):
            return KeyAgreementProfile(
                kind: .p256Ecdh,
                storageId: "ec-p256",
                keyAgreementAlgorithm: keyAgreementAlgorithm,
                keyFactoryAlgorithm: keyFactoryAlgorithm
            )
        case ("OKP", "X25519"):
            return KeyAgreementProfile(
                kind: .x25519,
                storageId: "okp-x25519",
                keyAgreementAlgorithm: keyAgreementAlgorithm,
                keyFactoryAlgorithm: keyFactoryAlgorithm
            )
        default:
            throw NSError(domain: "KeyAgreementProfile", code: 1, userInfo: [
                NSLocalizedDescriptionKey:
                    "Unsupported key profile: \(keyFactoryAlgorithm)/\(keyAgreementAlgorithm). "
                    + "Supported profiles: EC/ECDH (P-256) and OKP/X25519.",
            ])
        }
    }

    static func from(config: CryptoConfig) throws -> KeyAgreementProfile {
        switch (config.keyFactoryAlgorithm.uppercased(), config.keyAgreementAlgorithm.uppercased()) {
        case ("EC", "ECDH"):
            return KeyAgreementProfile(
                kind: .p256Ecdh,
                storageId: "ec-p256",
                keyAgreementAlgorithm: config.keyAgreementAlgorithm,
                keyFactoryAlgorithm: config.keyFactoryAlgorithm
            )
        case ("OKP", "X25519"):
            return KeyAgreementProfile(
                kind: .x25519,
                storageId: "okp-x25519",
                keyAgreementAlgorithm: config.keyAgreementAlgorithm,
                keyFactoryAlgorithm: config.keyFactoryAlgorithm
            )
        default:
            throw NSError(domain: "KeyAgreementProfile", code: 1, userInfo: [
                NSLocalizedDescriptionKey:
                    "Unsupported key profile: \(config.keyFactoryAlgorithm)/\(config.keyAgreementAlgorithm). "
                    + "Supported profiles: EC/ECDH (P-256) and OKP/X25519.",
            ])
        }
    }

    private static func normalizeKeyFactoryAlgorithm(_ value: String) -> String {
        switch value {
        case "Curve25519", "X25519":
            return "OKP"
        default:
            return value
        }
    }

    private static func requireString(_ dictionary: NSDictionary, key: String) throws -> String {
        guard let value = dictionary[key] as? String else {
            throw NSError(domain: "KeyAgreementProfile", code: 0, userInfo: [
                NSLocalizedDescriptionKey: "Missing required crypto option: \(key)",
            ])
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw NSError(domain: "KeyAgreementProfile", code: 0, userInfo: [
                NSLocalizedDescriptionKey: "Missing required crypto option: \(key)",
            ])
        }
        return trimmed
    }
}

@available(iOS 13.0, *)
struct KeyAgreementKeyPair {
    let profile: KeyAgreementProfile
    let privateKeyData: Data
    let publicKeyData: Data

    func sharedSecret(with serverPublicKeyData: Data) throws -> SharedSecret {
        switch profile.kind {
        case .p256Ecdh:
            let privateKey = try P256.KeyAgreement.PrivateKey(derRepresentation: privateKeyData)
            let serverPublicKey = try P256.KeyAgreement.PublicKey(derRepresentation: serverPublicKeyData)
            return try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
        case .x25519:
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKeyData)
            let serverPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKeyData)
            return try privateKey.sharedSecretFromKeyAgreement(with: serverPublicKey)
        }
    }
}
