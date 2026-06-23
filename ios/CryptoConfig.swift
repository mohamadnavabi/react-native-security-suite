import Foundation

@available(iOS 13.0, *)
struct CryptoConfig {
    let keyAgreementAlgorithm: String
    let keyFactoryAlgorithm: String
    let encryptionKeyAlgorithm: String
    let hmacKeyAlgorithm: String
    let cipherTransformation: String
    let gcmTagLength: Int
    let gcmIvLength: Int

    static func from(dictionary: NSDictionary?) throws -> CryptoConfig {
        guard let dictionary = dictionary else {
            throw NSError(domain: "CryptoConfig", code: 0, userInfo: [
                NSLocalizedDescriptionKey:
                    "Crypto options are required. Call SecuritySuite.initialize() before crypto APIs.",
            ])
        }

        return CryptoConfig(
            keyAgreementAlgorithm: try requireString(dictionary, key: "keyAgreementAlgorithm"),
            keyFactoryAlgorithm: try requireString(dictionary, key: "keyFactoryAlgorithm"),
            encryptionKeyAlgorithm: try requireString(dictionary, key: "encryptionKeyAlgorithm"),
            hmacKeyAlgorithm: try requireString(dictionary, key: "hmacKeyAlgorithm"),
            cipherTransformation: try requireString(dictionary, key: "cipherTransformation"),
            gcmTagLength: try requireInt(dictionary, key: "gcmTagLength"),
            gcmIvLength: try requireInt(dictionary, key: "gcmIvLength")
        )
    }

    func merged(with dictionary: NSDictionary?) throws -> CryptoConfig {
        guard let dictionary = dictionary else { return self }
        var merged: [String: Any] = [
            "keyAgreementAlgorithm": keyAgreementAlgorithm,
            "keyFactoryAlgorithm": keyFactoryAlgorithm,
            "encryptionKeyAlgorithm": encryptionKeyAlgorithm,
            "hmacKeyAlgorithm": hmacKeyAlgorithm,
            "cipherTransformation": cipherTransformation,
            "gcmTagLength": gcmTagLength,
            "gcmIvLength": gcmIvLength,
        ]
        for (key, value) in dictionary {
            if let stringKey = key as? String {
                merged[stringKey] = value
            }
        }
        return try CryptoConfig.from(dictionary: merged as NSDictionary)
    }

    private static func requireString(_ dictionary: NSDictionary, key: String) throws -> String {
        guard let value = dictionary[key] as? String else {
            throw NSError(domain: "CryptoConfig", code: 0, userInfo: [
                NSLocalizedDescriptionKey: "Missing required crypto option: \(key)",
            ])
        }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw NSError(domain: "CryptoConfig", code: 0, userInfo: [
                NSLocalizedDescriptionKey: "Missing required crypto option: \(key)",
            ])
        }
        return trimmed
    }

    private static func requireInt(_ dictionary: NSDictionary, key: String) throws -> Int {
        let value = dictionary[key]
        if let intValue = value as? Int {
            return intValue
        }
        if let numberValue = value as? NSNumber {
            return numberValue.intValue
        }
        throw NSError(domain: "CryptoConfig", code: 0, userInfo: [
            NSLocalizedDescriptionKey: "Missing required crypto option: \(key)",
        ])
    }
}
