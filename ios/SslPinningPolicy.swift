import CryptoKit
import Foundation
import Security

/// One pinned host (optionally with its subdomains) and the SPKI SHA-256 pins it accepts.
struct PinnedDomain {
    let domain: String
    let includeSubdomains: Bool
    let pins: Set<Data>

    func matches(host: String) -> Bool {
        host == domain || (includeSubdomains && host.hasSuffix("." + domain))
    }
}

struct PinningConfigurationError: Error {
    let message: String
}

/// SSL pinning rules for one request, parsed from the fetch options.
///
/// Accepts `pinnedDomains: [{ domain, pins, includeSubdomains? }]` and/or the legacy
/// `certificates` + `validDomains` pair, where every pin applies to every listed domain and
/// its subdomains. A host is accepted with the union of the pins of every entry that matches
/// it. Keep the semantics in sync with `android/.../PinningPolicy.java`.
final class PinningConfiguration {
    static let legacyPairError =
        "SSL pinning requires both 'certificates' (SPKI SHA-256 hashes) and 'validDomains'"

    let domains: [PinnedDomain]
    let error: String?

    var enabled: Bool { error == nil && !domains.isEmpty }

    init(data: NSDictionary) {
        do {
            domains = try PinningConfiguration.parse(data)
            error = nil
        } catch {
            domains = []
            self.error = (error as? PinningConfigurationError)?.message
                ?? "Invalid SSL pinning configuration"
        }
    }

    /// Union of the pins of every entry matching `host`; empty when the host is not pinned.
    func pins(forHost host: String) -> Set<Data> {
        let host = host.lowercased()
        return domains.reduce(into: Set<Data>()) { pins, entry in
            if entry.matches(host: host) {
                pins.formUnion(entry.pins)
            }
        }
    }

    func isPinned(host: String) -> Bool {
        !pins(forHost: host).isEmpty
    }

    // MARK: - Parsing

    private static func parse(_ data: NSDictionary) throws -> [PinnedDomain] {
        var result: [PinnedDomain] = []

        if let raw = value(data, "pinnedDomains") {
            guard let entries = raw as? [Any] else {
                throw failure("'pinnedDomains' must be an array")
            }
            guard !entries.isEmpty else {
                throw failure("'pinnedDomains' must contain at least one domain")
            }
            for (index, rawEntry) in entries.enumerated() {
                let label = "pinnedDomains[\(index)]"
                guard let entry = rawEntry as? NSDictionary else {
                    throw failure("\(label) must be an object")
                }
                var includeSubdomains = false
                if let flag = value(entry, "includeSubdomains") {
                    guard CFGetTypeID(flag as CFTypeRef) == CFBooleanGetTypeID(), let bool = flag as? Bool else {
                        throw failure("\(label).includeSubdomains must be a boolean")
                    }
                    includeSubdomains = bool
                }
                result.append(try makeDomain(
                    value(entry, "domain") as? String,
                    pins: try strings(entry, "pins", label: "\(label).pins"),
                    includeSubdomains: includeSubdomains,
                    label: label
                ))
            }
        }

        let hasCertificates = value(data, "certificates") != nil
        let hasValidDomains = value(data, "validDomains") != nil
        guard hasCertificates == hasValidDomains else {
            throw failure(legacyPairError)
        }
        if hasCertificates {
            result += try fromLegacy(
                certificates: try strings(data, "certificates", label: "certificates"),
                validDomains: try strings(data, "validDomains", label: "validDomains")
            )
        }

        return result
    }

    /// Legacy form: each valid domain (and its subdomains) accepts every certificate pin.
    private static func fromLegacy(certificates: [String], validDomains: [String]) throws -> [PinnedDomain] {
        guard !certificates.isEmpty else {
            throw failure("At least one certificate/public key pin is required")
        }
        var result: [PinnedDomain] = []
        for (index, domain) in validDomains.enumerated()
        where !domain.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            result.append(try makeDomain(
                domain, pins: certificates, includeSubdomains: true, label: "validDomains[\(index)]"
            ))
        }
        guard !result.isEmpty else {
            throw failure("At least one valid domain is required")
        }
        return result
    }

    private static func makeDomain(
        _ rawDomain: String?,
        pins rawPins: [String],
        includeSubdomains: Bool,
        label: String
    ) throws -> PinnedDomain {
        var domain = (rawDomain ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if domain.hasSuffix(".") {
            domain.removeLast()
        }
        guard !domain.isEmpty else {
            throw failure("\(label): 'domain' is required")
        }
        guard isHostname(domain) else {
            throw failure(
                "\(label): invalid domain '\(rawDomain ?? "")'. Use a bare hostname such as 'api.example.com'"
                    + " (no scheme, port, path or wildcard; set includeSubdomains to cover subdomains)"
            )
        }
        guard !rawPins.isEmpty else {
            throw failure("\(label): at least one pin is required for '\(domain)'")
        }
        var pins = Set<Data>()
        for (index, pin) in rawPins.enumerated() {
            guard let hash = decodePin(pin), hash.count == 32 else {
                throw failure("\(label): pin at index \(index) for '\(domain)' is not a base64 SPKI SHA-256 hash")
            }
            pins.insert(hash)
        }
        return PinnedDomain(domain: domain, includeSubdomains: includeSubdomains, pins: pins)
    }

    private static let hostnameCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyz0123456789-_")

    private static func isHostname(_ domain: String) -> Bool {
        domain.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.unicodeScalars.allSatisfy { hostnameCharacters.contains($0) }
        }
    }

    /// Accepts `sha256/<base64>` or bare base64, standard or URL-safe, padded or not (as Android does).
    private static func decodePin(_ pin: String) -> Data? {
        var base64 = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        if base64.lowercased().hasPrefix("sha256/") {
            base64 = String(base64.dropFirst("sha256/".count))
        }
        base64 = base64
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }

    private static func value(_ dictionary: NSDictionary, _ key: String) -> Any? {
        guard let value = dictionary[key], !(value is NSNull) else { return nil }
        return value
    }

    private static func strings(_ dictionary: NSDictionary, _ key: String, label: String) throws -> [String] {
        guard let array = value(dictionary, key) as? [Any] else {
            throw failure("\(label) must be an array of strings")
        }
        return try array.map { element in
            guard let string = element as? String else {
                throw failure("\(label) must be an array of strings")
            }
            return string
        }
    }

    private static func failure(_ message: String) -> PinningConfigurationError {
        PinningConfigurationError(message: message)
    }
}

/// Server-trust evaluation for pinned hosts.
enum ServerTrustPinning {
    /// Returns nil when `trust` is valid for `host` and its validated chain contains a pinned key,
    /// otherwise the reason it was rejected.
    static func evaluate(_ trust: SecTrust, host rawHost: String, configuration: PinningConfiguration) -> String? {
        let host = rawHost.lowercased()
        let pins = configuration.pins(forHost: host)
        guard !pins.isEmpty else {
            return "SSL pinning: host '\(host)' is not in the SSL pinning domains"
        }

        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))
        var trustError: CFError?
        guard SecTrustEvaluateWithError(trust, &trustError) else {
            return "SSL pinning: the certificate chain for '\(host)' is not trusted"
        }

        // Match pins only against the chain the system built and validated, never against every
        // certificate the server sent: a server can append any public certificate (such as the
        // pinned intermediate) to an otherwise unrelated chain.
        let matched = validatedChain(trust).contains { certificate in
            if let spki = spkiSHA256(certificate), pins.contains(spki) {
                return true
            }
            // Whole-certificate SHA-256 pins have always been accepted on iOS (Android takes SPKI only).
            return pins.contains(sha256(SecCertificateCopyData(certificate) as Data))
        }
        guard matched else {
            return "SSL pinning: no certificate in the chain for '\(host)' matches a configured pin"
        }
        return nil
    }

    static func validatedChain(_ trust: SecTrust) -> [SecCertificate] {
        if #available(iOS 15.0, macOS 12.0, *) {
            return (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        }
        return (0..<SecTrustGetCertificateCount(trust)).compactMap { SecTrustGetCertificateAtIndex(trust, $0) }
    }

    /// SHA-256 of the certificate's DER SubjectPublicKeyInfo — what
    /// `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256` hashes.
    static func spkiSHA256(_ certificate: SecCertificate) -> Data? {
        guard let key = SecCertificateCopyKey(certificate),
              let attributes = SecKeyCopyAttributes(key) as? [CFString: Any],
              let keyType = attributes[kSecAttrKeyType] as? String,
              let keySize = attributes[kSecAttrKeySizeInBits] as? Int,
              let algorithm = algorithmIdentifier(keyType: keyType, keySize: keySize),
              let publicKey = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            return nil
        }
        var bitString = Data([0x00])
        bitString.append(publicKey)
        return sha256(derElement(tag: 0x30, Data(algorithm) + derElement(tag: 0x03, bitString)))
    }

    private static func algorithmIdentifier(keyType: String, keySize: Int) -> [UInt8]? {
        if keyType == kSecAttrKeyTypeRSA as String {
            // rsaEncryption, NULL parameters
            return [0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00]
        }
        guard keyType == kSecAttrKeyTypeECSECPrimeRandom as String else { return nil }
        let ecPublicKey: [UInt8] = [0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]
        switch keySize {
        case 256: return [0x30, 0x13] + ecPublicKey + [0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
        case 384: return [0x30, 0x10] + ecPublicKey + [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]
        case 521: return [0x30, 0x10] + ecPublicKey + [0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]
        default: return nil
        }
    }

    private static func derElement(tag: UInt8, _ content: Data) -> Data {
        var element = Data([tag])
        if content.count < 0x80 {
            element.append(UInt8(content.count))
        } else {
            var lengthBytes: [UInt8] = []
            var length = content.count
            while length > 0 {
                lengthBytes.insert(UInt8(length & 0xFF), at: 0)
                length >>= 8
            }
            element.append(0x80 | UInt8(lengthBytes.count))
            element.append(contentsOf: lengthBytes)
        }
        element.append(content)
        return element
    }

    private static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}
