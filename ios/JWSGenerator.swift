import Foundation
import CryptoKit

@available(iOS 13.0, *)
struct JWSGenerator {
    private static let safeHeaderKey = try! NSRegularExpression(pattern: "^[a-zA-Z][a-zA-Z0-9_-]*$")
    private static let safeHeaderValue = try! NSRegularExpression(pattern: "^[\\x20-\\x7E]+$")

    static func validateAlgorithm(_ algorithm: String?) throws -> String {
        let value = algorithm ?? "HS256"
        switch value {
        case "HS256", "HS384", "HS512":
            return value
        default:
            throw NSError(
                domain: "JWS",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Unsupported JWS algorithm: \(value)"]
            )
        }
    }

    static func validateHeaderKey(_ key: String) throws {
        let range = NSRange(key.startIndex..., in: key)
        guard safeHeaderKey.firstMatch(in: key, range: range) != nil else {
            throw NSError(domain: "JWS", code: 2, userInfo: [NSLocalizedDescriptionKey: "Invalid JWS header key: \(key)"])
        }
    }

    static func validateHeaderValue(_ value: String) throws {
        let range = NSRange(value.startIndex..., in: value)
        guard safeHeaderValue.firstMatch(in: value, range: range) != nil else {
            throw NSError(domain: "JWS", code: 3, userInfo: [NSLocalizedDescriptionKey: "Invalid JWS header value"])
        }
    }

    static func resolveAlgorithm(_ algorithm: String?, headers: [String: Any]) throws -> String {
        let headerAlg = headers["alg"] as? String

        if let algorithm, let headerAlg, algorithm != headerAlg {
            throw NSError(
                domain: "JWS",
                code: 7,
                userInfo: [NSLocalizedDescriptionKey: "JWS algorithm mismatch: options.algorithm and headers.alg must match"]
            )
        }

        if let algorithm, !algorithm.isEmpty {
            return try validateAlgorithm(algorithm)
        }

        if let headerAlg, !headerAlg.isEmpty {
            return try validateAlgorithm(headerAlg)
        }

        return "HS256"
    }

    static func generate(
        payloadString: String,
        secret: String,
        algorithm: String?,
        headers: [String: Any]?,
        detached: Bool
    ) throws -> String {
        guard !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw NSError(
                domain: "JWS",
                code: 8,
                userInfo: [NSLocalizedDescriptionKey: "JWS secret is required and must be a non-empty string"]
            )
        }

        let normalizedHeaders = headers ?? [:]
        let alg = try resolveAlgorithm(algorithm, headers: normalizedHeaders)
        let protectedHeader = try buildProtectedHeader(algorithm: alg, headers: normalizedHeaders)

        let encodedProtectedHeader = base64URLEncode(protectedHeader)
        let encodedPayload = encodePayload(payloadString)
        let signingInput = buildSigningInput(encodedProtectedHeader: encodedProtectedHeader, encodedPayload: encodedPayload)

        let signature = try sign(
            data: Data(signingInput.utf8),
            secret: Data(secret.utf8),
            algorithm: alg
        )
        let encodedSignature = base64URLEncode(signature)

        return formatCompactJws(
            encodedProtectedHeader: encodedProtectedHeader,
            encodedPayload: encodedPayload,
            encodedSignature: encodedSignature,
            detached: detached
        )
    }

    static func verify(
        compactJWS: String,
        payloadString: String,
        secret: String,
        algorithm: String?,
        detached: Bool
    ) throws -> Bool {
        let encodedProtectedHeader: String
        let encodedSignature: String

        if detached {
            let parts = compactJWS.components(separatedBy: "..")
            guard parts.count == 2 else {
                throw NSError(domain: "JWS", code: 6, userInfo: [NSLocalizedDescriptionKey: "Invalid compact detached JWS format"])
            }
            encodedProtectedHeader = parts[0]
            encodedSignature = parts[1]
        } else {
            let parts = compactJWS.split(separator: ".", omittingEmptySubsequences: false)
            guard parts.count == 3 else {
                throw NSError(domain: "JWS", code: 6, userInfo: [NSLocalizedDescriptionKey: "Invalid compact JWS format"])
            }
            encodedProtectedHeader = String(parts[0])
            encodedSignature = String(parts[2])
        }

        let alg = try validateAlgorithm(algorithm)
        let encodedPayload = encodePayload(payloadString)
        let signingInput = buildSigningInput(encodedProtectedHeader: encodedProtectedHeader, encodedPayload: encodedPayload)
        let expected = try sign(data: Data(signingInput.utf8), secret: Data(secret.utf8), algorithm: alg)

        guard let provided = Data(base64URLEncoded: encodedSignature) else {
            return false
        }
        return expected == provided
    }

    private static func buildProtectedHeader(
        algorithm: String,
        headers: [String: Any]
    ) throws -> Data {
        var headerFields: [String: Any] = ["alg": algorithm]

        let sortedKeys = headers.keys.sorted()
        for key in sortedKeys {
            if key == "alg" { continue }
            try validateHeaderKey(key)
            let value = headers[key]

            if value is NSNull {
                headerFields[key] = NSNull()
            } else if let boolValue = value as? Bool {
                headerFields[key] = boolValue
            } else if let numberValue = value as? NSNumber {
                headerFields[key] = numberValue
            } else if let stringValue = value as? String {
                try validateHeaderValue(stringValue)
                headerFields[key] = stringValue
            } else {
                throw NSError(
                    domain: "JWS",
                    code: 9,
                    userInfo: [NSLocalizedDescriptionKey: "JWS header values must be JSON-serializable primitives: \(key)"]
                )
            }
        }

        return try JSONSerialization.data(withJSONObject: headerFields, options: [.sortedKeys])
    }

    static func encodePayload(_ payloadString: String) -> String {
        if payloadString.isEmpty {
            return ""
        }
        return base64URLEncode(Data(payloadString.utf8))
    }

    static func buildSigningInput(encodedProtectedHeader: String, encodedPayload: String) -> String {
        encodedProtectedHeader + "." + encodedPayload
    }

    static func formatCompactJws(
        encodedProtectedHeader: String,
        encodedPayload: String,
        encodedSignature: String,
        detached: Bool
    ) -> String {
        if detached {
            return "\(encodedProtectedHeader)..\(encodedSignature)"
        }
        return "\(encodedProtectedHeader).\(encodedPayload).\(encodedSignature)"
    }

    private static func sign(data: Data, secret: Data, algorithm: String) throws -> Data {
        let key = SymmetricKey(data: secret)
        switch algorithm {
        case "HS384":
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: key))
        case "HS512":
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: key))
        default:
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: key))
        }
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

@available(iOS 13.0, *)
enum JwsFetchPayload {
    static func build(
        url: String,
        method: String,
        requestBody: Data?,
        jwsOptions: [String: Any]
    ) throws -> String {
        if let payload = jwsOptions["payload"] {
            if payload is NSNull {
                return ""
            }
            if let payloadString = payload as? String {
                return payloadString
            }
            throw NSError(
                domain: "JWS",
                code: 10,
                userInfo: [NSLocalizedDescriptionKey: "JWS fetch payload must be a string when provided"]
            )
        }

        guard let requestUrl = URL(string: url) else {
            throw NSError(domain: "JWS", code: 11, userInfo: [NSLocalizedDescriptionKey: "Invalid URL"])
        }

        var fields: [String: Any] = [
            "method": method.uppercased(),
            "path": requestUrl.path.isEmpty ? "/" : requestUrl.path,
        ]

        if let query = requestUrl.query, !query.isEmpty {
            fields["query"] = query
        }

        if let requestBody, !requestBody.isEmpty {
            let digest = SHA256.hash(data: requestBody)
            fields["bodyHash"] = base64URLEncode(Data(digest))
        }

        if let headers = jwsOptions["headers"] as? [String: Any] {
            for key in ["timestamp", "nonce", "request_id", "requestId"] {
                if let value = headers[key], !(value is NSNull) {
                    fields[key] = value
                }
            }
        }

        let sortedKeys = fields.keys.sorted()
        var sortedFields: [String: Any] = [:]
        for key in sortedKeys {
            sortedFields[key] = fields[key]
        }

        let data = try JSONSerialization.data(withJSONObject: sortedFields, options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private static func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

@available(iOS 13.0, *)
private extension Data {
    init?(base64URLEncoded string: String) {
        var base64 = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = 4 - base64.count % 4
        if padding < 4 {
            base64 += String(repeating: "=", count: padding)
        }
        self.init(base64Encoded: base64)
    }
}
