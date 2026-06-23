import Foundation

/// Resolves JWS signing for `SecuritySuite.fetch`.
///
/// Priority:
/// 1. `options.jws.secret` — RFC 7515 compact JWS with an explicit secret string
/// 2. `options.jws` + native HMAC key — legacy detached JWS with `jws.headers`
/// 3. `options.keyId` + `options.requestId` + native HMAC key — legacy shortcut
///    (signs raw request body; header `X-JWS-Signature`)
/// 4. `options.keyId` + `options.requestId` + `options.secret` — explicit secret fallback
///
/// After `establishSharedKey` / `getSharedKey`, callers can pass only `keyId` and
/// `requestId` — no secret in JavaScript.
@available(iOS 13.0, *)
enum JwsFetchSigner {
    static let legacyHeaderName = "X-JWS-Signature"
    static let modernHeaderName = "X-Request-Signature"

    struct Result {
        let headerName: String
        let signature: String
    }

    static func sign(
        url: String,
        method: String,
        requestBody: Data?,
        options: NSDictionary,
        nativeHmacKey: Data?
    ) throws -> Result? {
        if let jwsOptions = options["jws"] as? [String: Any] {
            return try signWithJwsOptions(
                url: url,
                method: method,
                requestBody: requestBody,
                jwsOptions: jwsOptions,
                nativeHmacKey: nativeHmacKey
            )
        }

        if options["keyId"] != nil && options["requestId"] != nil {
            return try signWithLegacyKeyId(
                requestBody: requestBody,
                keyId: options["keyId"] as? String,
                requestId: options["requestId"] as? String,
                explicitSecret: options["secret"] as? String,
                nativeHmacKey: nativeHmacKey
            )
        }

        return nil
    }

    private static func signWithJwsOptions(
        url: String,
        method: String,
        requestBody: Data?,
        jwsOptions: [String: Any],
        nativeHmacKey: Data?
    ) throws -> Result {
        var headerName = modernHeaderName
        if let customHeaderName = jwsOptions["headerName"] as? String, !customHeaderName.isEmpty {
            headerName = customHeaderName
        }

        if let secret = jwsOptions["secret"] as? String,
           !secret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let headers = jwsOptions["headers"] as? [String: Any]
            let algorithm = jwsOptions["algorithm"] as? String
            let detached = jwsOptions["detached"] as? Bool ?? false
            let payloadString = try JwsFetchPayload.build(
                url: url,
                method: method,
                requestBody: requestBody,
                jwsOptions: jwsOptions
            )
            let signature = try JWSGenerator.generate(
                payloadString: payloadString,
                secret: secret,
                algorithm: algorithm,
                headers: headers,
                detached: detached
            )
            return Result(headerName: headerName, signature: signature)
        }

        guard let nativeHmacKey else {
            throw NSError(
                domain: "JWS",
                code: 20,
                userInfo: [
                    NSLocalizedDescriptionKey:
                        "HMAC key required for JWS signing. Call establishSharedKey or getSharedKey first.",
                ]
            )
        }

        let headers = jwsOptions["headers"] as? [String: String] ?? [:]
        let algorithm = jwsOptions["algorithm"] as? String
        let signature = try JWSGenerator.generate(
            payload: requestBody ?? Data(),
            secret: nativeHmacKey,
            algorithm: algorithm,
            headers: headers
        )
        return Result(headerName: legacyHeaderName, signature: signature)
    }

    private static func signWithLegacyKeyId(
        requestBody: Data?,
        keyId: String?,
        requestId: String?,
        explicitSecret: String?,
        nativeHmacKey: Data?
    ) throws -> Result {
        guard let keyId, let requestId else {
            throw NSError(
                domain: "JWS",
                code: 21,
                userInfo: [NSLocalizedDescriptionKey: "keyId and requestId are required for legacy JWS signing"]
            )
        }

        let payload = requestBody ?? Data()

        if let nativeHmacKey {
            let signature = try JWSGenerator.generate(
                payload: payload,
                secret: nativeHmacKey,
                algorithm: "HS256",
                headers: ["kid": keyId, "request_id": requestId]
            )
            return Result(headerName: legacyHeaderName, signature: signature)
        }

        if let explicitSecret,
           !explicitSecret.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            let payloadString = String(data: payload, encoding: .utf8) ?? ""
            let signature = try JWSGenerator.generate(
                payloadString: payloadString,
                secret: explicitSecret,
                algorithm: "HS256",
                headers: ["kid": keyId, "request_id": requestId],
                detached: true
            )
            return Result(headerName: legacyHeaderName, signature: signature)
        }

        throw NSError(
            domain: "JWS",
            code: 20,
            userInfo: [
                NSLocalizedDescriptionKey:
                    "HMAC key required for JWS signing. Call establishSharedKey or getSharedKey first.",
            ]
        )
    }
}
