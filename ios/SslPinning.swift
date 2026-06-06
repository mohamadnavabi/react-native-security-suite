import Pulse
import Foundation
import Security
import CommonCrypto

@available(iOS 13.0, *)
final class PinningConfiguration {
    let enabled: Bool
    let error: String?
    let validDomains: [String]
    let pinHashes: Set<Data>

    init(data: NSDictionary) {
        let hasCertificates = data["certificates"] != nil
        let hasValidDomains = data["validDomains"] != nil

        if hasCertificates != hasValidDomains {
            self.enabled = false
            self.error = "SSL pinning requires both 'certificates' (SPKI SHA-256 hashes) and 'validDomains'"
            self.validDomains = []
            self.pinHashes = []
            return
        }

        guard hasCertificates, let certs = data["certificates"] as? [String],
              let domains = data["validDomains"] as? [String] else {
            self.enabled = false
            self.error = nil
            self.validDomains = []
            self.pinHashes = []
            return
        }

        guard !certs.isEmpty else {
            self.enabled = false
            self.error = "At least one certificate/public key pin is required"
            self.validDomains = []
            self.pinHashes = []
            return
        }

        guard !domains.isEmpty else {
            self.enabled = false
            self.error = "At least one valid domain is required"
            self.validDomains = []
            self.pinHashes = []
            return
        }

        self.validDomains = domains
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
        self.pinHashes = Set(certs.compactMap { cert in
            let filtered = cert
                .replacingOccurrences(of: "sha256/", with: "", options: .caseInsensitive)
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return Data(base64Encoded: filtered)
        }.filter { !$0.isEmpty })

        if self.pinHashes.isEmpty {
            self.enabled = false
            self.error = "No valid SPKI SHA-256 pins found in certificates"
        } else {
            self.enabled = true
            self.error = nil
        }
    }
}

@available(iOS 13.0, *)
class SSLPinning: NSObject, URLSessionDataDelegate {
    var url: NSString!
    var data: NSDictionary!
    var callback: RCTResponseSenderBlock!
    let config: PinningConfiguration
    var loggerEnabled = false
    var networkLogger: NetworkLogger = .init()
    var responseData: Data = Data()
    let pulseNotification = PulseUINotification()

    init(url: NSString, data: NSDictionary, callback: @escaping RCTResponseSenderBlock) {
        self.url = url
        self.data = data
        self.callback = callback
        self.config = PinningConfiguration(data: data)
        super.init()

        #if DEBUG
        loggerEnabled = (data["loggerIsEnabled"] as? Bool) == true
        #else
        loggerEnabled = false
        #endif
    }

    static func isHttpsURL(_ urlString: String) -> Bool {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty else {
            return false
        }
        return scheme == "https"
    }

    static func hostnameMatchesValidDomains(_ host: String, validDomains: [String]) -> Bool {
        let normalizedHost = host.lowercased()
        return validDomains.contains { domain in
            normalizedHost == domain || normalizedHost.hasSuffix("." + domain)
        }
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard config.enabled else {
            // No pinning configured: standard TLS validation only.
            completionHandler(.performDefaultHandling, nil)
            return
        }

        guard let trust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let host = challenge.protectionSpace.host.lowercased()
        let port = challenge.protectionSpace.port

        guard port == 443 else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        guard Self.hostnameMatchesValidDomains(host, validDomains: config.validDomains) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Enforce hostname policy before trust evaluation.
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, host as CFString))

        var pinMatched = false
        let certificateCount = SecTrustGetCertificateCount(trust)
        for index in 0..<certificateCount {
            guard let certificate = SecTrustGetCertificateAtIndex(trust, index) else { continue }

            if let spkiHash = certificate.publicKeyPinHash, config.pinHashes.contains(spkiHash) {
                pinMatched = true
                break
            }

            let certData = SecCertificateCopyData(certificate) as Data
            let certHash = certData._hash()
            if config.pinHashes.contains(certHash) {
                pinMatched = true
                break
            }
        }

        guard pinMatched else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        var error: CFError?
        guard SecTrustEvaluateWithError(trust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) {
        guard loggerEnabled else { return }
        networkLogger.logTaskCreated(task)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if loggerEnabled {
            networkLogger.logDataTask(dataTask, didReceive: data)
        }
        responseData.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if loggerEnabled {
            networkLogger.logTask(task, didCompleteWithError: error)
        }

        if let error = error {
            callback([NSNull(), error.localizedDescription])
            return
        }

        guard let httpResponse = task.response as? HTTPURLResponse else {
            callback([NSNull(), "Unknown error occurred"])
            return
        }

        let responseUrl = httpResponse.url?.absoluteString ?? (url as String)
        let status = httpResponse.statusCode
        let headers = Self.sanitizedHeaders(httpResponse.allHeaderFields)

        if status > 299 {
            callback([NSNull(), [
                "url": responseUrl,
                "status": status,
                "headers": headers,
                "error": String(data: responseData, encoding: .utf8) ?? "",
            ]])
        } else {
            callback([[
                "url": responseUrl,
                "status": status,
                "headers": headers,
                "response": String(decoding: responseData, as: UTF8.self),
                "responseJson": try? JSONSerialization.jsonObject(with: responseData, options: []),
            ], NSNull()])
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        guard loggerEnabled else { return }
        networkLogger.logTask(task, didFinishCollecting: metrics)
        if let httpResponse = task.response as? HTTPURLResponse,
           let responseURL = URL(string: httpResponse.url?.absoluteString ?? (url as String)) {
            pulseNotification.showNotification(body: "\(httpResponse.statusCode) \(responseURL.relativePath)")
        }
    }

    private static let sensitiveHeaders: Set<String> = [
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "x-auth-token", "x-access-token", "x-jws-signature", "x-request-signature", "x-csrf-token",
    ]

    static func sanitizedHeaders(_ headers: [AnyHashable: Any]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in headers {
            guard let name = key as? String else { continue }
            let stringValue = String(describing: value)
            if sensitiveHeaders.contains(name.lowercased()) {
                result[name] = maskValue(stringValue)
            } else {
                result[name] = stringValue
            }
        }
        return result
    }

    static func maskValue(_ value: String) -> String {
        guard value.count > 8 else { return "***" }
        return String(value.prefix(4)) + "***" + String(value.suffix(2))
    }
}

@available(iOS 13.0, *)
extension Data {
    public func _hash() -> Data {
        guard !isEmpty else { return Data() }
        var result = [UInt8](repeating: 0, count: 256 / 8)
        self.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            guard let ptr = buf.baseAddress else { return }
            _ = CC_SHA256(ptr, CC_LONG(buf.count), &result)
        }
        return Data(result)
    }
}

@available(iOS 13.0, *)
extension SecCertificate {
    fileprivate var publicKeyPinHash: Data? {
        guard let key = SecCertificateCopyKey(self) else { return nil }
        return try? key.bytes().hash(digest: .sha256)
    }
}
