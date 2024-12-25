import Foundation

@available(iOS 13.0, *)
class SSLPinning: NSObject, URLSessionDelegate {
    var validDomains: [String] = []
    var intermediateKeyHashes: [Data] = []
    var leafKeyHashes: [Data] = []
    
    init(data: NSDictionary) {
        if let certs = data["certificates"] as? [String] {
            for cert in certs {
                var filteredCert = cert.replacingOccurrences(of: "sha256/", with: "", options: .caseInsensitive, range: nil)
                intermediateKeyHashes.append(Data(base64Encoded: filteredCert)!)
            }
        }
        
        if let domains = data["validDomains"] as? [String] {
            for domain in domains {
                validDomains.append(domain)
            }
        }
    }
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust else {
            return completionHandler(.cancelAuthenticationChallenge, nil)
        }
        
        let host = challenge.protectionSpace.host
        let port = challenge.protectionSpace.port
        guard port == 443, (3...4).contains(trust.certificates.count),
              let leafCertificate = trust.certificates.first,
              let commonName = leafCertificate.commonName,
              validDomains.contains(where: { commonName == $0 || commonName.hasSuffix("." + $0) }) else {
                  completionHandler(.cancelAuthenticationChallenge, nil)
                  return
              }
        let intermediateCertificatesValid = trust.certificates.dropFirst().prefix(2).allSatisfy {
            ($0.pin.map(intermediateKeyHashes.contains) ?? false)
        }
        let leafCertificateValid = leafKeyHashes.contains(leafCertificate.pin ?? .init())
        
        let pattern = commonName
            .replacingOccurrences(of: ".", with: "\\.")
            .replacingOccurrences(of: "*", with: ".+", options: [.anchored])
        guard intermediateCertificatesValid && (leafKeyHashes.isEmpty || leafCertificateValid),
              let commonNameRegex = try? NSRegularExpression(pattern: pattern) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        guard commonNameRegex.textMatches(in: host) == [host] else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        trust.policies = [.ssl(server: true, hostname: host)]
        do {
            if try !trust.evaluate() {
                completionHandler(.cancelAuthenticationChallenge, nil)
            }
        } catch {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let credential = URLCredential(trust: trust)
        completionHandler(.useCredential, credential)
    }
}

@available(iOS 13.0, *)
extension Data {
    /**
     Calculates hash digest of data.
     
     - Parameter digest: digest type. Currently only SHA is supported.
     - Returns: A data object with length equal to digest length.
    */
    public func _hash() -> Data {
        guard !isEmpty else { return Data() }
        var result = [UInt8](repeating: 0, count: 256/8)
        self.withUnsafeBytes { (buf: UnsafeRawBufferPointer) -> Void in
            let ptr = buf.baseAddress!
            let dataLen = CC_LONG(buf.count)
            CC_SHA256(ptr, dataLen, &result)
        }
        
        return Data(result)
    }
}

extension Dictionary {
 func toString() -> String? {
     return (self.compactMap({ (key, value) -> String in
         return "\(key)=\(value)"
     }) as Array).joined(separator: "&")
 }
}

@available(iOS 13.0, *)
extension SecTrust {
    // Returns certificates of the certificate chain used to evaluate trust.
    fileprivate var certificates: [SecCertificate] {
        (0..<SecTrustGetCertificateCount(self))
            .map { SecTrustGetCertificateAtIndex(self, $0 as CFIndex)! }
    }
    
    // Retrieves the policies used by a given trust management object.
    fileprivate var policies: [SecPolicy]? {
        get {
            var result: CFArray?
            SecTrustCopyPolicies(self, &result)
            return result as? [SecPolicy]
        }
        set {
            if let newValue = newValue {
                SecTrustSetPolicies(self, newValue as CFArray)
            } else {
                SecTrustSetPolicies(self, [] as CFArray)
            }
        }
    }
    
    fileprivate func evaluate() throws -> Bool {
        var error: CFError?
        let success = SecTrustEvaluateWithError(self, &error)
        if let error = error {
            throw error
        }
        return success
    }
}

@available(iOS 13.0, *)
extension SecCertificate {
    fileprivate var key: SecKey? {
        SecCertificateCopyKey(self)
    }
    
    fileprivate var commonName: String? {
        var result: CFString?
        SecCertificateCopyCommonName(self, &result)
        return result as String?
    }
    
    fileprivate var pin: Data? {
        try? key?.bytes().hash(digest: .sha256)
    }
}

extension SecPolicy {
    static func ssl(server: Bool, hostname: String) -> SecPolicy {
        SecPolicyCreateSSL(server, hostname as CFString)
    }
    
    static func basicX509() -> SecPolicy {
        SecPolicyCreateBasicX509()
    }
}

extension NSRegularExpression {
    public func matches(
        in string: String,
        options: NSRegularExpression.MatchingOptions = []
    ) -> [NSTextCheckingResult] {
        matches(in: string, options: options, range: NSRange(string.startIndex..., in: string))
    }
    
    public func textMatches(
        in string: String,
        options: NSRegularExpression.MatchingOptions = []
    ) -> [String] {
        textMatches(in: string, options: options, range: string.startIndex...)
    }

    public func matches<R: RangeExpression>(
        in string: String,
        options: NSRegularExpression.MatchingOptions = [],
        range: R
    ) -> [NSTextCheckingResult] where R.Bound == String.Index {
        matches(in: string, options: options, range: NSRange(range, in: string))
    }
    
    public func textMatches<R: RangeExpression>(
        in string: String,
        options: NSRegularExpression.MatchingOptions = [],
        range: R
    ) -> [String] where R.Bound == String.Index {
        matches(in: string, options: options, range: NSRange(range, in: string))
            .map {
                guard let range = Range($0.range, in: string) else {
                    return ""
                }
                return String(string[range])
            }
    }
}
