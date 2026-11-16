import Pulse
import Foundation
import Security

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
    let devToolsRequestId = "security-suite-" + UUID().uuidString
    private var pinningFailure: String?

    init(url: NSString, data: NSDictionary, config: PinningConfiguration, callback: @escaping RCTResponseSenderBlock) {
        self.url = url
        self.data = data
        self.callback = callback
        self.config = config
        super.init()

        loggerEnabled = (data["loggerIsEnabled"] as? Bool) == true
    }

    static func isHttpsURL(_ urlString: String) -> Bool {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty else {
            return false
        }
        return scheme == "https"
    }

    static func isHttpURL(_ urlString: String) -> Bool {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty else {
            return false
        }
        return scheme == "http"
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
            pinningFailure = "SSL pinning: no server trust to evaluate for '\(challenge.protectionSpace.host)'"
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if let failure = ServerTrustPinning.evaluate(trust, host: challenge.protectionSpace.host, configuration: config) {
            pinningFailure = failure
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        completionHandler(.useCredential, URLCredential(trust: trust))
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        guard config.enabled else {
            completionHandler(request)
            return
        }

        let target = request.url
        let host = target?.host?.lowercased() ?? ""
        if target?.scheme?.lowercased() != "https" {
            pinningFailure = "SSL pinning: refusing cleartext redirect to '\(host)'"
        } else if !config.isPinned(host: host) {
            pinningFailure = "SSL pinning: host '\(host)' is not in the SSL pinning domains"
        } else {
            completionHandler(request)
            return
        }
        task.cancel()
        completionHandler(nil)
    }

    func reportRequestStartToDevTools(_ request: URLRequest) {
        guard loggerEnabled else { return }
        var sanitizedRequest = request
        sanitizedRequest.allHTTPHeaderFields = Self.sanitizedHeaders(request.allHTTPHeaderFields ?? [:])
        SecuritySuiteNetworkInspector.reportRequestStart(devToolsRequestId, request: sanitizedRequest)
    }

    func urlSession(_ session: URLSession, didCreateTask task: URLSessionTask) {
        guard loggerEnabled else { return }
        networkLogger.logTaskCreated(task)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping (URLSession.ResponseDisposition) -> Void
    ) {
        if loggerEnabled {
            let httpResponse = response as? HTTPURLResponse
            SecuritySuiteNetworkInspector.reportResponseStart(
                devToolsRequestId,
                response: response,
                statusCode: httpResponse?.statusCode ?? 200,
                headers: Self.sanitizedHeaders(httpResponse?.allHeaderFields ?? [:])
            )
        }
        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if loggerEnabled {
            networkLogger.logDataTask(dataTask, didReceive: data)
            SecuritySuiteNetworkInspector.reportDataReceived(devToolsRequestId, data: data)
        }
        responseData.append(data)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        if loggerEnabled {
            networkLogger.logTask(task, didCompleteWithError: error)
            if error != nil {
                SecuritySuiteNetworkInspector.reportRequestFailed(devToolsRequestId)
            } else {
                SecuritySuiteNetworkInspector.reportResponseEnd(devToolsRequestId, body: responseData)
            }
        }

        if let failure = pinningFailure {
            callback([NSNull(), failure])
            return
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
