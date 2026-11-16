import XCTest

@available(iOS 13.0, *)
final class SslPinningNetworkErrorTests: XCTestCase {
    func testDnsFailuresAreUnknownHost() {
        XCTAssertEqual(SSLPinning.networkError(URLError(.cannotFindHost)), "UNKNOWN_HOST")
        XCTAssertEqual(SSLPinning.networkError(URLError(.dnsLookupFailed)), "UNKNOWN_HOST")
    }

    func testTlsFailuresAreHandshake() {
        XCTAssertEqual(SSLPinning.networkError(URLError(.secureConnectionFailed)), "SSL_HANDSHAKE")
        XCTAssertEqual(SSLPinning.networkError(URLError(.serverCertificateUntrusted)), "SSL_HANDSHAKE")
    }

    func testTimeout() {
        XCTAssertEqual(SSLPinning.networkError(URLError(.timedOut)), "TIMEOUT")
    }

    func testOtherFailuresAreNetwork() {
        XCTAssertEqual(SSLPinning.networkError(URLError(.cannotConnectToHost)), "NETWORK")
        XCTAssertEqual(SSLPinning.networkError(NSError(domain: "other", code: 1)), "NETWORK")
    }
}
