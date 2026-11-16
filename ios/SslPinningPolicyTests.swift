import Security
import XCTest

final class SslPinningPolicyTests: XCTestCase {
    private let pinA = "uJBIjh8wyk+eUkbrkXlZ7LT1Ja9NkCcXenILpFyNTgc="
    private let pinB = "dRNgUuqckRHTb2ykRnZKe2RGwIaxhouLyxQHyC25cbY="

    private func configuration(_ options: [String: Any]) -> PinningConfiguration {
        PinningConfiguration(data: options as NSDictionary)
    }

    private func entry(_ domain: String, _ pins: [Any], includeSubdomains: Any? = nil) -> [String: Any] {
        var entry: [String: Any] = ["domain": domain, "pins": pins]
        if let includeSubdomains { entry["includeSubdomains"] = includeSubdomains }
        return entry
    }

    private func hash(_ base64: String) -> Data {
        Data(base64Encoded: base64)!
    }

    func testNoPinningOptionsIsDisabled() {
        let config = configuration(["method": "GET", "certificates": NSNull(), "validDomains": NSNull()])
        XCTAssertFalse(config.enabled)
        XCTAssertNil(config.error)
    }

    func testEachDomainOnlyAcceptsItsOwnPins() {
        let config = configuration(["pinnedDomains": [
            entry("api.example.com", ["sha256/" + pinA]),
            entry("cdn.example.net", [pinB]),
        ]])

        XCTAssertTrue(config.enabled)
        XCTAssertEqual(config.pins(forHost: "API.example.com"), [hash(pinA)])
        XCTAssertEqual(config.pins(forHost: "cdn.example.net"), [hash(pinB)])
        XCTAssertFalse(config.isPinned(host: "v2.api.example.com"))
        XCTAssertFalse(config.isPinned(host: "example.org"))
    }

    func testIncludeSubdomainsAndOverlappingEntries() {
        let config = configuration(["pinnedDomains": [
            entry("example.net", [pinB], includeSubdomains: true),
            entry("api.example.net", [pinA]),
        ]])

        XCTAssertEqual(config.pins(forHost: "example.net"), [hash(pinB)])
        XCTAssertEqual(config.pins(forHost: "a.b.example.net"), [hash(pinB)])
        XCTAssertEqual(config.pins(forHost: "api.example.net"), [hash(pinA), hash(pinB)])
        XCTAssertFalse(config.isPinned(host: "badexample.net"))
    }

    func testLegacyFormPinsEveryDomainAndSubdomainWithEveryPin() {
        let config = configuration([
            "certificates": [pinA, pinB],
            "validDomains": [" API.Example.com ", "", "example.net"],
        ])

        XCTAssertEqual(config.domains.count, 2)
        XCTAssertEqual(config.pins(forHost: "v2.api.example.com"), [hash(pinA), hash(pinB)])
        XCTAssertEqual(config.pins(forHost: "example.net"), [hash(pinA), hash(pinB)])
    }

    func testInvalidConfigurationsAreRejected() {
        let cases: [([String: Any], String)] = [
            (["pinnedDomains": []], "at least one domain"),
            (["pinnedDomains": [entry("https://api.example.com", [pinA])]], "invalid domain"),
            (["pinnedDomains": [entry("*.example.com", [pinA])]], "invalid domain"),
            (["pinnedDomains": [entry("api.example.com", [])]], "at least one pin"),
            (["pinnedDomains": [entry("api.example.com", ["sha256/not-a-hash"])]], "pin at index 0"),
            (["pinnedDomains": [entry("api.example.com", [pinA], includeSubdomains: NSNumber(value: 1))]],
             "includeSubdomains must be a boolean"),
            (["certificates": [pinA]], "requires both"),
            (["certificates": [], "validDomains": ["api.example.com"]], "At least one certificate"),
        ]
        for (options, message) in cases {
            let config = configuration(options)
            XCTAssertFalse(config.enabled, message)
            XCTAssertTrue(config.error?.contains(message) == true, "\(config.error ?? "nil") should contain \(message)")
        }
    }

    func testSpkiHashMatchesOpenSSL() throws {
        let der = try XCTUnwrap(Data(base64Encoded: """
            MIIBbzCCARSgAwIBAgIUMh2yPHN4XBnNWL9tGLuanRNiGM0wCgYIKoZIzj0EAwIwFTETMBEGA1UEAwwKTGVnaXQgUm9vdDAeFw0y\
            NjExMTUwOTI5NDJaFw0yNzExMTUwOTI5NDJaMBUxEzARBgNVBAMMCkxlZ2l0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC\
            AAT0JLYgLNoFzZdVSPDOqIuEzkCEBEAq0s431Di1KT6Aqtgsga0Wjgk2aXz4yWgajK9cbDXKJNcboYCybX/fgQRKo0IwQDAdBgNV\
            HQ4EFgQUiuHDlp7vO94/IzdiQL44uwM1DBcwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDSQAw\
            RgIhAPVHaWmHuau5r32PmhJazfdNZKppvky8mtGUd8GOteUBAiEAiVOTIklqIHWwy8FdhquvXmnSuMtu/jQCAIckCb3UmO0=
            """))
        let certificate = try XCTUnwrap(SecCertificateCreateWithData(nil, der as CFData))

        XCTAssertEqual(
            ServerTrustPinning.spkiSHA256(certificate)?.base64EncodedString(),
            "lzquLs/svY+QB/h3P5dFe5kfOkjFo8rvinmvY3lXJeQ="
        )
    }
}
