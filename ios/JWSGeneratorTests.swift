import XCTest

@available(iOS 13.0, *)
final class JWSGeneratorTests: XCTestCase {
    private let secret = "secret"

    func testOmittedPayloadProducesThreeSegmentsWithEmptyMiddle() throws {
        try assertEmptyPayload("")
    }

    func testEmptyStringPayloadProducesThreeSegmentsWithEmptyMiddle() throws {
        try assertEmptyPayload("")
    }

    func testStringNullPayloadIsNotEmpty() throws {
        let jws = try JWSGenerator.generate(
            payloadString: "null",
            secret: secret,
            algorithm: "HS256",
            headers: ["kid": "test-key"],
            detached: false
        )
        let segments = jws.split(separator: ".", omittingEmptySubsequences: false)

        XCTAssertEqual(segments.count, 3)
        XCTAssertFalse(String(segments[1]).isEmpty)
        XCTAssertEqual(String(segments[1]), base64URLEncode(Data("null".utf8)))
    }

    func testStringUndefinedPayloadIsNotEmpty() throws {
        let jws = try JWSGenerator.generate(
            payloadString: "undefined",
            secret: secret,
            algorithm: "HS256",
            headers: ["kid": "test-key"],
            detached: false
        )
        let segments = jws.split(separator: ".", omittingEmptySubsequences: false)

        XCTAssertEqual(segments.count, 3)
        XCTAssertEqual(String(segments[1]), base64URLEncode(Data("undefined".utf8)))
    }

    func testObjectPayloadIsBase64UrlEncodedJson() throws {
        let payload = "{\"amount\":1000}"
        let jws = try JWSGenerator.generate(
            payloadString: payload,
            secret: secret,
            algorithm: "HS256",
            headers: ["kid": "test-key"],
            detached: false
        )
        let segments = jws.split(separator: ".", omittingEmptySubsequences: false)

        XCTAssertEqual(segments.count, 3)
        XCTAssertEqual(String(segments[1]), base64URLEncode(Data(payload.utf8)))
    }

    func testAlgorithmMismatchThrows() {
        XCTAssertThrowsError(
            try JWSGenerator.generate(
                payloadString: "",
                secret: secret,
                algorithm: "HS512",
                headers: ["alg": "HS256", "kid": "test-key"],
                detached: false
            )
        )
    }

    func testAlgorithmFromHeaderIsUsed() throws {
        let jws = try JWSGenerator.generate(
            payloadString: "",
            secret: secret,
            algorithm: nil,
            headers: ["alg": "HS384", "kid": "test-key"],
            detached: false
        )
        let protectedHeader = String(jws.split(separator: ".", omittingEmptySubsequences: false)[0])
        let decoded = try JSONSerialization.jsonObject(
            with: Data(base64: base64URLToBase64(protectedHeader)),
            options: []
        ) as? [String: Any]

        XCTAssertEqual(decoded?["alg"] as? String, "HS384")
    }

    func testDefaultAlgorithmIsHs256() throws {
        let jws = try JWSGenerator.generate(
            payloadString: "",
            secret: secret,
            algorithm: nil,
            headers: ["kid": "test-key"],
            detached: false
        )
        let protectedHeader = String(jws.split(separator: ".", omittingEmptySubsequences: false)[0])
        let decoded = try JSONSerialization.jsonObject(
            with: Data(base64: base64URLToBase64(protectedHeader)),
            options: []
        ) as? [String: Any]

        XCTAssertEqual(decoded?["alg"] as? String, "HS256")
    }

    func testDetachedOutputUsesDoubleDot() throws {
        let jws = try JWSGenerator.generate(
            payloadString: "payload",
            secret: secret,
            algorithm: "HS256",
            headers: ["kid": "test-key"],
            detached: true
        )

        XCTAssertTrue(jws.contains(".."))
        XCTAssertEqual(jws.components(separatedBy: "..").count, 2)
        XCTAssertTrue(
            try JWSGenerator.verify(
                compactJWS: jws,
                payloadString: "payload",
                secret: secret,
                algorithm: "HS256",
                detached: true
            )
        )
    }

    private func assertEmptyPayload(_ payload: String) throws {
        let jws = try JWSGenerator.generate(
            payloadString: payload,
            secret: secret,
            algorithm: "HS256",
            headers: ["kid": "test-key"],
            detached: false
        )
        let segments = jws.split(separator: ".", omittingEmptySubsequences: false)

        XCTAssertEqual(segments.count, 3)
        XCTAssertEqual(String(segments[1]), "")
        XCTAssertTrue(jws.contains(".."))
        XCTAssertTrue(
            try JWSGenerator.verify(
                compactJWS: jws,
                payloadString: payload,
                secret: secret,
                algorithm: "HS256",
                detached: false
            )
        )
    }

    private func base64URLEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func base64URLToBase64(_ value: String) -> String {
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = 4 - base64.count % 4
        if padding < 4 {
            base64 += String(repeating: "=", count: padding)
        }
        return base64
    }
}
